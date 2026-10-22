"""Scheduled monitoring: the folder it keeps, notifications by webhook and e-mail (to servers on localhost), and the commands it prints."""
import base64
import email
import http.server
import json
import socketserver
import sys
import tempfile
import threading
import unittest
from email import policy
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _net  # noqa: E402,F401  (a longer listen backlog for the local test servers)
import history as hi  # noqa: E402
import monitor as mon  # noqa: E402
import notify  # noqa: E402
import snapshot as sn  # noqa: E402
import test_cli_monitoring as tcm  # noqa: E402
import test_httpscan_checks as ths  # noqa: E402
import test_snapshot as ts  # noqa: E402
import webcrawler as wc  # noqa: E402


class Hook(http.server.ThreadingHTTPServer):
    def __init__(self, status=200, redirect=False):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                self.server.posts.append((self.path, json.loads(self.rfile.read(n) or b"null"), self.headers.get("Content-Type")))
                if self.server.redirect:
                    self.send_response(302)
                    self.send_header("Location", "/elsewhere")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(self.server.status)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")
        super().__init__(("127.0.0.1", 0), H)
        self.posts, self.status, self.redirect = [], status, redirect
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}/services/T000/B000/secretpath"

    def stop(self):
        self.shutdown()
        self.server_close()


class Smtp(socketserver.ThreadingTCPServer):
    """Just enough SMTP to receive a message: EHLO, AUTH PLAIN, MAIL, RCPT, DATA, QUIT."""
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, user="", password=""):
        class H(socketserver.StreamRequestHandler):
            def reply(self, line):
                self.wfile.write(line.encode() + b"\r\n")

            def handle(self):
                srv = self.server
                self.reply("220 test ESMTP")
                msg = {"from": "", "to": [], "data": b"", "authed": False}
                while True:
                    line = self.rfile.readline().decode("latin-1").rstrip("\r\n")
                    if not line:
                        return
                    cmd = line.upper()
                    if cmd.startswith("EHLO"):
                        self.wfile.write(b"250-test\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n")
                    elif cmd.startswith("AUTH PLAIN"):
                        _, user, pw = base64.b64decode(line.split()[2]).decode().split("\0")
                        ok = (user, pw) == (srv.user, srv.password)
                        msg["authed"] = ok
                        self.reply("235 ok" if ok else "535 5.7.8 bad credentials")
                    elif cmd.startswith("MAIL FROM"):
                        msg["from"] = line[10:].strip()
                        self.reply("250 ok")
                    elif cmd.startswith("RCPT TO"):
                        msg["to"].append(line[8:].strip())
                        self.reply("250 ok")
                    elif cmd == "DATA":
                        self.reply("354 go")
                        buf = b""
                        while not buf.endswith(b"\r\n.\r\n"):
                            buf += self.rfile.readline()
                        msg["data"] = buf[:-5]
                        srv.messages.append(msg)
                        self.reply("250 queued")
                    elif cmd == "QUIT":
                        self.reply("221 bye")
                        return
                    else:
                        self.reply("250 ok")
        super().__init__(("127.0.0.1", 0), H)
        self.user, self.password, self.messages = user, password, []
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def port(self):
        return self.server_address[1]

    def stop(self):
        self.shutdown()
        self.server_close()

    def parsed(self, i=-1):
        return email.message_from_bytes(self.messages[i]["data"], policy=policy.default)


class Messages(unittest.TestCase):
    def diffs(self, extra):
        old, _ = ts.crawl()
        new, _ = ts.crawl(extra)
        return sn.diff(old, new)

    def test_repeated_findings_are_one_line(self):
        d = self.diffs([f"https://bit.ly/{i}" for i in range(20)] + ["https://paypal.com@evil.test/login"])
        subject, text = notify.build_message("https://example.com/", d, "medium", when="2026-10-21 03:00 UTC")
        self.assertEqual(subject, f"WebCrawler: {len(d.regressions())} regression(s) on example.com")
        self.assertIn("2026-10-21 03:00 UTC", text)
        self.assertIn("20 places", text)
        self.assertIn("paypal.com@evil.test", text)

    def test_long_lists_are_cut_short(self):
        changes = [sn.Change("risk-new", f"https://e.com/{i}", f"problem {i}", "medium", f"code{i}") for i in range(30)]
        subject, text = notify.build_message("https://e.com/", sn.Diff(changes=changes), "medium")
        self.assertIn("30 regression(s)", subject)
        self.assertEqual(text.count("[MEDIUM]"), notify.MAX_LINES)
        self.assertIn("and 18 more", text)
        huge = [sn.Change("risk-new", "https://e.com/" + "x" * 900, "t" * 900, "high", f"c{i}") for i in range(12)]
        self.assertLessEqual(len(notify.build_message("https://e.com/", sn.Diff(changes=huge), "medium")[1]), notify.MAX_TEXT)

    def test_no_regressions_and_failures(self):
        subject, text = notify.build_message("https://example.com/", self.diffs([]), "medium")
        self.assertIn("no regressions", subject)
        subject, text = notify.build_message("https://example.com/", None, "medium", "The site is down.")
        self.assertEqual(subject, "WebCrawler: could not crawl example.com")
        self.assertIn("The site is down.", text)


class Webhook(unittest.TestCase):
    def test_the_message_arrives_as_json(self):
        h = Hook()
        self.addCleanup(h.stop)
        self.assertEqual(notify.send_webhook(h.url, "Subject", "Body", {"regressions": 3}), "")
        path, payload, ctype = h.posts[0]
        self.assertEqual(path, "/services/T000/B000/secretpath")
        self.assertEqual(ctype, "application/json")
        self.assertEqual(payload["text"], "Subject\nBody")
        self.assertEqual((payload["content"], payload["subject"], payload["regressions"]), ("Subject\nBody", "Subject", 3))

    def test_errors_never_repeat_the_secret_url(self):
        for kw, needle in (({"status": 500}, "HTTP 500"), ({"status": 404}, "HTTP 404"), ({"redirect": True}, "redirect")):
            h = Hook(**kw)
            err = notify.send_webhook(h.url, "s", "b")
            h.stop()
            self.assertIn(needle, err)
            self.assertNotIn("secretpath", err)
        self.assertEqual(len(h.posts), 1)                                                   # a redirect is reported, not followed
        err = notify.send_webhook("http://127.0.0.1:9/services/secretpath", "s", "b", timeout=2)
        self.assertTrue(err.startswith("could not reach"))
        self.assertNotIn("secretpath", err)
        self.assertIn("http", notify.send_webhook("ftp://example.com/x", "s", "b"))
        self.assertEqual(notify.describe_webhook(h.url.replace("secretpath", "x")), f"127.0.0.1:{h.server_address[1]}")


class Email(unittest.TestCase):
    def test_a_message_with_the_report_attached(self):
        s = Smtp("bot", "pw")
        self.addCleanup(s.stop)
        cfg = notify.SmtpConfig("127.0.0.1", ["a@example.com", "b@example.com"], s.port, "monitor@example.com", "bot", "pw", "none")
        self.assertEqual(notify.send_email(cfg, "Subject\nwith newline", "Body text", [("changes.html", b"<html>changes</html>", "text/html")]), "")
        m = s.parsed()
        self.assertEqual((m["Subject"], m["From"], m["To"]), ("Subject with newline", "monitor@example.com", "a@example.com, b@example.com"))
        self.assertEqual(m.get_body(("plain",)).get_content().strip(), "Body text")
        att = list(m.iter_attachments())[0]
        self.assertEqual((att.get_filename(), att.get_content()), ("changes.html", "<html>changes</html>"))
        self.assertEqual(s.messages[0]["to"], ["<a@example.com>", "<b@example.com>"])

    def test_bad_credentials_and_unreachable_servers(self):
        s = Smtp("bot", "pw")
        self.addCleanup(s.stop)
        err = notify.send_email(notify.SmtpConfig("127.0.0.1", ["a@example.com"], s.port, "", "bot", "wrong", "none"), "s", "b")
        self.assertIn("refused the user name or password", err)
        self.assertNotIn("wrong", err)
        err = notify.send_email(notify.SmtpConfig("127.0.0.1", ["a@example.com"], 9, "", "", "", "none"), "s", "b", timeout=2)
        self.assertTrue(err.startswith("could not send"))

    def test_a_password_is_never_sent_unencrypted_to_a_remote_server(self):
        self.assertIn("refusing", notify.SmtpConfig("mail.example.com", ["a@b.co"], 25, "", "u", "pw", "none").check())
        self.assertEqual(notify.SmtpConfig("mail.example.com", ["a@b.co"], 587, "", "u", "pw", "starttls").check(), "")
        self.assertEqual(notify.SmtpConfig("localhost", ["a@b.co"], 25, "", "u", "pw", "none").check(), "")
        self.assertIn("needs", notify.SmtpConfig("", ["a@b.co"]).check())
        self.assertIn("needs", notify.SmtpConfig("h", []).check())
        self.assertIn("security", notify.SmtpConfig("h", ["a@b.co"], security="tls13").check())


def args_for(**kw):
    base = dict(monitor="", target="https://example.com/", out=None, save=None, compare=None, history=None, resume=None, accepted=None, format=["json", "session"], keep=30)
    base.update(kw)
    return SimpleNamespace(**base)


class Folder(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_first_run_has_nothing_to_compare_with(self):
        a = args_for(monitor=str(self.tmp / "m"))
        plan = mon.prepare(a)
        self.assertIsNone(plan.previous)
        self.assertIsNone(a.compare)
        self.assertEqual((Path(a.out), Path(a.history)), (plan.latest, plan.history))
        self.assertTrue(plan.sessions.is_dir() and plan.latest.is_dir())
        self.assertEqual(a.format, ["json", "sarif"])                               # the session is saved once, in sessions/; the SARIF export is always kept
        self.assertRegex(plan.save.name, r"^session-\d{8}-\d{6}\.json$")

    def test_the_newest_session_is_what_the_next_crawl_compares_with(self):
        root = self.tmp / "m"
        (root / "sessions").mkdir(parents=True)
        for n in ("session-20260101-000000.json", "session-20260103-000000.json", "session-20260102-000000.json", "notes.txt"):
            (root / "sessions" / n).write_text("{}")
        a = args_for(monitor=str(root))
        plan = mon.prepare(a)
        self.assertEqual(Path(a.compare).name, "session-20260103-000000.json")

    def test_accepted_json_in_the_folder_is_used_automatically(self):
        root = self.tmp / "m"
        root.mkdir()
        (root / "accepted.json").write_text("{}")
        self.assertEqual(Path(mon.prepare(args_for(monitor=str(root))).accepted), (root / "accepted.json").resolve())
        self.assertEqual(mon.prepare(args_for(monitor=str(root), accepted="mine.json")).accepted, "mine.json")

    def test_old_outputs_are_cleared_but_nothing_else(self):
        root = self.tmp / "m"
        (root / "latest").mkdir(parents=True)
        for n in ("report.html", "changes.html", "trend.html", "keep-me.txt"):
            (root / "latest" / n).write_text("x")
        mon.prepare(args_for(monitor=str(root)))
        self.assertEqual(sorted(p.name for p in (root / "latest").iterdir()), ["keep-me.txt"])

    def test_conflicting_options_are_refused(self):
        for kw in ({"out": "x"}, {"save": "x"}, {"compare": "x"}, {"history": "x"}, {"resume": "x"}):
            with self.assertRaises(ValueError) as cm:
                mon.prepare(args_for(monitor=str(self.tmp / "m"), **kw))
            self.assertIn("--monitor chooses", str(cm.exception))
        with self.assertRaises(ValueError):
            mon.prepare(args_for(monitor=str(self.tmp / "m"), target=None))
        f = self.tmp / "file"
        f.write_text("x")
        with self.assertRaises(ValueError):
            mon.prepare(args_for(monitor=str(f)))

    def test_pruning_keeps_the_newest_and_never_fewer_than_two(self):
        d = self.tmp / "s"
        d.mkdir()
        for i in range(6):
            (d / f"session-2026010{i}-000000.json").write_text("{}")
        self.assertEqual(mon.prune(d, 3), 3)
        self.assertEqual([p.name for p in mon.sessions_in(d)], ["session-20260103-000000.json", "session-20260104-000000.json", "session-20260105-000000.json"])
        self.assertEqual(mon.prune(d, 0), 1)
        self.assertEqual(len(mon.sessions_in(d)), 2)


class Schedule(unittest.TestCase):
    def test_commands_use_absolute_paths_and_leave_secrets_out(self):
        argv = ["https://example.com", "--quick", "--monitor", "mon", "--accepted=acc.json", "--notify-webhook", "https://hooks.example/x/SECRET",
                "--cookie", "sid=SECRET2", "--print-schedule", "03:05", "--fail-on-regression"]
        c = mon.schedule_commands(argv, "03:05", sys.executable, str(ROOT / "webcrawler.py"), str(ROOT))
        text = c["windows"] + c["cron"]
        self.assertNotIn("SECRET", text)
        self.assertNotIn("--print-schedule", text)
        self.assertIn("/ST 03:05", c["windows"])
        self.assertTrue(c["cron"].startswith("5 3 * * * "))
        self.assertIn(str(Path("mon").resolve()), c["windows"])
        self.assertIn(str(Path("acc.json").resolve()), c["windows"])
        self.assertIn("--fail-on-regression", c["args"])
        self.assertEqual(set(c["dropped"]), {"--notify-webhook", "--cookie"})

    def test_the_time_is_checked(self):
        for bad in ("", "25:00", "3pm", "12:60", "noon"):
            with self.assertRaises(ValueError):
                mon.schedule_commands([], bad, "python", "x.py", ".")

    def test_cli_prints_and_creates_nothing(self):
        d = Path(tempfile.mkdtemp())
        rc, text = tcm.cli("https://example.com", "--quick", "--monitor", str(d / "m"), "--print-schedule", "04:00")
        self.assertEqual(rc, 0)
        self.assertIn("Nothing has been scheduled", text)
        self.assertIn("schtasks /Create", text)
        self.assertFalse((d / "m").exists())
        self.assertEqual(tcm.cli("https://example.com", "--print-schedule", "04:00")[0], 2)           # needs --monitor
        self.assertEqual(tcm.cli("https://example.com", "--monitor", str(d), "--print-schedule", "late")[0], 2)


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ths.serve()
        cls.srv.other_base = cls.srv.base
        cls.base = cls.srv.base

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.srv.extra = ""
        self.root = Path(tempfile.mkdtemp()) / "m"
        self.hook = Hook()
        self.addCleanup(self.hook.stop)

    def run_monitor(self, *extra, start="/"):
        return tcm.cli(self.base + start, "--quick", "--delay", "0", "--depth", "3", "-q", "--no-tls", "--monitor", str(self.root), *extra)

    def test_baseline_then_quiet_then_regression(self):
        hook = ("--notify-webhook", self.hook.url)
        rc, text = self.run_monitor(*hook, "--fail-on-regression")
        self.assertEqual(rc, 0)
        self.assertIn("first run, recording a baseline", text)
        self.assertIn("Baseline recorded", text)
        self.assertEqual(self.hook.posts, [])                                        # nothing to report on a baseline
        for name in ("report.html", "trend.html"):
            self.assertTrue((self.root / "latest" / name).exists(), name)
        self.assertEqual(len(mon.sessions_in(self.root / "sessions")), 1)

        rc, text = self.run_monitor(*hook, "--fail-on-regression")
        self.assertEqual(rc, 0)
        self.assertIn("comparing with session-", text)
        self.assertEqual(self.hook.posts, [])                                        # nothing changed: silence
        self.assertTrue((self.root / "latest" / "changes.html").exists())

        self.srv.extra = "<a href='https://paypal.com@evil.test/login'>login</a>"
        rc, text = self.run_monitor(*hook, "--fail-on-regression")
        self.assertEqual(rc, 3)
        self.assertIn("Notified the webhook at 127.0.0.1", text)
        self.assertNotIn("secretpath", text)
        self.assertEqual(len(self.hook.posts), 1)
        body = self.hook.posts[0][1]
        self.assertIn("1 regression(s) on 127.0.0.1", body["subject"])
        self.assertIn("paypal.com@evil.test", body["message"])
        self.assertEqual(len(hi.History.load(self.root / "history.json").runs), 3)
        self.assertIn("More open problems", (self.root / "latest" / "trend.html").read_text(encoding="utf-8"))

    def test_email_goes_out_with_the_changes_attached(self):
        smtp = Smtp()
        self.addCleanup(smtp.stop)
        mail = ("--notify-email", "ops@example.com", "--smtp-host", "127.0.0.1", "--smtp-port", str(smtp.port), "--smtp-security", "none", "--smtp-from", "wc@example.com")
        self.run_monitor(*mail)
        self.srv.extra = "<a href='https://bit.ly/x'>s</a>"
        rc, text = self.run_monitor(*mail)
        self.assertEqual(rc, 0)
        self.assertIn("E-mailed ops@example.com", text)
        m = smtp.parsed()
        self.assertIn("1 regression(s)", m["Subject"])
        self.assertIn("bit.ly/x", list(m.iter_attachments())[0].get_content())

    def test_notify_always_also_reports_a_clean_run_and_the_baseline(self):
        self.run_monitor("--notify-webhook", self.hook.url, "--notify-always")
        self.assertIn("baseline crawl", self.hook.posts[0][1]["subject"])
        self.run_monitor("--notify-webhook", self.hook.url, "--notify-always")
        self.assertIn("no regressions", self.hook.posts[1][1]["subject"])

    def test_the_environment_can_supply_the_webhook(self):
        import os
        os.environ["WEBCRAWLER_WEBHOOK"] = self.hook.url
        self.addCleanup(os.environ.pop, "WEBCRAWLER_WEBHOOK", None)
        self.run_monitor()
        self.srv.extra = "<a href='https://bit.ly/x'>s</a>"
        self.run_monitor()
        self.assertEqual(len(self.hook.posts), 1)

    def test_old_sessions_are_pruned(self):
        for _ in range(4):
            self.run_monitor("--keep", "2")
        self.assertEqual(len(mon.sessions_in(self.root / "sessions")), 2)
        self.assertEqual(len(hi.History.load(self.root / "history.json").runs), 4)          # but the history keeps every run

    def test_an_unreachable_site_is_reported_and_exits_4(self):
        rc, text = tcm.cli("http://127.0.0.1:9/", "--quick", "--delay", "0", "--timeout", "2", "-q", "--no-tls", "--monitor", str(self.root), "--notify-webhook", self.hook.url)
        self.assertEqual(rc, mon.EXIT_UNREACHABLE)
        self.assertIn("The site did not answer", text)
        self.assertEqual(self.hook.posts[0][1]["subject"], "WebCrawler: could not crawl 127.0.0.1:9")
        self.assertEqual(mon.sessions_in(self.root / "sessions"), [])                       # a failed crawl does not become the next baseline...
        self.assertEqual(hi.History.load(self.root / "history.json").runs, [])              # ...or a point on the trend

    def test_a_crawl_that_hit_its_limit_says_so(self):
        rc, text = self.run_monitor("--max-pages", "1")
        self.assertIn("stopped at its limit", text)

    def test_accepted_findings_in_the_folder_quiet_the_run(self):
        self.run_monitor()
        tcm.cli("--accepted", str(self.root / "accepted.json"), "--accept", "shortener", "--reason", "marketing")
        self.srv.extra = "<a href='https://bit.ly/x'>s</a>"
        rc, text = self.run_monitor("--notify-webhook", self.hook.url, "--fail-on-regression")
        self.assertEqual((rc, self.hook.posts), (0, []))
        self.assertIn("1 accepted finding(s) not counted", text)

    def test_half_configured_email_and_orphan_notification_options_are_errors(self):
        self.assertEqual(self.run_monitor("--notify-email", "a@example.com")[0], 2)                      # no --smtp-host
        self.assertEqual(tcm.cli(self.base + "/", "--quick", "--notify-webhook", self.hook.url)[0], 2)   # notifications belong to --monitor
        self.assertEqual(self.hook.posts, [])


if __name__ == "__main__":
    unittest.main()
