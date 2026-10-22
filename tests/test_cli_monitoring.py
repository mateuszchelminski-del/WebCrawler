"""The command-line monitoring workflow: save a crawl, resume it, compare it later, log in, fail a build on regressions.
No browser needed: everything uses --quick against a local server."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_httpscan_checks as ths  # noqa: E402
import webcrawler as wc  # noqa: E402


def cli(*argv):
    """Run the CLI, returning (exit code, printed output)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = wc.main(list(argv))
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 2
    return rc, out.getvalue() + err.getvalue()


class Monitoring(unittest.TestCase):
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
        self.srv.hits.clear()
        self.srv.extra = ""
        self.tmp = Path(tempfile.mkdtemp())

    def crawl(self, name, *extra, start="/"):
        out = self.tmp / name
        rc, text = cli(self.base + start, "--quick", "--delay", "0", "--depth", "3", "-q", "--out", str(out), "--no-tls", *extra)
        return rc, text, out

    def test_two_identical_crawls_have_no_differences(self):
        rc, _, a = self.crawl("a")
        rc, text, b = self.crawl("b", "--compare", str(a / "session.json"), "--fail-on-regression")
        self.assertEqual(rc, 0)
        self.assertIn("No differences", text)
        self.assertTrue((b / "changes.html").exists())

    def test_titles_and_link_text_the_console_cannot_show_do_not_end_the_crawl(self):
        # output redirected to a file on Windows uses a legacy code page; an arrow in a link's text must not become an error
        self.srv.extra = "<a href='/a?x=1'>Docs ↗ café 日本</a>"
        raw = io.BytesIO()
        out = io.TextIOWrapper(raw, encoding="cp1252", errors="strict", write_through=True)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = wc.main([self.base + "/", "--quick", "--delay", "0", "--depth", "1", "--out", str(self.tmp / "u"), "--no-tls", "--format", "json"])
        self.assertEqual(rc, 0)
        self.assertIn("Docs", raw.getvalue().decode("cp1252"))
        links = json.loads((self.tmp / "u" / "links.json").read_text(encoding="utf-8"))
        self.assertTrue(any("↗" in l["text"] for l in links["links"]))              # the saved data keeps the real characters

    def test_a_local_folder_can_be_quick_scanned(self):
        site = self.tmp / "site"
        (site / "docs").mkdir(parents=True)
        (site / "index.html").write_text("<title>Home</title><a href='docs/a.html'>A</a><a href='https://bit.ly/x'>s</a>", encoding="utf-8")
        (site / "docs" / "a.html").write_text("<title>A</title><a href='../index.html'>home</a>", encoding="utf-8")
        for target in (str(site), str(site / "index.html")):
            out = self.tmp / ("o" + str(len(target)))
            rc, text = cli(target, "--quick", "--delay", "0", "--depth", "2", "-q", "--out", str(out), "--no-tls", "--format", "json")
            self.assertEqual(rc, 0, text)
            self.assertIn("served at http://127.0.0.1:", text)
            links = {l["href"] for l in json.loads((out / "links.json").read_text(encoding="utf-8"))["links"]}
            self.assertTrue(any(h.endswith("/docs/a.html") for h in links), links)
            self.assertIn("https://bit.ly/x", links)

    def test_a_new_risky_link_fails_the_build(self):
        _, _, a = self.crawl("a")
        self.srv.extra = "<a href='https://paypal.com@evil.test/login'>login</a>"
        rc, text, b = self.crawl("b", "--compare", str(a / "session.json"), "--fail-on-regression")
        self.assertEqual(rc, 3)
        self.assertIn("New problems (1)", text)
        self.assertIn("exiting with status 3", text)
        changes = json.loads((b / "changes.json").read_text(encoding="utf-8"))
        self.assertTrue(any(c["section"] == "risk-new" and "paypal.com@evil.test" in c["subject"] for c in changes["changes"]))
        self.assertIn("paypal.com@evil.test", (b / "changes.html").read_text(encoding="utf-8").replace("&#x27;", "'"))

    def test_without_the_flag_a_regression_is_reported_but_does_not_fail(self):
        _, _, a = self.crawl("a")
        self.srv.extra = "<a href='https://bit.ly/x'>s</a>"
        rc, text, _ = self.crawl("b", "--compare", str(a / "session.json"))
        self.assertEqual(rc, 0)
        self.assertIn("New problems", text)

    def test_fail_level(self):
        _, _, a = self.crawl("a")
        self.srv.extra = "<a href='https://example.org:8443/x'>odd port</a>"   # a low finding
        self.assertEqual(self.crawl("b", "--compare", str(a / "session.json"), "--fail-on-regression")[0], 0)           # medium: not tripped
        self.assertEqual(self.crawl("c", "--compare", str(a / "session.json"), "--fail-on-regression", "low")[0], 3)    # low: tripped

    def test_diff_two_saved_sessions(self):
        _, _, a = self.crawl("a")
        self.srv.extra = "<a href='https://bit.ly/x'>s</a>"
        _, _, b = self.crawl("b")
        out = self.tmp / "diff"
        rc, text = cli("--diff", str(a / "session.json"), str(b / "session.json"), "--out", str(out), "--fail-on-regression")
        self.assertEqual(rc, 3)
        self.assertIn("Comparing", text)
        self.assertTrue((out / "changes.html").exists())
        rc, text = cli("--diff", str(a / "session.json"), str(a / "session.json"))
        self.assertEqual(rc, 0)
        self.assertIn("No differences", text)

    def test_diff_of_a_bad_file_is_a_clean_error(self):
        bad = self.tmp / "bad.json"
        bad.write_text("nope", encoding="utf-8")
        rc, text = cli("--diff", str(bad), str(bad))
        self.assertEqual(rc, 2)
        self.assertIn("not a session file", text)

    def test_stop_early_then_resume(self):
        rc, text, a = self.crawl("a", "--max-pages", "2", start="/chain/0")
        self.assertIn("--resume", text)                                   # told how to continue
        session = a / "session.json"
        data = json.loads(session.read_text(encoding="utf-8"))
        self.assertTrue(data["resume"]["queue"])
        first = dict(self.srv.hits)
        rc, text = cli("--resume", str(session), "--quick", "--delay", "0", "--max-pages", "50", "--depth", "10", "-q", "--out", str(self.tmp / "b"), "--no-tls")
        self.assertEqual(rc, 0)
        self.assertIn("Resuming", text)
        self.assertEqual(json.loads((self.tmp / "b" / "session.json").read_text(encoding="utf-8"))["resume"], None)   # finished this time
        chain = {p: n for p, n in self.srv.hits.items() if p.startswith("/chain/")}
        self.assertEqual(len(chain), 8)
        self.assertTrue(all(n == 1 for n in chain.values()), chain)       # nothing fetched twice
        self.assertTrue(set(first) <= set(self.srv.hits))

    def test_resume_of_a_finished_session_starts_over_and_says_so(self):
        _, _, a = self.crawl("a")
        rc, text = cli("--resume", str(a / "session.json"), "--quick", "--delay", "0", "-q", "--out", str(self.tmp / "b"), "--no-tls")
        self.assertEqual(rc, 0)
        self.assertIn("nothing to resume", text)

    def test_login_from_flags_and_environment(self):
        secret = "VERYSECRET123"
        rc, text, a = self.crawl("a", "--cookie", f"sid=ok; trace={secret}", "--header", "X-Token: t", start="/members")
        self.assertEqual(rc, 0)
        self.assertIn("Using your login", text)
        self.assertNotIn(secret, text)
        self.assertEqual(len(json.loads((a / "session.json").read_text(encoding="utf-8"))["graph"]["nodes"]) >= 2, True)
        self.assertNotIn("/logout", self.srv.hits)
        with mock.patch.dict(os.environ, {"WEBCRAWLER_COOKIE": f"sid=ok; trace={secret}", "WEBCRAWLER_HEADERS": "X-Token: t"}):
            rc, text, b = self.crawl("b", start="/members")
        self.assertIn("/account", (b / "links.txt").read_text(encoding="utf-8"))
        for d in (a, b):                                                  # the secret never reaches any output file
            for f in d.iterdir():
                self.assertNotIn(secret, f.read_text(encoding="utf-8"), f.name)

    def test_cookie_file_and_bad_header(self):
        cf = self.tmp / "cookies.json"
        cf.write_text(json.dumps([{"name": "sid", "value": "ok", "domain": "127.0.0.1", "path": "/"}]), encoding="utf-8")
        rc, text, out = self.crawl("a", "--cookie-file", str(cf), "--header", "X-Token: t", start="/members")
        self.assertEqual(rc, 0)
        self.assertIn("/account", (out / "links.txt").read_text(encoding="utf-8"))
        rc, text = cli(self.base + "/", "--quick", "--header", "no colon here", "--out", str(self.tmp / "x"))
        self.assertEqual(rc, 2)
        self.assertIn("not a header", text)

    def test_probe_and_sitemap_flags(self):
        rc, text, a = self.crawl("a", "--probe-files")
        site = json.loads((a / "session.json").read_text(encoding="utf-8"))["site"]
        self.assertTrue(any(f["path"] == "/.git/HEAD" and f["exposed"] for f in site["files"]))
        self.assertIn("Site-wide findings", text)
        report = (a / "report.html").read_text(encoding="utf-8")
        self.assertIn("Git repository is publicly readable", report)
        self.srv.hits.clear()
        self.crawl("b", "--no-sitemap")
        self.assertNotIn("/sitemap.xml", self.srv.hits)

    def test_save_path_and_format_selection(self):
        target = self.tmp / "named.json"
        rc, text, out = self.crawl("a", "--save", str(target), "--format", "csv")
        self.assertTrue(target.exists())
        self.assertEqual({p.name for p in out.iterdir()}, {"links.csv"})


if __name__ == "__main__":
    unittest.main()
