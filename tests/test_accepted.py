"""Accepted findings: the file format, matching and expiry, and how they quiet comparisons, reports and the command line."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import accepted as ac  # noqa: E402
import analysis as an  # noqa: E402
import report  # noqa: E402
import snapshot as sn  # noqa: E402
import test_cli_monitoring as tcm  # noqa: E402
import test_snapshot as ts  # noqa: E402
import webcrawler as wc  # noqa: E402

TODAY = date(2026, 10, 21)


def acc(*entries):
    return ac.Accepted(list(entries), today=TODAY)


def entry(code, where="*", expires="", reason="because"):
    return {"code": code, "where": where, "reason": reason, "expires": expires, "added": "2026-01-01"}


class Matching(unittest.TestCase):
    def test_codes_and_places_are_globs_and_case_insensitive(self):
        a = acc(entry("no-csp", "https://Example.com/docs/*"), entry("cookie-*", "*"), entry("host-unresolved", "old.example.com"))
        self.assertTrue(a.match("no-csp", "https://example.com/docs/a/b"))
        self.assertFalse(a.match("no-csp", "https://example.com/other"))
        self.assertFalse(a.match("no-hsts", "https://example.com/docs/a"))
        self.assertTrue(a.match("COOKIE-NO-SECURE", "anything"))
        self.assertTrue(a.match("host-unresolved", "OLD.example.com"))
        self.assertFalse(a.match("host-unresolved", "new.example.com"))

    def test_expiry(self):
        a = acc(entry("no-csp", expires="2026-10-20"), entry("no-hsts", expires="2026-10-21"), entry("no-nosniff", expires="2027-01-01"), entry("weak-csp"))
        self.assertIsNone(a.match("no-csp", "x"))                           # expired yesterday
        self.assertIsNotNone(a.lapsed("no-csp", "x"))
        self.assertIsNotNone(a.match("no-hsts", "x"))                       # today is still inside the date
        self.assertIsNotNone(a.match("no-nosniff", "x"))
        self.assertIsNotNone(a.match("weak-csp", "x"))                      # no expiry: until removed
        self.assertIsNone(a.lapsed("weak-csp", "x"))

    def test_split_and_unused(self):
        a = acc(entry("no-csp"), entry("gone-problem"))
        fs = [{"code": "no-csp", "where": "u1", "severity": "low"}, {"code": "no-hsts", "where": "u1", "severity": "low"}]
        open_, done = a.split(fs)
        self.assertEqual(([f["code"] for f in open_], [f["code"] for f in done]), (["no-hsts"], ["no-csp"]))
        self.assertEqual(done[0]["accepted_reason"], "because")
        self.assertEqual([e["code"] for e in a.unused(fs)], ["gone-problem"])        # nothing matched it any more: safe to remove


class Files(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_round_trip_and_replacing_an_entry(self):
        a = ac.Accepted(today=TODAY)
        a.add("no-csp", "https://e.com/*", "static pages", "2027-06-30")
        a.add("no-csp", "https://e.com/*", "new reason")                              # same code and place: replaced, not duplicated
        a.add("weak-csp")
        p = self.tmp / "sub" / "accepted.json"
        a.save(p)
        b = ac.Accepted.load(p, TODAY)
        self.assertEqual(len(b), 2)
        self.assertEqual(b.entries[0]["reason"] if b.entries[0]["code"] == "no-csp" else b.entries[1]["reason"], "new reason")
        self.assertEqual(json.loads(p.read_text(encoding="utf-8"))["format"], "webcrawler-accepted")
        self.assertTrue(b.remove("weak-csp"))
        self.assertFalse(b.remove("weak-csp"))

    def test_a_missing_file_is_an_empty_list(self):
        self.assertEqual(len(ac.Accepted.load(self.tmp / "nope.json")), 0)
        self.assertEqual(len(ac.Accepted.load(None)), 0)

    def test_bad_files_are_refused_with_a_reason(self):
        for text, needle in (("{not json", "not valid JSON"), ('{"format": "other"}', "not a WebCrawler accepted"), ('[]', "not a WebCrawler accepted"),
                             ('{"format": "webcrawler-accepted", "accepted": [{"where": "*"}]}', "no 'code'"),
                             ('{"format": "webcrawler-accepted", "accepted": [{"code": "x", "expires": "next week"}]}', "YYYY-MM-DD")):
            p = self.tmp / "bad.json"
            p.write_text(text, encoding="utf-8")
            with self.assertRaises(ValueError) as cm:
                ac.Accepted.load(p)
            self.assertIn(needle, str(cm.exception))

    def test_add_validates(self):
        with self.assertRaises(ValueError):
            ac.Accepted().add("", "*")
        with self.assertRaises(ValueError):
            ac.Accepted().add("no-csp", "*", expires="soon")


def page_session(urls, code="password-in-url", headers=None):
    """A bare session whose pages all have one finding."""
    return {"created": "2026-10-01T00:00:00Z", "start": "https://e.com/", "links": [], "broken": [], "site": {},
            "graph": {"nodes": [{"url": u, "kind": "page", "visited": True, "status": 200} for u in urls], "edges": [], "sources": []},
            "pages": [{"url": u, "status": 200, "findings": ([{"code": code, "severity": "low", "title": "No CSP", "detail": ""}] if code else []), "headers": headers or {}} for u in urls]}


class InComparisons(unittest.TestCase):
    def test_accepted_findings_are_not_new_problems(self):
        old, _ = ts.crawl()
        new, _ = ts.crawl(["https://bit.ly/x"], site_findings=[(an.Finding("exposed-file", "high", ".env file is readable", "/.env"), "https://example.com/.env")])
        plain = sn.diff(old, new)
        self.assertEqual(len(plain.regressions("low")), 2)
        quiet = sn.diff(old, new, acc(entry("shortener", "https://bit.ly/*"), entry("exposed-file", "https://example.com/.env", reason="honeypot")))
        self.assertEqual(quiet.regressions("low"), [])
        self.assertEqual(quiet.suppressed, 2)
        self.assertIn("2 accepted finding(s) not counted", quiet.summary())
        self.assertEqual(quiet.to_dict()["suppressed"], 2)

    def test_an_expired_acceptance_counts_again(self):
        old, _ = ts.crawl()
        new, _ = ts.crawl(["https://bit.ly/x"])
        d = sn.diff(old, new, acc(entry("shortener", expires="2026-01-01")))
        self.assertEqual((len(d.regressions("low")), d.suppressed), (1, 0))

    def test_a_removed_header_can_be_accepted_by_the_finding_it_would_raise(self):
        old, _ = ts.crawl()
        new, _ = ts.crawl(headers={"strict-transport-security": "max-age=31536000"})        # the CSP header disappeared
        self.assertTrue([c for c in sn.diff(old, new).changes if c.section in ("header-weaker", "risk-new")])
        d = sn.diff(old, new, acc(entry("no-csp")))
        self.assertEqual([c for c in d.changes if c.section == "header-weaker"], [])

    def test_fixes_are_still_reported(self):
        old, _ = ts.crawl(findings=[an.Finding("password-in-url", "medium", "Password form posts in the clear")])
        new, _ = ts.crawl()
        d = sn.diff(old, new, acc(entry("password-in-url")))
        self.assertTrue([c for c in d.changes if c.section == "risk-resolved"])


class Grouping(unittest.TestCase):
    def test_the_same_finding_on_many_pages_is_one_line(self):
        urls = [f"https://e.com/p{i}" for i in range(12)]
        d = sn.diff(page_session(urls, code=None), page_session(urls))
        rows = [c for c in d.changes if c.section == "risk-new"]
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0].subject, rows[0].count, rows[0].code), ("12 places", 12, "password-in-url"))
        self.assertIn("e.g. https://e.com/p0", rows[0].detail)
        self.assertEqual(len(d.regressions("low")), 1)

    def test_a_few_pages_are_listed_individually(self):
        urls = [f"https://e.com/p{i}" for i in range(4)]
        d = sn.diff(page_session(urls, code=None), page_session(urls))
        self.assertEqual(len([c for c in d.changes if c.section == "risk-new"]), 4)

    def test_grouped_fixes(self):
        urls = [f"https://e.com/p{i}" for i in range(9)]
        d = sn.diff(page_session(urls), page_session(urls, code=None))
        rows = [c for c in d.changes if c.section == "risk-resolved"]
        self.assertEqual((len(rows), rows[0].count), (1, 9))

    def test_accepting_by_pattern_quiets_the_whole_group(self):
        urls = [f"https://e.com/p{i}" for i in range(12)]
        d = sn.diff(page_session(urls, code=None), page_session(urls), acc(entry("password-in-url", "https://e.com/*")))
        self.assertEqual(([c for c in d.changes if c.section == "risk-new"], d.suppressed), ([], 12))

    def test_hardening_that_got_weaker_everywhere_is_grouped_too(self):
        urls = [f"https://e.com/p{i}" for i in range(10)]
        d = sn.diff(page_session(urls, code=None), page_session(urls, code="no-csp"))
        rows = [c for c in d.changes if c.section == "header-weaker"]
        self.assertEqual((len(rows), rows[0].count), (1, 10))


class InReports(unittest.TestCase):
    def test_accepted_findings_are_listed_apart_and_not_counted(self):
        import webcrawler
        page = an.PageSecurity("https://e.com/", 200, [an.Finding("no-csp", "low", "No Content-Security-Policy <b>x</b>"), an.Finding("no-hsts", "medium", "No HSTS")], {})
        link = webcrawler.Link(1, "https://bit.ly/x", "x", "external", "bit.ly", 1, False, "https://e.com/")
        everything = report.build_html("https://e.com/", [link], [page], [], None, {})
        self.assertIn("No HSTS", everything)
        quiet = report.build_html("https://e.com/", [link], [page], [], None, {}, acc(entry("no-csp", reason="static <i>site</i>"), entry("shortener")))
        head, _, tail = quiet.partition("<h2>Accepted findings</h2>")
        self.assertIn("No HSTS", head)
        self.assertNotIn("No Content-Security-Policy", head)                  # not in the page-security table...
        self.assertIn("No Content-Security-Policy", tail)                     # ...but listed under Accepted, with the reason
        self.assertIn("static &lt;i&gt;site&lt;/i&gt;", tail)
        self.assertNotIn("<i>site</i>", quiet)
        self.assertNotIn("<b>x</b>", quiet)
        self.assertNotIn("Accepted findings", report.build_html("https://e.com/", [link], [page], [], None, {}))
        lapsed = report.build_html("https://e.com/", [], [page], [], None, {}, acc(entry("no-csp", expires="2026-01-01")))
        self.assertIn("Expired acceptances", lapsed)
        self.assertIn("No Content-Security-Policy", lapsed.partition("<h2>Accepted findings</h2>")[0])        # it counts again

    def test_diff_report_mentions_suppressed(self):
        old, _ = ts.crawl()
        new, _ = ts.crawl(["https://bit.ly/x"])
        h = report.build_diff_html(sn.diff(old, new, acc(entry("shortener"))))
        self.assertIn("1 new finding(s) are accepted", h)


class OnTheCommandLine(tcm.Monitoring):
    """Inherits the local server and helpers from the monitoring tests (their own test methods are not repeated here)."""

    def test_accept_and_unaccept_edit_the_file(self):
        f = self.tmp / "acc" / "accepted.json"
        rc, text = tcm.cli("--accepted", str(f), "--accept", "no-csp", "--where", "https://e.com/*", "--reason", "static", "--expires", "2027-01-01")
        self.assertEqual(rc, 0)
        self.assertIn("Accepted no-csp @ https://e.com/* until 2027-01-01: static", text)
        self.assertEqual(ac.Accepted.load(f).entries[0]["reason"], "static")
        rc, text = tcm.cli("--accepted", str(f), "--accept", "weak-csp")
        self.assertIn("Tip: add --reason", text)
        self.assertEqual(len(ac.Accepted.load(f)), 2)
        rc, text = tcm.cli("--accepted", str(f), "--unaccept", "no-csp", "--where", "https://e.com/*")
        self.assertEqual((rc, len(ac.Accepted.load(f))), (0, 1))
        self.assertEqual(tcm.cli("--accept", "no-csp")[0], 2)                          # no file given
        self.assertEqual(tcm.cli("--accepted", str(f), "--accept", "x", "--expires", "soon")[0], 2)

    def test_a_bad_file_stops_before_any_request(self):
        f = self.tmp / "bad.json"
        f.write_text("{oops", encoding="utf-8")
        self.srv.hits.clear()
        rc, text = tcm.cli(self.base + "/", "--quick", "--accepted", str(f), "-q", "--out", str(self.tmp / "o"), "--no-tls")
        self.assertEqual(rc, 2)
        self.assertIn("not valid JSON", text)
        self.assertEqual(dict(self.srv.hits), {})

    def test_an_accepted_regression_does_not_fail_the_build(self):
        _, _, a = self.crawl("a")
        self.srv.extra = "<a href='https://bit.ly/x'>s</a>"
        f = self.tmp / "accepted.json"
        self.assertEqual(self.crawl("b", "--compare", str(a / "session.json"), "--fail-on-regression")[0], 3)
        rc, text, b = self.crawl("c", "--compare", str(a / "session.json"), "--fail-on-regression", "--accepted", str(f))
        self.assertEqual(rc, 3)                                                           # the file does not exist yet: nothing accepted
        tcm.cli("--accepted", str(f), "--accept", "shortener", "--reason", "marketing links")
        rc, text, b = self.crawl("d", "--compare", str(a / "session.json"), "--fail-on-regression", "--accepted", str(f))
        self.assertEqual(rc, 0)
        self.assertIn("1 accepted finding(s) not counted", text)
        self.assertIn("accepted, not counted", text)
        self.assertIn("marketing links", (b / "report.html").read_text(encoding="utf-8"))

    def test_the_environment_variable_names_the_file(self):
        _, _, a = self.crawl("a")
        self.srv.extra = "<a href='https://bit.ly/x'>s</a>"
        f = self.tmp / "env.json"
        tcm.cli("--accepted", str(f), "--accept", "shortener")
        import os
        old = os.environ.get("WEBCRAWLER_ACCEPTED")
        os.environ["WEBCRAWLER_ACCEPTED"] = str(f)
        try:
            self.assertEqual(self.crawl("b", "--compare", str(a / "session.json"), "--fail-on-regression")[0], 0)
        finally:
            if old is None:
                os.environ.pop("WEBCRAWLER_ACCEPTED")
            else:
                os.environ["WEBCRAWLER_ACCEPTED"] = old


# the inherited monitoring tests were already run by their own module; do not run them a second time here
for _name in [n for n in dir(tcm.Monitoring) if n.startswith("test_") and n not in vars(OnTheCommandLine)]:
    setattr(OnTheCommandLine, _name, None)


if __name__ == "__main__":
    unittest.main()
