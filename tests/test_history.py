"""The history of a monitored site: a row of numbers per crawl, and the trend page drawn from them."""
import json
import re
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
import history as hi  # noqa: E402
import snapshot as sn  # noqa: E402
import test_cli_monitoring as tcm  # noqa: E402
import test_snapshot as ts  # noqa: E402


class Summaries(unittest.TestCase):
    def test_counts_open_findings_by_severity(self):
        s, _ = ts.crawl(["https://bit.ly/x", "https://203.0.113.9/x"], findings=[an.Finding("no-csp", "low", "No CSP")],
                        site_findings=[(an.Finding("exposed-file", "high", ".env readable"), "https://example.com/.env")])
        row = hi.summarize(s)
        self.assertEqual((row["high"], row["medium"], row["low"], row["accepted"]), (1, 2, 1, 0))
        self.assertEqual((row["pages"], row["links"]), (1, 4))
        self.assertTrue(row["created"])

    def test_accepted_findings_are_counted_apart(self):
        s, _ = ts.crawl(["https://bit.ly/x"], findings=[an.Finding("no-csp", "low", "No CSP")])
        row = hi.summarize(s, ac.Accepted([{"code": "no-csp", "where": "*", "reason": "", "expires": "", "added": ""}], today=date(2026, 1, 1)))
        self.assertEqual((row["low"], row["medium"], row["accepted"]), (0, 1, 1))

    def test_a_comparison_adds_what_changed(self):
        old, _ = ts.crawl()
        new, _ = ts.crawl(["https://bit.ly/x"])
        row = hi.summarize(new, None, sn.diff(old, new))
        self.assertEqual((row["regressions"], row["fixed"], row["new_pages"], row["changed_pages"]), (1, 0, 0, 0))
        self.assertNotIn("regressions", hi.summarize(new))


class Files(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_round_trip_and_cap(self):
        h = hi.History()
        for i in range(hi.MAX_RUNS + 5):
            h.add({"created": f"2026-01-01T00:00:{i % 60:02d}Z", "high": i}, "https://e.com/")
        self.assertEqual((len(h.runs), h.runs[-1]["high"], h.start), (hi.MAX_RUNS, hi.MAX_RUNS + 4, "https://e.com/"))
        p = self.tmp / "a" / "history.json"
        h.save(p)
        self.assertEqual(len(hi.History.load(p).runs), hi.MAX_RUNS)
        self.assertEqual(sorted(x.name for x in p.parent.iterdir()), ["history.json"])               # no temp files left behind

    def test_missing_and_bad_files(self):
        self.assertEqual(hi.History.load(self.tmp / "none.json").runs, [])
        for text in ("{oops", '{"format": "something-else"}', "[]"):
            p = self.tmp / "bad.json"
            p.write_text(text, encoding="utf-8")
            with self.assertRaises(ValueError):
                hi.History.load(p)

    def test_direction(self):
        h = hi.History()
        self.assertEqual(h.direction(), "steady")
        h.add({"high": 0, "medium": 2, "low": 1})
        h.add({"high": 0, "medium": 1, "low": 3})
        self.assertEqual(h.direction(), "better")                      # one medium fewer outweighs two more lows
        h.add({"high": 1, "medium": 0, "low": 0})
        self.assertEqual(h.direction(), "worse")
        h.add({"high": 1, "medium": 0, "low": 0})
        self.assertEqual(h.direction(), "steady")


class TrendPage(unittest.TestCase):
    def history(self, n=5):
        h = hi.History("https://e.com/<b>")
        for i in range(n):
            h.add({"created": f"2026-10-{i + 1:02d}T00:00:00Z", "pages": 20 + i, "high": i % 2, "medium": 3 - i % 3, "low": 5, "accepted": 2, "regressions": i, "changed_pages": 1})
        return h

    def test_it_is_a_self_contained_chart(self):
        page = hi.trend_html(self.history())
        self.assertIn("<svg", page)
        self.assertEqual(page.count("<polyline"), 3)
        self.assertEqual(page.count("<circle"), 15)
        self.assertIn("2026-10-05", page)
        self.assertNotRegex(page, r"<script|src=|href=")
        self.assertIn("&lt;b&gt;", page)                                 # the site's name is escaped
        self.assertNotIn("<b>", page.split("<main>")[1].split("</h1>")[0] + "")

    def test_empty_and_single_run(self):
        self.assertIn("No crawls recorded", hi.trend_html(hi.History()))
        one = hi.trend_html(self.history(1))
        self.assertEqual(one.count("<polyline"), 0)                     # nothing to join yet, but the point is drawn
        self.assertEqual(one.count("<circle"), 3)

    def test_the_headline_says_which_way_it_went(self):
        h = hi.History()
        h.add({"created": "2026-10-01", "high": 2})
        h.add({"created": "2026-10-02", "high": 0})
        self.assertIn("Fewer open problems", hi.trend_html(h))

    def test_long_histories_are_trimmed_for_drawing(self):
        h = hi.History()
        for i in range(400):
            h.add({"created": f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}Z", "high": 1})
        self.assertEqual(hi.trend_html(h).count("<circle"), 120 * 3)

    def test_text_table(self):
        t = self.history().to_text(3)
        self.assertEqual(len(t.splitlines()), 4)
        self.assertIn("regression(s)", t)


class OnTheCommandLine(tcm.Monitoring):
    def test_each_crawl_extends_the_history_and_redraws_the_trend(self):
        hist = self.tmp / "h" / "history.json"
        _, _, a = self.crawl("a", "--history", str(hist))
        self.assertEqual(len(hi.History.load(hist).runs), 1)
        self.srv.extra = "<a href='https://bit.ly/x'>s</a>"
        rc, text, b = self.crawl("b", "--history", str(hist), "--compare", str(a / "session.json"))
        self.last_output = text
        runs = hi.History.load(hist).runs
        changes = json.loads((b / "changes.json").read_text(encoding="utf-8"))["changes"]
        self.assertTrue(any(c["section"] == "risk-new" and "bit.ly" in c["subject"] for c in changes), (changes[:4], self.last_output[-1500:]))
        self.assertEqual(len(runs), 2)
        self.assertGreaterEqual(runs[-1]["medium"] - runs[0]["medium"], 1)               # (how many other pages differ between two crawls depends on timing)
        self.assertGreaterEqual(runs[-1]["regressions"], 1)
        self.assertIn("open problems are worse", text)
        page = (b / "trend.html").read_text(encoding="utf-8")
        self.assertIn("More open problems", page)
        self.assertEqual(page.count("<circle"), 6)
        self.assertEqual(json.loads(hist.read_text(encoding="utf-8"))["start"], self.base + "/")


for _name in [n for n in dir(tcm.Monitoring) if n.startswith("test_") and n not in vars(OnTheCommandLine)]:
    setattr(OnTheCommandLine, _name, None)

if __name__ == "__main__":
    unittest.main()
