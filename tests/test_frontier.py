import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import frontier as fr  # noqa: E402

ROOT = "https://example.com/"


class Normalize(unittest.TestCase):
    def test_canonical_form(self):
        self.assertEqual(fr.normalize("HTTPS://Example.COM:443/a?utm_source=x&id=1#frag"), "https://example.com/a?id=1")
        self.assertEqual(fr.normalize("http://example.com:80"), "http://example.com/")
        self.assertEqual(fr.normalize("https://example.com:8443/x"), "https://example.com:8443/x")
        self.assertEqual(fr.normalize("file:///c:/a/b.html#x"), "file:///c:/a/b.html")

    def test_tracking_params_dropped_real_ones_kept(self):
        self.assertEqual(fr.normalize("https://e.com/?fbclid=1&gclid=2&page=3"), "https://e.com/?page=3")


class Scope(unittest.TestCase):
    def test_host_scope(self):
        self.assertTrue(fr.in_scope("https://example.com/x", ROOT, "host"))
        self.assertTrue(fr.in_scope("https://www.example.com/x", ROOT, "host"))  # www is the same site
        self.assertFalse(fr.in_scope("https://blog.example.com/x", ROOT, "host"))
        self.assertFalse(fr.in_scope("https://evil.com/x", ROOT, "host"))
        self.assertFalse(fr.in_scope("https://example.com:8443/x", ROOT, "host"))

    def test_subdomain_and_any(self):
        self.assertTrue(fr.in_scope("https://blog.example.com/x", ROOT, "subdomains"))
        self.assertTrue(fr.in_scope("http://example.com/x", ROOT, "subdomains"))
        self.assertFalse(fr.in_scope("https://notexample.com/x", ROOT, "subdomains"))
        self.assertTrue(fr.in_scope("https://anything.org/", ROOT, "any"))
        self.assertFalse(fr.in_scope("mailto:a@b.co", ROOT, "any"))

    def test_local_files(self):
        root = "file:///site/index.html"
        self.assertTrue(fr.in_scope("file:///site/sub/p.html", root, "host"))
        self.assertFalse(fr.in_scope("file:///other/p.html", root, "host"))


class FakeRobots:
    def allowed(self, url):
        return "/private/" not in url


class FrontierRules(unittest.TestCase):
    def make(self, **kw):
        return fr.Frontier(ROOT, fr.CrawlOptions(**kw), FakeRobots())

    def test_start_page_first(self):
        f = self.make()
        self.assertEqual(f.pop(), ("https://example.com/", 0, None))
        self.assertIsNone(f.pop())

    def test_dedupe_and_visited(self):
        f = self.make()
        f.pop()
        self.assertTrue(f.push("https://example.com/a#x", 1, ROOT))
        self.assertFalse(f.push("https://example.com/a?utm_source=z", 1, ROOT))  # same page after normalising
        self.assertFalse(f.push(ROOT, 1, ROOT))  # already visited

    def test_filters_and_reasons(self):
        f = self.make(depth=2, exclude=[r"/logout"], include=[r"example\.com/(docs|blog)"])
        f.pop()
        self.assertTrue(f.push("https://example.com/docs/a", 1, ROOT))
        self.assertFalse(f.push("https://example.com/about", 1, ROOT))
        self.assertFalse(f.push("https://example.com/docs/logout", 1, ROOT))
        self.assertFalse(f.push("https://other.org/docs/a", 1, ROOT))
        self.assertFalse(f.push("https://example.com/docs/b", 3, ROOT))
        self.assertFalse(f.push("https://example.com/docs/report.pdf", 1, ROOT))
        self.assertFalse(f.push("mailto:a@b.co", 1, ROOT))
        self.assertEqual(f.skipped, {"not included": 1, "excluded": 1, "out of scope": 1, "too deep": 1, "file download": 1, "not a web page": 1})

    def test_robots_checked_at_pop(self):
        f = self.make()
        f.pop()
        f.push("https://example.com/private/x", 1, ROOT)
        f.push("https://example.com/ok", 1, ROOT)
        self.assertEqual(f.pop()[0], "https://example.com/ok")
        self.assertEqual(f.skipped["blocked by robots.txt"], 1)
        g = self.make(ignore_robots=True)
        g.pop()
        g.push("https://example.com/private/x", 1, ROOT)
        self.assertEqual(g.pop()[0], "https://example.com/private/x")

    def test_bfs_vs_dfs_order(self):
        for strategy, want in (("bfs", ["a", "b", "c"]), ("dfs", ["c", "b", "a"])):
            f = self.make(strategy=strategy)
            f.pop()
            for n in "abc":
                f.push(f"https://example.com/{n}", 1, ROOT)
            self.assertEqual([f.pop()[0].rsplit("/", 1)[1] for _ in range(3)], want, strategy)

    def test_max_pages(self):
        f = self.make(max_pages=3)
        f.pop()
        for n in range(10):
            f.push(f"https://example.com/{n}", 1, ROOT)
        self.assertEqual(sum(1 for _ in iter(f.pop, None)), 2)
        self.assertEqual(len(f.visited), 3)


class StateAndResume(unittest.TestCase):
    def test_state_round_trip_keeps_queue_visited_and_deferred(self):
        o = fr.CrawlOptions(depth=1)
        f = fr.Frontier(ROOT, o, FakeRobots())
        f.pop()
        f.push("https://example.com/a", 1, ROOT)
        f.push("https://example.com/b", 1, ROOT)
        f.push("https://example.com/deep", 2, "https://example.com/a")   # one hop too deep
        f.pop()
        again = fr.Frontier.from_state(json.loads(json.dumps(f.to_state())), o, FakeRobots())
        self.assertEqual((sorted(again.visited), [x[0] for x in again._q]), (sorted(f.visited), ["https://example.com/b"]))
        self.assertEqual(len(again.deferred), 1)

    def test_a_deeper_resume_picks_up_the_deferred_links(self):
        f = fr.Frontier(ROOT, fr.CrawlOptions(depth=0), FakeRobots())
        f.pop()
        f.push("https://example.com/a", 1, ROOT)
        self.assertEqual(len(f), 0)
        deeper = fr.Frontier.from_state(f.to_state(), fr.CrawlOptions(depth=1), FakeRobots())
        self.assertEqual(deeper.pop()[0], "https://example.com/a")
        same = fr.Frontier.from_state(f.to_state(), fr.CrawlOptions(depth=0), FakeRobots())
        self.assertIsNone(same.pop())

    def test_requeue_puts_the_page_next(self):
        for strategy in ("bfs", "dfs"):
            f = fr.Frontier(ROOT, fr.CrawlOptions(strategy=strategy), FakeRobots())
            f.pop()
            f.push("https://example.com/a", 1, ROOT)
            f.push("https://example.com/b", 1, ROOT)
            f.requeue("https://example.com/started", 1, ROOT)
            self.assertEqual(f.pop()[0], "https://example.com/started", strategy)
            f.requeue("https://example.com/started", 1, ROOT)       # requeueing a page that is already waiting changes nothing
            f.requeue("https://example.com/started", 1, ROOT)
            self.assertEqual(sum(1 for x in f._q if x[0].endswith("started")), 1)


class PacerTests(unittest.TestCase):
    def test_spacing_between_requests(self):
        now = [100.0]
        p = fr.Pacer(fr.CrawlOptions(delay_min=1.0, delay_max=1.0), clock=lambda: now[0])
        self.assertEqual(p.reserve(), 0.0)            # first request goes at once
        self.assertAlmostEqual(p.reserve(), 1.0)      # the second must wait a full gap
        self.assertAlmostEqual(p.reserve(), 2.0)      # and the third queues behind it
        now[0] = 110.0
        self.assertEqual(p.reserve(), 0.0)            # after a pause the queue is empty again

    def test_random_gap_stays_in_range(self):
        for r, want in ((0.0, 2.0), (1.0, 6.0)):
            now = [0.0]
            p = fr.Pacer(fr.CrawlOptions(delay_min=2.0, delay_max=6.0), clock=lambda: now[0], rng=lambda r=r: r)
            p.reserve()
            self.assertAlmostEqual(p.reserve(), want)

    def test_rps_cap_and_robots_floor(self):
        now = [0.0]
        p = fr.Pacer(fr.CrawlOptions(delay_min=0.0, delay_max=0.0, max_rps=4), clock=lambda: now[0])
        p.reserve()
        self.assertAlmostEqual(p.reserve(), 0.25)
        q = fr.Pacer(fr.CrawlOptions(delay_min=0.1, delay_max=0.1), clock=lambda: now[0], min_floor=5.0)
        q.reserve()
        self.assertAlmostEqual(q.reserve(), 5.0)  # Crawl-delay from robots.txt wins


class Options(unittest.TestCase):
    def test_clamped(self):
        o = fr.CrawlOptions(depth=999, max_pages=0, delay_min=3, delay_max=1, concurrency=0, scope="bogus", strategy="x").clamped()
        self.assertEqual((o.depth, o.max_pages, o.delay_max, o.concurrency, o.scope, o.strategy), (25, 1, 3.0, 1, "host", "bfs"))

    def test_presets_ordered_by_speed(self):
        gaps = [fr.with_preset(n).delay_min for n in ("stealth", "polite", "balanced", "fast", "blitz")]
        self.assertEqual(gaps, sorted(gaps, reverse=True))
        self.assertEqual(fr.with_preset("stealth").concurrency, 1)


if __name__ == "__main__":
    unittest.main()
