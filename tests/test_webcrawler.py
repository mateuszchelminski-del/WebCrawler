"""Tests for webcrawler.py. Run from the WebCrawler folder:  python -m unittest discover -s tests -v

The unit tests need nothing installed. The browser tests need Playwright and at least one browser
(Chrome, Edge or Chromium); they are skipped automatically if none can be started.
"""
import functools
import http.server
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _net  # noqa: E402,F401  (a longer listen backlog for the local test servers)
import webcrawler as wc  # noqa: E402

PAGE = "https://example.com/blog/post.html"


class Classify(unittest.TestCase):
    def kind(self, raw, page=PAGE):
        return wc.classify(wc.resolve(raw, page), page)

    def test_kinds(self):
        self.assertEqual(self.kind("/contact"), "internal")
        self.assertEqual(self.kind("../about"), "internal")
        self.assertEqual(self.kind("https://other.org/x"), "external")
        self.assertEqual(self.kind("https://www.example.com/"), "external")  # a subdomain is another host
        self.assertEqual(self.kind("#comments"), "anchor")
        self.assertEqual(self.kind("/a#b"), "internal")
        self.assertEqual(self.kind("mailto:a@b.co"), "mailto")
        self.assertEqual(self.kind("tel:+1555"), "tel")
        self.assertEqual(self.kind("/files/Report.PDF"), "file")
        self.assertEqual(self.kind("ftp://example.com/x"), "other")

    def test_not_links(self):
        for raw in ("javascript:alert(1)", "data:text/html,hi", "   ", "", "vbscript:x"):
            self.assertIsNone(wc.resolve(raw, PAGE), raw)

    def test_local_files_are_internal(self):
        page = "file:///c:/site/index.html"
        self.assertEqual(wc.classify(wc.resolve("about.html", page), page), "internal")
        self.assertEqual(wc.classify(wc.resolve("https://x.org/", page), page), "external")


class Targets(unittest.TestCase):
    def test_bare_domain_gets_https(self):
        self.assertEqual(wc.normalize_target("example.com/a"), "https://example.com/a")

    def test_existing_path_becomes_file_url(self):
        self.assertTrue(wc.normalize_target(str(ROOT / "test-site" / "index.html")).startswith("file:///"))

    def test_bad_schemes_rejected(self):
        for bad in ("javascript:alert(1)", "ftp://example.com/x", "data:text/html,hi"):
            with self.assertRaises(ValueError, msg=bad):
                wc.normalize_target(bad)


class Store(unittest.TestCase):
    def test_dedupe_count_and_stats(self):
        s = wc.LinkStore()
        a = s.add({"href": "/contact", "text": "  Contact \n us ", "page": PAGE})
        self.assertEqual((a[0], a[1].n, a[1].text, a[1].href), (True, 1, "Contact us", "https://example.com/contact"))
        b = s.add({"href": "https://example.com/contact", "text": "again", "page": PAGE})
        self.assertEqual((b[0], b[1].count, len(s)), (False, 2, 1))
        s.add({"href": "https://x.org/", "text": "x", "rel": "noopener NoFollow", "page": PAGE})
        s.add({"href": "https://y.org/p", "page": PAGE})
        s.add({"href": "mailto:me@example.com", "page": PAGE})
        self.assertIsNone(s.add({"href": "javascript:void(0)", "page": PAGE}))
        st = s.stats()
        self.assertEqual((st["total"], st["by_kind"]["internal"], st["by_kind"]["external"], st["external_hosts"]), (4, 1, 2, 2))
        self.assertTrue(next(l for l in s.all() if l.host == "x.org").nofollow)

    def test_exports(self):
        s = wc.LinkStore()
        s.add({"href": "/a", "text": 'He said "hi", ok', "page": PAGE})
        s.add({"href": "https://q.io/?x=1", "text": "=HYPERLINK(evil)", "page": PAGE})
        lines = wc.to_csv(s.all()).splitlines()
        self.assertEqual(lines[0], "#,url,text,type,host,seen,nofollow,found_on,risk,findings")
        self.assertIn('"He said ""hi"", ok"', lines[1])
        self.assertIn("'=HYPERLINK(evil)", lines[2])  # formula neutralised
        self.assertEqual(json.loads(wc.to_json(s.all(), PAGE))["count"], 2)
        self.assertEqual(wc.to_txt(s.all()), "https://example.com/a\nhttps://q.io/?x=1\n")


class Following(unittest.TestCase):
    def test_same_site(self):
        self.assertTrue(wc.same_site("https://a.com/x", "https://a.com/"))
        self.assertFalse(wc.same_site("https://b.com/x", "https://a.com/"))
        self.assertFalse(wc.same_site("http://a.com/x", "https://a.com/"))
        self.assertTrue(wc.same_site("file:///site/sub/p.html", "file:///site/index.html"))
        self.assertFalse(wc.same_site("file:///other/p.html", "file:///site/index.html"))

    def test_robots(self):
        r = wc.Robots(True)
        rp = wc.robotparser.RobotFileParser()
        rp.parse(["User-agent: *", "Disallow: /private/"])
        r._cache["https://a.com"] = rp
        self.assertTrue(r.allowed("https://a.com/public"))
        self.assertFalse(r.allowed("https://a.com/private/x"))
        self.assertTrue(wc.Robots(False).allowed("https://a.com/private/x"))
        self.assertTrue(r.allowed("file:///anything"))

    def test_candidates(self):
        s = wc.LinkStore()
        page = "https://a.com/"
        for h in ("/one", "/two#frag", "/one", "https://b.com/x", "/private/p", "/doc.pdf", "mailto:x@y.z", "/seen"):
            s.add({"href": h, "page": page})
        rp = wc.robotparser.RobotFileParser()
        rp.parse(["User-agent: *", "Disallow: /private/"])
        robots = wc.Robots(True)
        robots._cache["https://a.com"] = rp
        got = wc.follow_candidates(s.all(), page, page, {"https://a.com/seen"}, robots)
        self.assertEqual(got, ["https://a.com/one", "https://a.com/two"])


class Cli(unittest.TestCase):
    def test_headless_requires_auto(self):
        with self.assertRaises(SystemExit):
            wc.main(["https://example.com", "--headless"])

    def test_overlay_script_carries_config(self):
        js = wc.overlay_script("hacker", "line", False)
        self.assertTrue(js.startswith('window.__WC_CONFIG = {"skin": "hacker", "mode": "line", "summoned": false};'))
        self.assertIn("__wc_capture", js)


class CliOptions(unittest.TestCase):
    def opts(self, *argv):
        return wc.build_options(wc.build_parser().parse_args(["https://example.com", *argv]))

    def test_defaults_differ_by_mode(self):
        self.assertEqual(self.opts().depth, 0)
        self.assertEqual(self.opts("--quick").depth, 2)
        self.assertEqual(self.opts("--quick", "--depth", "5").depth, 5)

    def test_preset_then_explicit_flags_win(self):
        o = self.opts("--preset", "stealth", "--delay-min", "1", "--concurrency", "3", "--scope", "subdomains")
        self.assertEqual((o.delay_min, o.delay_max, o.concurrency, o.scope), (1.0, 15.0, 3, "subdomains"))
        o = self.opts("--delay", "2")
        self.assertEqual((o.delay_min, o.delay_max), (2.0, 2.0))
        o = self.opts("--delay-min", "9")  # a minimum above the default maximum raises the maximum with it
        self.assertEqual((o.delay_min, o.delay_max), (9.0, 9.0))

    def test_filters_and_limits(self):
        o = self.opts("--include", "/docs", "--exclude", "/logout", "--exclude", "x=1", "--max-duration", "90", "--ignore-robots", "--strategy", "dfs")
        self.assertEqual((o.include, o.exclude, o.max_duration, o.ignore_robots, o.strategy), (["/docs"], ["/logout", "x=1"], 90.0, True, "dfs"))

    def test_new_network_options(self):
        o = self.opts("--quick", "--insecure", "--render", "never", "--render-limit", "7", "--max-variants", "5", "--user-agent", "chrome")
        self.assertEqual((o.verify_tls, o.render, o.render_limit, o.max_query_variants), (False, "never", 7, 5))
        self.assertTrue(o.user_agent.startswith("Mozilla/5.0") and "Chrome" in o.user_agent)
        self.assertEqual(self.opts("--user-agent", "MyBot/1.0").user_agent, "MyBot/1.0")
        d = self.opts()
        self.assertEqual((d.verify_tls, d.render, d.render_limit, d.max_query_variants), (True, "auto", 100, 20))

    def test_render_flags_need_quick(self):
        with self.assertRaises(SystemExit):
            wc.main(["https://example.com", "--render", "always"])

    def test_bad_regex_is_an_error(self):
        with self.assertRaises(ValueError):
            self.opts("--exclude", "([bad")

    def test_quick_rejects_browser_flags(self):
        for flag in ("--auto", "--headless"):
            with self.assertRaises(SystemExit):
                wc.main(["https://example.com", "--quick", flag])


class CliQuickScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT / "tests"))
        import test_httpscan as ths
        cls.srv, cls.base = ths.serve()
        cls.srv.ext_base = cls.base

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def run_cli(self, *extra):
        d = tempfile.mkdtemp()
        rc = wc.main([self.base + "/index.html", "--quick", "--delay", "0", "--depth", "3", "--out", d, "-q", *extra])
        return rc, Path(d)

    def test_writes_every_artifact(self):
        rc, d = self.run_cli()
        self.assertEqual(rc, 0)
        names = {p.name for p in d.iterdir()}
        self.assertEqual(names, {"links.json", "links.csv", "links.txt", "report.html", "sitemap.html", "graph.json", "session.json"})
        report = (d / "report.html").read_text(encoding="utf-8")
        self.assertIn("nope.html", report)  # the broken link is in the report
        graph = json.loads((d / "graph.json").read_text(encoding="utf-8"))
        self.assertGreater(graph["stats"]["pages"], 5)
        self.assertIn("<canvas", (d / "sitemap.html").read_text(encoding="utf-8"))

    def test_format_selection(self):
        rc, d = self.run_cli("--format", "csv", "map")
        self.assertEqual({p.name for p in d.iterdir()}, {"links.csv", "sitemap.html"})


# ----------------------------------------------------------------------------------- real-browser tests

def _have_browser():
    try:
        from playwright.sync_api import Error, sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as pw:
            forced = os.environ.get("WEBCRAWLER_BROWSER", "").strip().lower()
            for name in ((forced,) if forced in wc.BROWSERS else wc.AUTO_ORDER):
                engine, channel = wc.BROWSERS[name]
                try:
                    b = getattr(pw, engine).launch(headless=True, **({"channel": channel} if channel else {}))
                    b.close()
                    return True
                except Error:
                    continue
    except Exception:
        pass
    return False


@unittest.skipUnless(_have_browser(), "Playwright with a browser is not available")
class RealBrowser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(ROOT / "test-site"))
        handler.log_message = lambda *a, **k: None
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def crawl(self, target, *extra):
        with tempfile.TemporaryDirectory() as d:
            rc = wc.main([target, "--auto", "--headless", "--delay", "0", "--speed", "900", "--out", d, "-q", *extra])
            self.assertEqual(rc, 0)
            return json.loads((Path(d) / "links.json").read_text(encoding="utf-8"))

    def test_single_page_scroll_capture(self):
        data = self.crawl(self.base + "/index.html")
        by = {l["href"]: l for l in data["links"]}
        b = self.base
        for expected, kind in ((b + "/about.html", "internal"), (b + "/deep/page.html", "internal"), ("mailto:hello@test.example", "mailto"),
                               ("tel:+15555550100", "tel"), (b + "/files/report.pdf", "file"), ("https://example.org/", "external"),
                               (b + "/index.html#top", "anchor"), (b + "/late.html", "internal"), (b + "/private/secret.html", "internal")):
            self.assertIn(expected, by, expected)
            self.assertEqual(by[expected]["kind"], kind, expected)
        self.assertEqual(by[b + "/about.html"]["count"], 2)  # linked twice on the page
        self.assertTrue(by["https://partner.test.example/offer"]["nofollow"])
        self.assertFalse(any("hidden.html" in h or h.startswith("javascript") for h in by))  # invisible / not real links

    def test_follow_respects_depth_and_robots(self):
        data = self.crawl(self.base + "/index.html", "--depth", "3")
        found_on = {l["page"] for l in data["links"]}
        self.assertIn(self.base + "/deep/page.html", found_on)
        self.assertIn(self.base + "/deep/level3.html", found_on)
        self.assertFalse(any("/private/" in p for p in found_on), "robots.txt forbids /private/")
        self.assertNotIn("https://secret.test.example/", {l["href"] for l in data["links"]})

    def test_depth_zero_stays_on_start_page(self):
        data = self.crawl(self.base + "/index.html")
        self.assertEqual({l["page"] for l in data["links"]}, {self.base + "/index.html"})

    def test_ignore_robots_enters_private(self):
        data = self.crawl(self.base + "/index.html", "--depth", "1", "--ignore-robots")
        self.assertIn("https://secret.test.example/", {l["href"] for l in data["links"]})

    def test_local_file_target(self):
        data = self.crawl(str(ROOT / "test-site" / "index.html"))
        self.assertTrue(any(l["href"].endswith("/about.html") and l["kind"] == "internal" for l in data["links"]))

    def test_scan_line_mode_still_captures_when_scrolling(self):
        data = self.crawl(self.base + "/index.html", "--mode", "line", "--speed", "300")
        self.assertIn(self.base + "/late.html", {l["href"] for l in data["links"]})


if __name__ == "__main__":
    unittest.main()
