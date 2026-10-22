"""Engine tests: drive a real browser through the same worker thread the GUI uses. Skipped if no browser is available."""
import functools
import http.server
import queue
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_webcrawler import _have_browser  # noqa: E402

import engine as eng  # noqa: E402
import frontier as fr  # noqa: E402


class WeakHeaders(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Server", "Apache/2.4.49")
        self.send_header("Set-Cookie", "sid=1; Path=/")
        super().end_headers()


def collect(e, until, timeout=60):
    """Gather engine events until until(events) is true."""
    seen, end = [], time.time() + timeout
    while time.time() < end and not until(seen):
        try:
            seen.append(e.events.get(timeout=0.3))
        except queue.Empty:
            pass
    return seen


def finished(events):
    return ("auto", False) in [x[:2] for x in events]


@unittest.skipUnless(_have_browser(), "Playwright with a browser is not available")
class EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        handler = functools.partial(WeakHeaders, directory=str(ROOT / "test-site"))
        handler.log_message = lambda *a, **k: None
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def run_engine(self, url, depth=0, **opts):
        e = eng.Engine()
        e.start()
        o = dict(delay_min=0, delay_max=0, scroll_speed=900, depth=depth)
        o.update(opts)
        e.send("start", settings=eng.Settings(url=url, headless=True, auto=True, opts=fr.CrawlOptions(**o)))
        self.addCleanup(lambda: (e.send("quit"), e.join(timeout=10)))
        return e

    def test_auto_crawl_emits_links_security_and_finishes(self):
        e = self.run_engine(self.base + "/index.html")
        ev = collect(e, finished)
        self.assertIn("browser", [x[0] for x in ev])
        self.assertIn(("auto", True), [x[:2] for x in ev])
        links = {x[1].href: x for x in ev if x[0] == "link"}
        self.assertIn(self.base + "/about.html", links)
        flagged = {f.code for x in ev if x[0] == "link" for f in x[2]}
        wanted = {"raw-ip", "shortener", "userinfo", "punycode", "open-redirect", "sensitive-file", "admin-path", "exec-download"}
        self.assertTrue(wanted <= flagged, flagged)
        sec = [x[1] for x in ev if x[0] == "security"]
        self.assertTrue(sec, "no page security event")
        codes = {f.code for f in sec[0].findings}
        self.assertTrue({"no-csp", "server-version", "cookie-no-httponly"} <= codes, codes)

    def test_depth_follows_and_reset_clears(self):
        e = self.run_engine(self.base + "/index.html", depth=1)
        ev = collect(e, finished)
        pages = [x[1] for x in ev if x[0] == "page"]
        self.assertGreaterEqual(len(pages), 3)
        self.assertFalse(any("/private/" in p for p in pages))  # robots.txt respected
        before = len(e.store)
        e.send("reset")  # forgets everything, then re-captures only what is visible on the current page
        time.sleep(1.5)
        self.assertGreater(before, 10)
        self.assertLess(len(e.store), before)

    def test_crawl_builds_the_site_graph_and_reports_broken_links(self):
        e = self.run_engine(self.base + "/index.html", depth=3)
        ev = collect(e, finished)
        index, about = fr.normalize(self.base + "/index.html"), fr.normalize(self.base + "/about.html")
        self.assertIn((index, about), e.graph.edges)
        self.assertTrue(e.graph.nodes[about].visited)
        self.assertTrue(any(x[0] == "broken" and x[1].endswith("/nope.html") and x[2] == 404 for x in ev), [x for x in ev if x[0] == "broken"])
        done = [x for x in ev if x[0] == "scan_done"]
        self.assertEqual(len(done), 1)
        self.assertGreaterEqual(done[0][1]["pages"], 5)
        self.assertTrue(any(x[0] == "progress" for x in ev) or done[0][1]["seconds"] < 1)

    def test_delay_between_pages_is_applied(self):
        t = time.time()
        e = self.run_engine(self.base + "/index.html", depth=1, max_pages=3, delay_min=1.0, delay_max=1.0)
        collect(e, finished)
        self.assertGreaterEqual(time.time() - t, 2.0)  # three pages, two gaps of a second

    def test_time_limit_stops_the_crawl(self):
        e = self.run_engine(self.base + "/index.html", depth=5, delay_min=1.0, delay_max=1.0, max_duration=3.0)
        ev = collect(e, finished)
        done = [x for x in ev if x[0] == "scan_done"][0][1]
        self.assertEqual(done["limit"], "time limit")

    def test_stop_command_ends_auto_crawl(self):
        e = self.run_engine(self.base + "/index.html", depth=5, delay_min=1.0, delay_max=1.0)
        collect(e, lambda s: ("auto", True) in [x[:2] for x in s])
        e.send("auto", on=False)
        ev = collect(e, finished, timeout=15)
        self.assertTrue([x for x in ev if x[0] == "scan_done"][0][1]["stopped"])

    def test_unavailable_browser_reports_instead_of_crashing(self):
        e = eng.Engine()
        e.start()
        self.addCleanup(lambda: (e.send("quit"), e.join(timeout=10)))
        e.send("start", settings=eng.Settings(url=self.base, browser="webkit", headless=True))
        ev = collect(e, lambda s: any(x[0] == "browser" for x in s), timeout=30)
        browsers = [x for x in ev if x[0] == "browser"]
        self.assertTrue(browsers)
        self.assertIn(browsers[0][1], ("error", "running"))  # "running" only if webkit happens to be installed


if __name__ == "__main__":
    unittest.main()
