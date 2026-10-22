"""Quick-scanner tests. No browser needed: everything runs against small local HTTP servers."""
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
import frontier as fr  # noqa: E402
import graph as gr  # noqa: E402
import httpscan as hs  # noqa: E402
import webcrawler as wc  # noqa: E402


class Site(http.server.SimpleHTTPRequestHandler):
    """test-site/ plus a few virtual routes for redirects, throttling, slowness and an unreliable page."""
    hits: dict = {}

    def log_message(self, *a, **k):
        pass

    def _html(self, body, status=200, extra=None):
        data = ("<html><head><title>V</title></head><body>" + body + "</body></html>").encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        Site.hits[path] = Site.hits.get(path, 0) + 1
        if path in ("/redir", "/perm"):
            self.send_response(301 if path == "/redir" else 308)
            self.send_header("Location", "/about.html")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/flaky":
            if Site.hits[path] == 1:
                self._html("slow down", 429, {"Retry-After": "0"})
            else:
                self._html("<a href='/about.html'>ok now</a>")
        elif path == "/slowroot":
            self._html("".join(f"<a href='/slow/{i}'>s{i}</a>" for i in range(8)))
        elif path.startswith("/slow/"):
            time.sleep(0.3)
            self._html("slow page")
        elif path == "/pdfroot":
            self._html("<a href='/files/report.pdf'>pdf</a><a href='/data.bin'>bin</a>")
        elif path == "/data.bin":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", "3")
            self.end_headers()
            self.wfile.write(b"<a>")
        elif path == "/chain":
            self._html("<a href='/redir'>redirects</a><a href='/perm'>permanent</a><a href='/flaky'>flaky</a><a href='/nope'>gone</a>")
        elif path == "/crawldelay/robots.txt" or path == "/robots.txt" and getattr(self.server, "crawl_delay", 0):
            body = f"User-agent: *\nCrawl-delay: {self.server.crawl_delay}\n".encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/ext":
            self._html(f"<a href='{self.server.ext_base}/ok'>ok</a><a href='{self.server.ext_base}/gone'>gone</a>")
        elif path == "/ok":
            self._html("fine")
        else:
            super().do_GET()

    def do_HEAD(self):
        path = self.path.split("?")[0]
        if path == "/ok":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/gone":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            super().do_HEAD()


def serve():
    handler = functools.partial(Site, directory=str(ROOT / "test-site"))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def scan(start, **kw):
    opts = fr.CrawlOptions(delay_min=0, delay_max=0, **kw)
    ev, store, site = queue.Queue(), wc.LinkStore(), gr.SiteGraph()
    s = hs.QuickScanner(start, opts, store, site, ev)
    t = time.time()
    s.start()
    s.join(timeout=60)
    events = []
    while not ev.empty():
        events.append(ev.get())
    return s, events, store, site, time.time() - t


class Parser(unittest.TestCase):
    def test_links_text_title_base(self):
        p = hs.parse_html("<title> My  Page </title><base href='/x/'><a href='a.html'>Hello <b>there</b></a><a href='b' aria-label='Label'><img alt='logo'></a>"
                          "<a href='c'><img alt='only image'></a><area href='/map' alt='Map'><a>no href</a>")
        self.assertEqual(p.title, "My Page")
        self.assertEqual(p.base, "/x/")
        self.assertEqual([(l["href"], l["text"]) for l in p.links], [("a.html", "Hello there"), ("b", "Label"), ("c", "only image"), ("/map", "Map")])

    def test_broken_markup_does_not_raise(self):
        p = hs.parse_html("<a href='x'><div><a href='y'></p></table>>><<")
        self.assertGreaterEqual(len(p.links), 1)


class Scanning(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = serve()
        cls.ext, cls.ext_base = serve()
        cls.srv.ext_base = cls.ext_base

    @classmethod
    def tearDownClass(cls):
        for srv in (cls.srv, cls.ext):
            srv.shutdown()
            srv.server_close()

    def setUp(self):
        Site.hits.clear()

    def test_full_crawl_finds_pages_broken_links_and_findings(self):
        s, ev, store, site, _ = scan(self.base + "/index.html", depth=3)
        visited = {u for u in s.frontier.visited}
        for page in ("/index.html", "/about.html", "/deep/page.html", "/deep/level3.html", "/late.html"):
            self.assertIn(self.base + page, visited, page)
        self.assertFalse(any("/private/" in u for u in visited), "robots.txt forbids /private/")
        broken = [e for e in ev if e[0] == "broken"]
        self.assertTrue(any(e[1].endswith("/nope.html") and e[2] == 404 and e[3].endswith("/index.html") for e in broken), broken)
        self.assertEqual(ev[0][:2], ("auto", True))
        self.assertIn(("auto", False), [e[:2] for e in ev])
        self.assertEqual(ev[-1][:2], ("auto", False))
        self.assertTrue(any(e[0] == "scan_done" for e in ev))
        self.assertTrue(any(e[0] == "security" for e in ev))
        flagged = {f.code for e in ev if e[0] == "link" for f in e[2]}
        self.assertTrue({"shortener", "userinfo", "raw-ip", "sensitive-file"} <= flagged, flagged)
        self.assertIn((fr.normalize(self.base + "/index.html"), fr.normalize(self.base + "/about.html")), site.edges)
        self.assertEqual(site.nodes[fr.normalize(self.base + "/nope.html")].status, 404)
        self.assertGreater(site.stats()["pages"], 5)
        self.assertEqual(s.summary["pages"], len(visited))

    def test_ignore_robots_enters_private(self):
        s, *_ = scan(self.base + "/index.html", depth=1, ignore_robots=True)
        self.assertTrue(any("/private/" in u for u in s.frontier.visited))

    def test_limits(self):
        s, *_ = scan(self.base + "/index.html", depth=5, max_pages=2)
        self.assertEqual(len(s.frontier.visited), 2)
        s, *_ = scan(self.base + "/index.html", depth=0)
        self.assertEqual(len(s.frontier.visited), 1)

    def test_files_not_fetched_and_non_html_not_parsed(self):
        s, ev, store, *_ = scan(self.base + "/pdfroot", depth=2)
        visited = {u.replace(self.base, "") for u in s.frontier.visited}
        self.assertNotIn("/files/report.pdf", visited)       # downloads are recorded as links, never fetched
        self.assertIn("/data.bin", visited)                   # an unknown type is requested...
        self.assertEqual({l.href for l in store.all()}, {self.base + "/files/report.pdf", self.base + "/data.bin"})  # ...but its body is never parsed

    def test_redirect_retry_and_missing(self):
        s, ev, _, site, _ = scan(self.base + "/chain", depth=1)
        node = site.nodes[fr.normalize(self.base + "/redir")]
        self.assertEqual(node.status, 301)
        self.assertIn((fr.normalize(self.base + "/redir"), fr.normalize(self.base + "/about.html")), site.edges)
        self.assertEqual(site.nodes[fr.normalize(self.base + "/perm")].status, 308)  # a 308 is followed too
        self.assertIn((fr.normalize(self.base + "/perm"), fr.normalize(self.base + "/about.html")), site.edges)
        self.assertEqual(site.nodes[fr.normalize(self.base + "/flaky")].status, 200)  # 429 once, then retried
        self.assertGreaterEqual(Site.hits["/flaky"], 2)
        self.assertTrue(any(e[0] == "broken" and e[1].endswith("/nope") for e in ev))

    def test_pacing_spaces_requests(self):
        opts = fr.CrawlOptions(depth=1, delay_min=0.25, delay_max=0.25, concurrency=4)
        ev, store, site = queue.Queue(), wc.LinkStore(), gr.SiteGraph()
        s = hs.QuickScanner(self.base + "/chain", opts, store, site, ev)
        t = time.time()
        s.start()
        s.join(60)
        self.assertGreaterEqual(s.pages, 4)
        self.assertGreaterEqual(time.time() - t, 0.25 * (s.pages - 1) - 0.1)

    def test_concurrency_is_faster_than_one_at_a_time(self):
        _, _, _, _, fast = scan(self.base + "/slowroot", depth=1, concurrency=8)
        _, _, _, _, slow = scan(self.base + "/slowroot", depth=1, concurrency=1)
        self.assertLess(fast, slow * 0.6, (fast, slow))

    def test_stop_ends_quickly(self):
        opts = fr.CrawlOptions(depth=1, delay_min=0.5, delay_max=0.5, concurrency=1)
        ev, store, site = queue.Queue(), wc.LinkStore(), gr.SiteGraph()
        s = hs.QuickScanner(self.base + "/slowroot", opts, store, site, ev)
        s.start()
        time.sleep(1.2)
        s.stop()
        t = time.time()
        s.join(10)
        self.assertFalse(s.is_alive())
        self.assertLess(time.time() - t, 3.0)
        self.assertTrue(s.summary["stopped"])

    def test_max_duration(self):
        opts = fr.CrawlOptions(depth=1, delay_min=0.3, delay_max=0.3, concurrency=1, max_duration=0.8)
        ev, store, site = queue.Queue(), wc.LinkStore(), gr.SiteGraph()
        s = hs.QuickScanner(self.base + "/slowroot", opts, store, site, ev)
        s.start()
        s.join(20)
        self.assertEqual(s.summary["limit"], "time limit")
        self.assertLess(s.pages, 9)

    def test_check_external_links(self):
        s, ev, _, site, _ = scan(self.base + "/ext", depth=1, check_external=True, ignore_robots=True)
        broken = [e for e in ev if e[0] == "broken"]
        self.assertTrue(any(e[1].endswith("/gone") and e[2] == 404 for e in broken), broken)
        self.assertFalse(any(e[1].endswith("/ok") for e in broken))
        self.assertEqual(site.nodes[fr.normalize(self.ext_base + "/ok")].status, 200)

    def test_unreachable_host_is_reported_not_raised(self):
        s, ev, *_ = scan("http://127.0.0.1:9/", depth=0, timeout=3)
        self.assertTrue(any(e[0] == "broken" and e[2] == 0 for e in ev))
        self.assertTrue(any(e[0] == "scan_done" for e in ev))

    def test_robots_crawl_delay_slows_the_scan(self):
        self.srv.crawl_delay = 1  # robots.txt only allows whole seconds
        try:
            opts = fr.CrawlOptions(depth=1, delay_min=0, delay_max=0, concurrency=4)
            ev, store, site = queue.Queue(), wc.LinkStore(), gr.SiteGraph()
            s = hs.QuickScanner(self.base + "/pdfroot", opts, store, site, ev)
            t = time.time()
            s.start()
            s.join(60)
            self.assertEqual(s.pages, 2)
            self.assertGreaterEqual(time.time() - t, 0.9)
        finally:
            self.srv.crawl_delay = 0


if __name__ == "__main__":
    unittest.main()
