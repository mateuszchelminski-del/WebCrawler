"""Quick-scanner behaviour that only shows up on real sites. Each test reproduces something a real run turned up:
Cloudflare-hosted sites that serve clean URLs through 308 redirects and protect e-mail addresses, servers that always compress,
rate limiting, firewalls that refuse unknown clients, crawler traps, self-signed certificates, huge sitemaps, odd encodings."""
import gzip
import os
import queue
import ssl
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import checks as ck  # noqa: E402
import frontier as fr  # noqa: E402
import graph as gr  # noqa: E402
import httpscan as hs  # noqa: E402
import test_httpclient as thc  # noqa: E402
import webcrawler as wc  # noqa: E402


def cf_encode(addr: str, key: int = 0x4B) -> str:
    return bytes([key] + [b ^ key for b in addr.encode()]).hex()


class Site(thc.Handler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        srv = self.server
        path, _, query = self.path.partition("?")
        n = srv.hits[path] = srv.hits.get(path, 0) + 1
        srv.order.append(path)
        base = srv.base
        if path == "/":
            kids = "".join(f"<a href='/p/{i}'>page {i}</a>" for i in range(srv.kids))
            return self.send_body(f"<title>Home</title>{kids}<a href='/old.html'>old</a><a href='/new'>new</a><a href='/email'>mail</a>"
                                  f"<a href='/cdn-cgi/trace'>trace</a><a href='/cal?d=1'>calendar</a><a href='/loop-a'>loop</a>", ctype="text/html")
        if path.startswith("/p/"):
            return self.send_body(f"<title>{path}</title><p>{path}</p><a href='/'>home</a>")
        if path == "/old.html":
            return self.redirect("/new", 308)
        if path == "/new":
            return self.send_body("<title>New</title><a href='/p/1'>one</a>")
        if path == "/email":
            h = cf_encode("me@example.com")
            return self.send_body(f"<a href='/cdn-cgi/l/email-protection#{h}'>write to me</a>"
                                  f"<a class='__cf_email__' href='/cdn-cgi/l/email-protection#{h}' data-cfemail='{h}'>[email&#160;protected]</a>")
        if path == "/cdn-cgi/l/email-protection" or path.startswith("/cdn-cgi/"):
            return self.send_body("not a page", 404)
        if path == "/cal":
            d = int(query.split("=")[1])
            return self.send_body(f"<a href='/cal?d={d + 1}'>next day</a>")
        if path == "/loop-a":
            return self.redirect("/loop-b")
        if path == "/loop-b":
            return self.redirect("/loop-a")
        if path == "/always-gzip":
            return self.send_body(gzip.compress(b"<a href='/p/7'>seven</a><a href='/p/8'>eight</a>"), headers={"Content-Encoding": "gzip"})
        if path == "/latin1":
            return self.send_body("<title>café</title><a href='/p/3'>café crème</a>".encode("latin-1"), ctype="text/html; charset=iso-8859-1")
        if path == "/bom-utf16":
            return self.send_body("<a href='/p/4'>utf16</a>".encode("utf-16"), ctype="text/html")
        if path == "/huge":
            return self.send_body("<a href='/p/5'>five</a>" + "<p>filler</p>" * 400000, ctype="text/html")
        if path == "/rl":
            return self.send_body("<a href='/rl/1'>1</a><a href='/rl/2'>2</a><a href='/rl/3'>3</a><a href='/rl/4'>4</a>")
        if path.startswith("/rl/"):
            if srv.hits[path] <= srv.fail_first:        # 429 on every attempt the client is willing to make, so the page ends up refused
                return self.send_body("slow down", 429, headers={"Retry-After": "0"})
            return self.send_body("fine")
        if path.startswith("/blocked"):
            return self.send_body("<a href='/blocked/1'>1</a><a href='/blocked/2'>2</a><a href='/blocked/3'>3</a>") if path == "/blocked" else self.send_body("no", 403)
        if path == "/basic":
            return self.send_body("login", 401, headers={"WWW-Authenticate": 'Basic realm="staff"'})
        if path == "/robots.txt":
            return self.send_body("User-agent: *\nDisallow: /secret/\n", ctype="text/plain")
        if path == "/sitemap.xml" and srv.big_sitemap:
            urls = "".join(f"<url><loc>{base}/s/{i}</loc></url>" for i in range(50000))
            return self.send_body(f"<urlset>{urls}</urlset>", ctype="application/xml")
        if path.startswith("/s/"):
            return self.send_body("<p>sitemap page</p>")
        return super().do_GET()


def serve(**attrs):
    srv = thc.Server(("127.0.0.1", 0), Site)
    srv.log, srv.counts, srv.other = [], {}, ""
    srv.hits, srv.order, srv.kids, srv.fail_first, srv.big_sitemap = {}, [], 60, 0, False
    for k, v in attrs.items():
        setattr(srv, k, v)
    srv.base = f"http://127.0.0.1:{srv.server_address[1]}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def scan(start, wait=90, **kw):
    kw.setdefault("delay_min", 0)
    kw.setdefault("delay_max", 0)
    kw.setdefault("depth", 2)
    kw.setdefault("use_sitemap", False)
    kw.setdefault("check_tls", False)
    opts = fr.CrawlOptions(**kw)
    ev, store, site, info = queue.Queue(), wc.LinkStore(), gr.SiteGraph(), ck.SiteInfo()
    s = hs.QuickScanner(start, opts, store, site, ev, {}, info)
    s.start()
    s.join(wait)
    events = []
    while not ev.empty():
        events.append(ev.get())
    return s, events, store, site, info


class RealWorld(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = serve()
        cls.base = cls.srv.base

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.srv.hits.clear()
        self.srv.order.clear()
        self.srv.fail_first = 0
        self.srv.big_sitemap = False

    # ---------------------------------------------------------------- efficiency
    def test_many_pages_share_a_few_connections(self):
        s, ev, store, site, info = scan(self.base + "/", depth=1, concurrency=4)
        net = s.summary["net"]
        self.assertGreaterEqual(net["requests"], 60)
        self.assertLessEqual(net["connections"], 8, net)                       # 60+ requests on at most 2 x concurrency connections
        self.assertGreater(net["reused"], net["requests"] * 0.8, net)
        self.assertIn("connection(s)", " ".join(e[1] for e in ev if e[0] == "status"))

    def test_a_server_that_always_compresses_is_read_correctly(self):
        s, ev, store, *_ = scan(self.base + "/always-gzip", depth=0)
        self.assertTrue({self.base + "/p/7", self.base + "/p/8"} <= {l.href for l in store.all()})

    def test_odd_encodings_still_yield_links_and_text(self):
        s, ev, store, site, info = scan(self.base + "/latin1", depth=0)
        link = next(l for l in store.all() if l.href.endswith("/p/3"))
        self.assertEqual(link.text, "café crème")
        self.assertEqual(site.nodes[fr.normalize(self.base + "/latin1")].title, "café")
        s, ev, store, *_ = scan(self.base + "/bom-utf16", depth=0)
        self.assertIn(self.base + "/p/4", {l.href for l in store.all()})

    def test_a_huge_page_is_cut_but_its_early_links_are_kept(self):
        s, ev, store, *_ = scan(self.base + "/huge", depth=0)
        self.assertIn(self.base + "/p/5", {l.href for l in store.all()})

    # ---------------------------------------------------------------- redirects and platform quirks
    def test_clean_url_redirects_do_not_inflate_the_page_count(self):
        s, ev, store, site, info = scan(self.base + "/", depth=1)
        st = site.stats()
        self.assertGreaterEqual(st["redirects"], 1)
        self.assertEqual(st["pages"], len([n for n in site.nodes.values() if n.visited and not (300 <= (n.status or 0) < 400)]))
        nodes, edges = site.view()
        self.assertNotIn(fr.normalize(self.base + "/old.html"), {n.url for n in nodes})                  # folded into /new
        self.assertIn((fr.normalize(self.base + "/"), fr.normalize(self.base + "/new")), {e for e, _ in edges})

    def test_redirect_loops_are_reported_as_errors_with_a_reason(self):
        s, ev, *_ = scan(self.base + "/loop-a", depth=0)
        broken = [e for e in ev if e[0] == "broken"]
        self.assertTrue(broken and broken[0][4] == "redirect loop", broken)

    def test_cloudflare_protected_email_links_become_mailto_links_and_are_never_fetched(self):
        s, ev, store, site, info = scan(self.base + "/email", depth=1)
        links = {l.href: l for l in store.all()}
        self.assertIn("mailto:me@example.com", links)
        self.assertEqual(links["mailto:me@example.com"].kind, "mailto")
        self.assertNotIn("/cdn-cgi/l/email-protection", self.srv.hits)
        self.assertFalse([e for e in ev if e[0] == "broken"])
        self.assertFalse(any("[email" in l.text for l in store.all()))           # Cloudflare's placeholder text never reaches the results

    def test_cloudflare_platform_endpoints_are_not_crawled(self):
        s, *_ = scan(self.base + "/", depth=1)
        self.assertNotIn("/cdn-cgi/trace", self.srv.hits)
        self.assertGreaterEqual(s.frontier.skipped.get("platform endpoint", 0), 1)

    def test_cloudflare_email_decoding(self):
        self.assertEqual(wc.decode_cf_email(cf_encode("a.b+c@example.org", 0x07)), "a.b+c@example.org")
        self.assertEqual(wc.decode_cf_email("zz"), "")
        self.assertEqual(wc.decode_cf_email(""), "")
        self.assertEqual(wc.resolve(f"/cdn-cgi/l/email-protection#{cf_encode('x@y.zz')}", "https://site.test/p"), "mailto:x@y.zz")
        self.assertIsNone(wc.resolve("/cdn-cgi/l/email-protection#nothex!!", "https://site.test/p") and None)
        p = hs.parse_html(f"<a href='/cdn-cgi/l/email-protection#{cf_encode('q@w.ee')}' data-cfemail='{cf_encode('q@w.ee')}'>[email&#160;protected]</a>")
        self.assertEqual(p.links[0]["text"], "q@w.ee")

    # ---------------------------------------------------------------- crawler traps
    def test_a_calendar_style_trap_is_capped(self):
        s, *_ = scan(self.base + "/cal?d=1", depth=50, max_pages=200)
        cal = [p for p in self.srv.hits if p == "/cal"]
        self.assertEqual(self.srv.hits["/cal"], 20)                           # the default of 20 distinct query strings, not 50
        self.assertEqual(s.frontier.skipped.get("too many parameter variants"), 1)
        self.srv.hits.clear()
        scan(self.base + "/cal?d=1", depth=50, max_pages=200, max_query_variants=0)
        self.assertEqual(self.srv.hits["/cal"], 26)                           # 0 turns the guard off: only the depth limit (25) stops it

    # ---------------------------------------------------------------- servers that push back
    def test_rate_limiting_slows_the_scan_and_is_called_by_its_name(self):
        self.srv.fail_first = 3                                               # every page answers 429 on its first 3 attempts
        s, ev, store, site, info = scan(self.base + "/rl", depth=1, concurrency=1)
        reasons = {e[4] for e in ev if e[0] == "broken"}
        self.assertEqual(reasons, {"rate limited (HTTP 429)"})
        self.assertGreaterEqual(s.summary["throttled"], 1)
        self.assertTrue(any("pushing back" in e[1] for e in ev if e[0] == "status"))
        self.assertGreater(s.pacer.penalty, 0)                                # and it stayed cautious

    def test_the_scan_speeds_up_again_when_the_server_recovers(self):
        p = fr.Pacer(fr.CrawlOptions(delay_min=0, delay_max=0))
        self.assertTrue(p.slow_down())
        self.assertEqual(p.penalty, 1.0)
        self.assertTrue(p.slow_down())
        self.assertEqual(p.penalty, 2.0)
        for _ in range(60):
            p.speed_up()
        self.assertEqual(p.penalty, 0.0)
        for _ in range(10):
            p.slow_down()
        self.assertEqual(p.penalty, 30.0)                                     # never more than 30 s
        self.assertFalse(p.slow_down())

    def test_a_site_that_refuses_the_crawler_gets_a_clear_hint(self):
        s, ev, store, site, info = scan(self.base + "/blocked", depth=1)
        self.assertTrue(s.summary["blocked"])
        self.assertTrue(any("refusing this crawler" in e[1] for e in ev if e[0] == "status"))
        self.assertEqual([e for e in ev if e[0] == "broken"], [])                   # forbidden pages are restricted, not broken
        self.assertEqual(site.stats()["restricted"], 3)

    def test_a_normal_site_is_not_called_blocking(self):
        s, *_ = scan(self.base + "/", depth=1)
        self.assertFalse(s.summary["blocked"])

    def test_basic_authentication_over_http_is_a_finding_of_its_own(self):
        s, ev, store, site, info = scan(self.base + "/basic", depth=0)
        found = {f.code: f for f, w in info.findings}
        self.assertEqual(found["restricted"].title, "Restricted page (HTTP 401, Basic authentication)")
        self.assertEqual(found["basic-auth-http"].severity, "high")
        self.assertFalse([e for e in ev if e[0] == "broken"])

    def test_reason_text(self):
        f = hs.Fetched("u", status=404)
        self.assertEqual(hs.reason_for(f), "not found (HTTP 404)")
        self.assertEqual(hs.reason_for(hs.Fetched("u", status=502)), "bad gateway (HTTP 502)")
        self.assertEqual(hs.reason_for(hs.Fetched("u", status=599)), "server error (HTTP 599)")
        self.assertEqual(hs.reason_for(hs.Fetched("u", status=418)), "error (HTTP 418)")
        self.assertEqual(hs.reason_for(hs.Fetched("u", error="timed out")), "timed out")

    # ---------------------------------------------------------------- big sitemaps
    def test_a_50000_url_sitemap_is_parsed_fast_and_capped(self):
        urls = "".join(f"<url><loc>https://e.com/s/{i}</loc></url>" for i in range(50000))
        data = f"<urlset>{urls}</urlset>".encode()
        t = time.time()
        pages, kids, err = ck.parse_sitemap(data)
        self.assertEqual((len(pages), err), (50000, ""))
        self.assertLess(time.time() - t, 3.0)
        seeds = ck.discover_seeds("https://e.com/", lambda u: (200, data) if u.endswith("sitemap.xml") else (404, b""))
        self.assertEqual(len(seeds.pages), 5000)                              # capped, in order
        f = fr.Frontier("https://e.com/", fr.CrawlOptions(depth=1, max_pages=100000))
        t = time.time()
        queued = sum(1 for p in seeds.pages if f.push(p, 1, None))
        self.assertEqual(queued, 5000)
        self.assertLess(time.time() - t, 2.0)

    def test_a_scan_with_a_big_sitemap_still_respects_max_pages(self):
        self.srv.big_sitemap = True
        s, ev, store, site, info = scan(self.base + "/s/0", depth=1, max_pages=12, use_sitemap=True)
        self.assertEqual(len(s.frontier.visited), 12)
        self.assertEqual(info.seeds["pages"], 5000)


class TlsReal(unittest.TestCase):
    def test_a_self_signed_site_can_be_crawled_with_verification_off(self):
        d = tempfile.mkdtemp()
        from test_checks import make_cert
        pair = make_cert(d)
        if not pair:
            self.skipTest("openssl is not available to make a test certificate")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*pair)
        srv = serve()
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        srv.base = f"https://localhost:{srv.server_address[1]}"
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close()))
        s, ev, *_ = scan(srv.base + "/", depth=0)
        broken = [e for e in ev if e[0] == "broken"]
        self.assertTrue(broken and "certificate verify failed" in broken[0][4], broken)
        s, ev, store, site, info = scan(srv.base + "/", depth=1, verify_tls=False, max_pages=5)
        self.assertGreaterEqual(len(s.frontier.visited), 2)
        self.assertTrue(any("not being verified" in e[1] for e in ev if e[0] == "status"))
        self.assertFalse([e for e in ev if e[0] == "broken" and "certificate" in e[4]])


if __name__ == "__main__":
    unittest.main()
