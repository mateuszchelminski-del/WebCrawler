"""Quick-scanner features added for monitoring and real-world use: discovery, deeper checks, logins, resume."""
import http.server
import queue
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _net  # noqa: E402,F401  (a longer listen backlog for the local test servers)
import analysis as an  # noqa: E402
import auth  # noqa: E402
import checks as ck  # noqa: E402
import frontier as fr  # noqa: E402
import graph as gr  # noqa: E402
import httpscan as hs  # noqa: E402
import snapshot as sn  # noqa: E402
import webcrawler as wc  # noqa: E402


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a, **k):
        pass

    def send(self, body, status=200, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        srv, path = self.server, self.path.split("?")[0]
        srv.hits[path] = srv.hits.get(path, 0) + 1
        srv.seen.append((path, {k.lower(): v for k, v in self.headers.items()}))
        base = srv.base
        pages = {
            "/": f"<title>Home</title><a href='/a'>A</a><a href='/b'>B</a>",
            "/a": "<title>A</title>a" + srv.extra, "/b": "<title>B</title>b", "/hidden": "<title>Hidden</title>nobody links here",
            "/admin/": "admin area",
            "/page-html": ("<title>P</title><meta name='generator' content='WordPress 6.2'><script src='/js/jquery-3.4.1.min.js'></script>"
                           "<script src='https://cdn.thirdparty.test/lib.js'></script><form action='/login'><input type='password'></form>"),
            "/chain/0": "<a href='/chain/1'>1</a>",
            "/article": f"<title>Article</title><h1>News</h1><p>{srv.article}</p>{srv.extra}",
            "/inputs": ("<title>Inputs</title><form method='post' action='/login'><input name='user'><input type='password' name='pw'></form>"
                        "<form action='/search'><input name='q'></form><a href='/search?q=1&page=2'>s</a><a href='/item?id=7'>i</a>"),
        }
        for i in range(1, 7):
            pages[f"/chain/{i}"] = f"<a href='/chain/{i + 1}'>next</a>"
        if path == "/robots.txt":
            return self.send(f"User-agent: *\nDisallow: /admin/\nSitemap: {base}/sitemap.xml\n", ctype="text/plain")
        if path == "/sitemap.xml":
            return self.send(f"<urlset><url><loc>{base}/a</loc></url><url><loc>{base}/b</loc></url><url><loc>{base}/hidden</loc></url><url><loc>{base}/admin/</loc></url></urlset>", ctype="application/xml")
        if path == "/.git/HEAD":
            return self.send("ref: refs/heads/main\n", ctype="text/plain")
        if path == "/.env":
            return self.send("SECRET_KEY=abc\nDEBUG=1\n", ctype="text/plain")
        if path in ("/members", "/account"):
            ok = "sid=ok" in self.headers.get("Cookie", "") and self.headers.get("X-Token") == "t"
            if not ok:
                return self.send("denied", 403)
            return self.send("<title>Members</title><a href='/account'>Account</a><a href='/logout'>Log out</a>" if path == "/members" else "<title>Account</title>mine")
        if path == "/logout":
            return self.send("bye")
        if path == "/with-assets":
            return self.send("<title>Assets</title><link rel='stylesheet' href='/site.css'><img src='/pic.png' width=4 height=4><script src='/app.js'></script><p>page with assets</p>")
        if path == "/app.js":
            return self.send("fetch('/api/data').then(r => r.text()).then(t => { document.title = 'loaded ' + t; });", ctype="application/javascript")
        if path == "/site.css":
            return self.send("p { color: green }", ctype="text/css")
        if path == "/pic.png":
            return self.send(bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c6360000002000001e221bc330000000049454e44ae426082"), ctype="image/png")
        if path == "/api/data":
            return self.send('{"ok": true}', ctype="application/json")
        if path == "/leak":
            self.send_response(302)
            self.send_header("Location", srv.other_base + "/echo")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/echo":
            return self.send("echo")
        if path.startswith("/chain/"):
            time.sleep(0.25)
        if path in pages:
            return self.send(pages[path])
        return self.send("not found", 404)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


def serve():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.base = f"http://127.0.0.1:{srv.server_address[1]}"
    srv.hits, srv.seen, srv.other_base, srv.extra, srv.article = {}, [], "", "", "an article with some words in it"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run_scan(start, wait=60, auth_cfg=None, resume=None, stop_after=None, **kw):
    kw.setdefault("delay_min", 0)
    kw.setdefault("delay_max", 0)
    kw.setdefault("depth", 3)
    opts = fr.CrawlOptions(**kw)
    ev, store, site, info, sec = queue.Queue(), wc.LinkStore(), gr.SiteGraph(), ck.SiteInfo(), {}
    if resume and "restore" in resume:
        sn.restore(resume["restore"], store, site, sec, info)
        resume = resume["restore"]["resume"]
    s = hs.QuickScanner(start, opts, store, site, ev, sec, info, auth_cfg, resume)
    s.start()
    if stop_after:
        time.sleep(stop_after)
        s.stop()
    s.join(wait)
    events = []
    while not ev.empty():
        events.append(ev.get())
    return s, events, store, site, info, sec


class Quick(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.other = serve(), serve()
        cls.srv.other_base = cls.other.base
        cls.base = cls.srv.base

    @classmethod
    def tearDownClass(cls):
        for s in (cls.srv, cls.other):
            s.shutdown()
            s.server_close()

    def setUp(self):
        self.srv.hits.clear()
        self.srv.seen.clear()
        self.other.seen.clear()

    # ---------------------------------------------------------------- discovery
    def test_sitemap_seeds_find_pages_nothing_links_to(self):
        s, ev, store, site, info, sec = run_scan(self.base + "/")
        visited = {u.replace(self.base, "") for u in s.frontier.visited}
        self.assertIn("/hidden", visited)                              # only the sitemap knows about it
        self.assertNotIn("/admin/", visited)                           # robots.txt forbids it, even though the sitemap lists it
        self.assertEqual(site.orphans(), [fr.normalize(self.base + "/admin/"), fr.normalize(self.base + "/hidden")])   # listed, linked from nowhere
        codes = {(f.code, w) for f, w in info.findings}
        self.assertIn(("orphan-page", fr.normalize(self.base + "/hidden")), codes)
        self.assertNotIn(("orphan-page", fr.normalize(self.base + "/admin/")), codes)   # never fetched, so nothing to report
        self.assertIn("robots-sensitive", {c for c, _ in codes})       # robots.txt advertises /admin/
        self.assertEqual(info.seeds["pages"], 4)

    def test_sitemap_can_be_switched_off(self):
        s, *_ , info, _ = run_scan(self.base + "/", use_sitemap=False)
        self.assertNotIn(fr.normalize(self.base + "/hidden"), s.frontier.visited)
        self.assertNotIn("/sitemap.xml", self.srv.hits)
        self.assertEqual(info.seeds, {})

    def test_probing_is_opt_in(self):
        run_scan(self.base + "/", depth=0)
        self.assertNotIn("/.git/HEAD", self.srv.hits)
        self.assertNotIn("/.env", self.srv.hits)
        *_, info, _ = run_scan(self.base + "/", depth=0, probe_files=True)
        exposed = {f["path"] for f in info.files if f["exposed"]}
        self.assertTrue({"/.git/HEAD", "/.env", "/robots.txt", "/sitemap.xml"} <= exposed)
        sev = {(f.code, f.severity) for f, _ in info.findings}
        self.assertIn(("exposed-file", "high"), sev)
        self.assertIn(("no-security-txt", "info"), sev)

    def test_tls_is_only_checked_for_https_starts(self):
        *_, info, _ = run_scan(self.base + "/", depth=0)
        self.assertEqual(info.tls, {})

    # ---------------------------------------------------------------- deeper checks
    def test_markup_findings_and_technologies(self):
        s, ev, store, site, info, sec = run_scan(self.base + "/page-html", depth=0, use_sitemap=False)
        page = sec[self.base + "/page-html"]
        codes = {f.code for f in page.findings}
        self.assertTrue({"no-sri-script", "password-in-url", "no-csp"} <= codes, codes)   # markup findings sit next to header findings
        tech = {k for k in info.tech}
        self.assertTrue({("WordPress", "6.2"), ("jQuery", "3.4.1")} <= tech)
        self.assertIn("old-jquery", {f.code for f, _ in info.findings})

    # ---------------------------------------------------------------- logins
    def cfg(self):
        return auth.AuthConfig.build(cookie="sid=ok", headers=["X-Token: t"], domain="127.0.0.1")

    def test_protected_pages_need_the_login(self):
        s, ev, store, site, info, sec = run_scan(self.base + "/members", use_sitemap=False)
        self.assertFalse(any(e[0] == "broken" for e in ev))                 # asking for a login is not a broken link...
        self.assertIn(("restricted", fr.normalize(self.base + "/members")), {(f.code, w) for f, w in info.findings})   # ...it is part of the attack surface
        self.assertEqual(site.stats()["restricted"], 1)
        self.assertEqual(site.stats()["broken"], 0)
        s, ev, store, site, info, sec = run_scan(self.base + "/members", auth_cfg=self.cfg(), use_sitemap=False)
        visited = {u.replace(self.base, "") for u in s.frontier.visited}
        self.assertEqual(visited, {"/members", "/account"})
        self.assertEqual(site.nodes[fr.normalize(self.base + "/members")].status, 200)

    def test_logout_link_is_never_followed_with_a_login(self):
        run_scan(self.base + "/members", auth_cfg=self.cfg(), use_sitemap=False)
        self.assertNotIn("/logout", self.srv.hits)

    def test_credentials_are_not_sent_to_another_host_after_a_redirect(self):
        s, *_ = run_scan(self.base + "/leak", auth_cfg=self.cfg(), depth=0, use_sitemap=False)
        first = [h for p, h in self.srv.seen if p == "/leak"][0]
        self.assertEqual((first.get("cookie"), first.get("x-token")), ("sid=ok", "t"))   # the crawled site got them
        hops = [h for p, h in self.other.seen if p == "/echo"]
        self.assertTrue(hops, "the redirect was not followed")
        for h in hops:
            self.assertFalse({"cookie", "x-token", "authorization"} & set(h), "credentials leaked to another host")

    def test_login_status_message_does_not_contain_secrets(self):
        s, ev, *_ = run_scan(self.base + "/members", auth_cfg=self.cfg(), use_sitemap=False)
        text = " ".join(str(e) for e in ev)
        self.assertIn("Using your login", text)
        self.assertNotIn("sid=ok", text)

    # ---------------------------------------------------------------- save and resume
    def test_resume_continues_where_it_stopped_without_refetching(self):
        s1, ev1, store1, site1, info1, sec1 = run_scan(self.base + "/chain/0", use_sitemap=False, depth=10, delay_min=0.1, delay_max=0.1, concurrency=1, stop_after=1.0)
        self.assertTrue(s1.summary["stopped"])
        self.assertTrue(s1.summary["resumable"])
        done_first = {u for u in s1.frontier.visited}
        self.assertTrue(0 < len(done_first) < 8)
        first_hits = dict(self.srv.hits)
        data = sn.build(self.base + "/chain/0", s1.opts, store1, site1, sec1, [], info1, s1.resume_state)
        path = str(Path(tempfile.mkdtemp()) / "s.json")
        sn.save(path, data)                                           # through a real file, as the app does
        s2, ev2, *_ = run_scan(self.base + "/chain/0", use_sitemap=False, depth=10, resume={"restore": sn.load(path)})
        self.assertFalse(s2.summary["resumable"])
        self.assertEqual(len(s2.frontier.visited), 8)   # /chain/0 .. /chain/6, plus /chain/7 which is a 404
        for page, n in self.srv.hits.items():
            if page.startswith("/chain/"):
                self.assertEqual(n, 1, f"{page} was fetched {n} times")  # nothing visited before the stop was fetched again
        self.assertTrue(set(first_hits) <= set(self.srv.hits))

    def test_resume_can_go_deeper_than_the_first_run(self):
        s1, *_ , info1, sec1 = run_scan(self.base + "/chain/0", use_sitemap=False, depth=2, delay_min=0, delay_max=0)
        self.assertEqual(len(s1.frontier.visited), 3)                  # /chain/0..2
        self.assertTrue(s1.frontier.deferred)                          # /chain/3 was one hop too deep
        state = s1.frontier.to_state()
        s2 = hs.QuickScanner(self.base + "/chain/0", fr.CrawlOptions(depth=5, delay_min=0, delay_max=0), s1.store, s1.graph, queue.Queue(), {}, ck.SiteInfo(), None, state)
        s2.start()
        s2.join(30)
        self.assertEqual(len(s2.frontier.visited), 6)                  # /chain/0..5


class InputsAndHosts(unittest.TestCase):
    """Forms, URL parameters and related host names are collected as pages are scanned. Related hosts need real-looking names,
    so these pages are served by a stand-in for the fetcher instead of the local server."""
    PAGE = ("<title>Shop</title><a href='/search?q=x&page=2'>s</a><a href='https://api.example.com/v1?key=1'>api</a><a href='https://old.example.com/'>old</a>"
            "<a href='https://other.org/?z=1'>other</a><form method='post' action='/login'><input name='user'><input type='password' name='pw'></form>")

    def scan(self, resolved):
        def fake(self_, url):
            return hs.Fetched(url, url, 200, [("Content-Type", "text/html"), ("Content-Security-Policy", "default-src 'self' https://cdn.example.com; img-src https://evil.net")],
                              body=InputsAndHosts.PAGE, html=True)
        with mock.patch.object(hs.QuickScanner, "_fetch_paced", fake), mock.patch.object(ck, "resolve_hosts", return_value=resolved):
            return run_scan("https://www.example.com/", depth=0, use_sitemap=False, check_tls=False, ignore_robots=True)

    def test_everything_the_page_reveals_is_inventoried(self):
        *_, info, _ = self.scan({"api.example.com": ["203.0.113.5"], "old.example.com": [], "cdn.example.com": ["203.0.113.6"], "www.example.com": ["203.0.113.7"]})
        (form,) = info.forms.values()
        self.assertEqual((form["action"], form["method"], form["password"], form["csrf"]), ("https://www.example.com/login", "post", True, False))
        self.assertEqual(set(info.params), {"q", "page", "key", "z"})
        self.assertEqual(set(info.hosts), {"www.example.com", "api.example.com", "old.example.com", "cdn.example.com"})     # other.org and evil.net are not this site's
        self.assertEqual(info.hosts["cdn.example.com"]["sources"], ["csp"])
        self.assertEqual(info.hosts["api.example.com"]["addresses"], ["203.0.113.5"])
        self.assertIn(("host-unresolved", "old.example.com"), [(f.code, w) for f, w in info.findings])

    def test_host_lookups_can_be_switched_off(self):
        def fake(self_, url):
            return hs.Fetched(url, url, 200, [("Content-Type", "text/html")], body=InputsAndHosts.PAGE, html=True)
        with mock.patch.object(hs.QuickScanner, "_fetch_paced", fake), mock.patch.object(ck, "resolve_hosts") as lookup:
            *_, info, _ = run_scan("https://www.example.com/", depth=0, use_sitemap=False, check_tls=False, ignore_robots=True, resolve_hosts=False)
        lookup.assert_not_called()
        self.assertIn("api.example.com", info.hosts)                            # still noted, just not looked up
        self.assertIsNone(info.hosts["api.example.com"]["addresses"])


if __name__ == "__main__":
    unittest.main()
