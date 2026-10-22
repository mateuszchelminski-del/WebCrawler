"""JavaScript-aware quick scan: which pages get rendered, what the renderer finds, and that it stays bounded and well behaved."""
import http.server
import json
import queue
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _net  # noqa: E402,F401  (a longer listen backlog for the local test servers)
from test_webcrawler import _have_browser  # noqa: E402

import auth  # noqa: E402
import checks as ck  # noqa: E402
import frontier as fr  # noqa: E402
import graph as gr  # noqa: E402
import httpscan as hs  # noqa: E402
import render  # noqa: E402
import webcrawler as wc  # noqa: E402


class Heuristics(unittest.TestCase):
    def check(self, html, mode="auto"):
        return render.needs_js(html, html.count("<a href"), mode)

    def test_pages_that_build_themselves_with_javascript(self):
        self.assertIn("application shell", self.check('<head><script src="/main.js"></script></head><body><div id="root"></div></body>'))
        self.assertIn("application shell", self.check('<body><div id="__next">\n</div><script src=x></script></body>'))
        self.assertIn("application shell", self.check('<body><div id="app"><!-- built by vue --></div></body>'))
        self.assertIn("framework root", self.check('<body><app-root></app-root><script src="a.js"></script></body>'))
        self.assertIn("asks for JavaScript", self.check('<body><noscript>You need to enable JavaScript to run this app.</noscript><script src="x.js"></script></body>'))
        self.assertIn("very little content", self.check('<body><h1>Loading</h1><script src="x.js"></script></body>'))

    def test_pages_the_server_already_rendered_are_left_alone(self):
        self.assertEqual(self.check("<body><h1>Hello</h1><p>World</p></body>"), "")                         # no scripts: nothing hidden
        self.assertEqual(self.check('<body><article>' + "word " * 400 + '</article><script src="a.js"></script></body>'), "")
        self.assertEqual(self.check("<body>" + "".join(f'<a href="/{i}">x</a>' for i in range(12)) + '<div id="root"></div><script></script></body>'), "")
        self.assertEqual(self.check('<body><div id="root"><p>' + "server rendered " * 50 + '</p></div></body>'), "")   # root with content in it

    def test_the_mode_overrides_the_judgement(self):
        spa = '<body><div id="root"></div></body>'
        self.assertEqual(self.check(spa, "never"), "")
        self.assertTrue(self.check("<p>static</p>", "always"))
        self.assertTrue(self.check(spa, "auto"))

    def test_text_length_ignores_scripts_styles_and_comments(self):
        self.assertEqual(render.visible_text_length("<style>p{}</style><script>var x=1;</script><!-- c --><p>Hello   world</p><noscript>no</noscript>"), 11)

    def test_options_are_clamped(self):
        o = fr.CrawlOptions(render="bogus", render_limit=-5).clamped()
        self.assertEqual((o.render, o.render_limit), ("auto", 0))


class Spa(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def page(self, body, status=200):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        srv, path = self.server, self.path.split("?")[0]
        srv.hits[path] = srv.hits.get(path, 0) + 1
        srv.seen.append((path, {k.lower(): v for k, v in self.headers.items()}))
        if path == "/":
            return self.page("<title>Home</title><a href='/spa'>spa</a>")
        if path == "/spa":
            return self.page("<title>SPA</title><div id='root'></div><script>document.getElementById('root').innerHTML = "
                             "'<a href=\"/spa/a\">A page</a><a href=\"/spa/b\">B page</a>';</script>")
        if path in ("/spa/a", "/spa/b"):
            return self.page(f"<title>{path}</title><p>a page</p>")
        if path == "/scroll":
            return self.page("<title>Scroll</title><div id='app'></div><script>"
                             "var n = 0, box = document.getElementById('app');"
                             "function more() { for (var i = 0; i < 5; i++) { n++; var a = document.createElement('a'); a.href = '/item/' + n; a.textContent = 'item ' + n; "
                             "box.appendChild(a); box.appendChild(document.createElement('br')); box.appendChild(document.createElement('div')).style.height = '400px'; } }"
                             "more(); window.addEventListener('scroll', function () { if (n < 25 && window.innerHeight + window.scrollY >= document.body.scrollHeight - 50) more(); });"
                             "</script>")
        if path.startswith("/item/"):
            return self.page(f"<p>{path}</p>")
        if path == "/lazy":
            return self.page("<title>Lazy</title><div id='root'></div><script>fetch('/api/links').then(function (r) { return r.json(); }).then(function (l) {"
                             "document.getElementById('root').innerHTML = l.map(function (u) { return '<a href=\"' + u + '\">' + u + '</a>'; }).join(''); });</script>")
        if path == "/api/links":
            data = json.dumps(["/lazy/1", "/lazy/2", "/lazy/3"]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/delayed":
            return self.page("<div id='root'></div><script>setTimeout(function () { document.getElementById('root').innerHTML = '<a href=\"/late/1\">late</a>'; }, 800);</script>")
        if path == "/ssr":
            return self.page("<title>Server rendered</title>" + "".join(f"<a href='/ssr/{i}'>s{i}</a>" for i in range(12)) + "<script src='/app.js'></script>")
        if path.startswith("/ssr/"):
            return self.page("<p>x</p>")
        if path == "/app.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/broken-js":
            return self.page("<div id='root'></div><script>throw new Error('boom');</script>")
        if path == "/members-spa":
            ok = "sid=ok" in self.headers.get("Cookie", "")
            return self.page("<div id='root'></div><script>fetch('/api/members').then(function (r) { return r.json(); }).then(function (l) {"
                             "document.getElementById('root').innerHTML = l.map(function (u) { return '<a href=\"' + u + '\">m</a>'; }).join(''); });</script>" if ok else "denied", 200 if ok else 403)
        if path == "/api/members":
            ok = self.headers.get("X-Token") == "t" and "sid=ok" in self.headers.get("Cookie", "")
            data = json.dumps(["/members/1", "/members/2"] if ok else []).encode()
            self.send_response(200 if ok else 403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/slow-spa":
            time.sleep(4)
            return self.page("<div id='root'></div><script>document.getElementById('root').innerHTML='<a href=\"/x\">x</a>'</script>")
        if path == "/insecure-spa":
            return self.page("<div id='root'></div><script>document.getElementById('root').innerHTML = "
                             "'<form action=\"/login\"><input type=\"password\"></form><img src=\"/pixel.png\"><script src=\"/jquery-3.4.1.min.js\"><\\/script>';</script>")
        if path == "/pixel.png":
            return self.page("png")
        return self.page("not found", 404)


def serve():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Spa)
    srv.hits, srv.seen = {}, []
    srv.base = f"http://127.0.0.1:{srv.server_address[1]}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def scan(start, wait=120, auth_cfg=None, stop_after=None, **kw):
    kw.setdefault("delay_min", 0)
    kw.setdefault("delay_max", 0)
    kw.setdefault("depth", 1)
    kw.setdefault("use_sitemap", False)
    kw.setdefault("check_tls", False)
    kw.setdefault("timeout", 10)
    opts = fr.CrawlOptions(**kw)
    ev, store, site, info, sec = queue.Queue(), wc.LinkStore(), gr.SiteGraph(), ck.SiteInfo(), {}
    s = hs.QuickScanner(start, opts, store, site, ev, sec, info, auth_cfg)
    s.start()
    if stop_after:
        time.sleep(stop_after)
        s.stop()
    s.join(wait)
    events = []
    while not ev.empty():
        events.append(ev.get())
    return s, events, store, site, info, sec


def hrefs(store, base):
    return {l.href.replace(base, "") for l in store.all()}


@unittest.skipUnless(_have_browser(), "Playwright with a browser is not available")
class Rendering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = serve()
        cls.base = cls.srv.base
        scan(cls.base + "/lazy", depth=0, render="always", wait=90)        # warm up: the first start of a browser on a cold CI machine can take very long

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.srv.hits.clear()
        self.srv.seen.clear()

    def test_links_built_by_javascript_are_found_only_when_rendering(self):
        s, ev, store, site, *_ = scan(self.base + "/spa", depth=1, render="never")
        self.assertEqual(hrefs(store, self.base), set())                       # the shell has no links of its own
        self.assertEqual(s.summary["rendered"], 0)
        self.assertIsNone(s.renderer)                                          # no browser was even started
        s, ev, store, site, *_ = scan(self.base + "/spa", depth=1, render="auto")
        self.assertEqual(hrefs(store, self.base), {"/spa/a", "/spa/b"})
        self.assertEqual(s.summary["rendered"], 1)
        self.assertTrue(site.nodes[fr.normalize(self.base + "/spa")].rendered)
        self.assertTrue({"/spa/a", "/spa/b"} <= {u.replace(self.base, "") for u in s.frontier.visited})   # and they were followed
        self.assertTrue(any("Rendering in a browser" in e[1] for e in ev if e[0] == "status"))
        self.assertIn("rendered in a browser", " ".join(e[1] for e in ev if e[0] == "status"))

    def test_infinite_scroll_is_scrolled(self):
        s, ev, store, *_ = scan(self.base + "/scroll", depth=0, render="auto")
        self.assertEqual({h for h in hrefs(store, self.base) if h.startswith("/item/")}, {f"/item/{i}" for i in range(1, 26)})

    def test_content_fetched_or_added_late_is_waited_for(self):
        s, ev, store, *_ = scan(self.base + "/lazy", depth=0, render="auto")
        self.assertEqual(hrefs(store, self.base), {"/lazy/1", "/lazy/2", "/lazy/3"}, [e[1] for e in ev if e[0] == "status"])
        s, ev, store, *_ = scan(self.base + "/delayed", depth=0, render="auto")
        self.assertEqual(hrefs(store, self.base), {"/late/1"})

    def test_a_page_the_server_rendered_is_not_sent_to_the_browser(self):
        s, ev, store, *_ = scan(self.base + "/ssr", depth=0, render="auto")
        self.assertEqual((s.summary["rendered"], s.renderer), (0, None))
        self.assertEqual(len(store.all()), 12)

    def test_always_renders_even_a_static_page(self):
        s, ev, store, *_ = scan(self.base + "/ssr", depth=0, render="always")
        self.assertEqual(s.summary["rendered"], 1)
        self.assertEqual(len(store.all()), 12)

    def test_the_render_budget_is_respected(self):
        s, ev, *_ = scan(self.base + "/spa", depth=2, render="always", render_limit=1, max_pages=4)
        self.assertEqual(s.summary["rendered"], 1)
        s, ev, *_ = scan(self.base + "/spa", depth=1, render="auto", render_limit=0)
        self.assertEqual(s.summary["rendered"], 0)

    def test_a_script_error_leaves_the_static_result(self):
        s, ev, store, site, *_ = scan(self.base + "/broken-js", depth=0, render="auto")
        self.assertEqual(hrefs(store, self.base), set())
        self.assertEqual(s.summary["pages"], 1)

    def test_what_the_page_becomes_is_analysed_too(self):
        s, ev, store, site, info, sec = scan(self.base + "/insecure-spa", depth=0, render="auto")
        codes = {f.code for f in sec[self.base + "/insecure-spa"].findings}
        self.assertIn("password-in-url", codes)                                # a form that only exists after the script ran
        self.assertIn(("jQuery", "3.4.1"), set(info.tech))

    def test_images_are_not_downloaded_while_rendering(self):
        scan(self.base + "/insecure-spa", depth=0, render="auto")
        self.assertNotIn("/pixel.png", self.srv.hits)

    def test_the_login_reaches_the_rendered_page(self):
        cfg = auth.AuthConfig.build(cookie="sid=ok", headers=["X-Token: t"], domain="127.0.0.1")
        s, ev, store, *_ = scan(self.base + "/members-spa", depth=0, render="auto", auth_cfg=cfg)
        self.assertEqual(hrefs(store, self.base), {"/members/1", "/members/2"})
        api = [h for p, h in self.srv.seen if p == "/api/members"][0]
        self.assertEqual(api.get("x-token"), "t")                              # headers go to the site's API calls
        self.assertIn("sid=ok", api.get("cookie", ""))
        s, ev, store, *_ = scan(self.base + "/members-spa", depth=0, render="auto")
        self.assertEqual(hrefs(store, self.base), set())                       # without it, nothing

    def test_no_browser_means_a_message_and_a_normal_scan(self):
        with mock.patch.object(wc, "_playwright_or_raise", side_effect=RuntimeError("Playwright is not installed. Run:  pip install -r requirements.txt")):
            s, ev, store, *_ = scan(self.base + "/spa", depth=1, render="auto")
        self.assertEqual(s.summary["rendered"], 0)
        self.assertEqual(s.summary["pages"], 1)
        self.assertTrue(any("rendering is unavailable" in e[1] for e in ev if e[0] == "status"))
        self.assertEqual(ev[-1][:2], ("auto", False))                          # the scan still finished cleanly

    def test_stopping_during_a_slow_render_returns_promptly_and_cleans_up(self):
        t = time.time()
        s, ev, *_ = scan(self.base + "/slow-spa", depth=0, render="always", stop_after=1.5, wait=40)
        self.assertFalse(s.is_alive())
        self.assertLess(time.time() - t, 30)
        time.sleep(0.5)
        self.assertFalse([th for th in threading.enumerate() if th.name == "renderer"])     # the browser thread is gone

    def test_a_page_that_cannot_be_rendered_falls_back_to_the_static_result(self):
        class Dead(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                n = self.server.n = getattr(self.server, "n", 0) + 1
                body = b"<div id='root'></div><script src='x.js'></script>"
                if n >= 2:                      # the plain fetch works; the browser's request is left hanging
                    time.sleep(6)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        d = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Dead)
        threading.Thread(target=d.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (d.shutdown(), d.server_close()))
        s, ev, store, *_ = scan(f"http://127.0.0.1:{d.server_address[1]}/", depth=0, render="auto", timeout=2, wait=60)
        self.assertEqual((s.summary["rendered"], s.summary["pages"]), (0, 1))


if __name__ == "__main__":
    unittest.main()
