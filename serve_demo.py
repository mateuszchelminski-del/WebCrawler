"""Serve test-site/ on http://127.0.0.1:8000 as a deliberately imperfect site, so every feature has something to find.

    python serve_demo.py          the site as it is today
    python serve_demo.py --v2     the same site after a careless change: a new shortened link, an old jQuery, no CSP header
                                  (crawl "today", save the session, then crawl --v2 and compare to see the regressions)

What it has on purpose: weak headers and a version-disclosing Server header, a cookie without flags, an exposed .git/HEAD and
.env, a sitemap that lists a page nothing links to (orphan.html), a robots.txt that advertises /private/, and a members area
(/members) that needs the cookie  sid=demo  and the header  X-Token: demo  to see.  Only listens on localhost. Ctrl+C stops it.
"""
import functools
import http.server
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "test-site"
V2 = "--v2" in sys.argv
PORT = 8000


class Handler(http.server.SimpleHTTPRequestHandler):
    server_version = "Apache/2.4.49"  # a version-disclosing Server header, on purpose
    sys_version = ""

    def end_headers(self):
        self.send_header("X-Powered-By", "PHP/7.4.3")
        if not V2:
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
        self.send_header("Set-Cookie", "session=demo123; Path=/")
        super().end_headers()

    def _send(self, body: str, ctype: str = "text/plain", status: int = 200) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        base = f"http://127.0.0.1:{PORT}"
        if path == "/.git/HEAD":
            return self._send("ref: refs/heads/main\n")
        if path == "/.env":
            return self._send("APP_KEY=base64:demo\nDB_PASSWORD=hunter2\n")
        if path == "/sitemap.xml":
            urls = "".join(f"<url><loc>{base}/{p}</loc></url>" for p in ("index.html", "about.html", "orphan.html"))
            return self._send(f"<?xml version='1.0'?><urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>{urls}</urlset>", "application/xml")
        if path in ("/members", "/members/account"):
            if "sid=demo" not in self.headers.get("Cookie", "") or self.headers.get("X-Token") != "demo":
                return self._send("Please sign in.", status=403)
            body = "<title>Members</title><h1>Members</h1><a href='/members/account'>Account</a> <a href='/logout'>Log out</a>" if path == "/members" else "<title>Account</title><h1>Your account</h1>"
            return self._send(body, "text/html")
        if V2 and path in ("/", "/index.html"):
            html = (ROOT / "index.html").read_text(encoding="utf-8")
            extra = "<p><a href='https://bit.ly/3demo2'>New promotion</a></p><script src='/js/jquery-3.4.1.min.js'></script>"
            return self._send(html.replace("</body>", extra + "</body>"), "text/html")
        return super().do_GET()


if __name__ == "__main__":
    handler = functools.partial(Handler, directory=str(ROOT))
    with http.server.ThreadingHTTPServer(("127.0.0.1", PORT), handler) as srv:
        print(f"Demo site{' (v2: after a careless change)' if V2 else ''}: http://127.0.0.1:{PORT}/index.html   (Ctrl+C to stop)")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
