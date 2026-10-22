"""The HTTP client against a local keep-alive server that misbehaves in the ways real servers do."""
import gzip
import http.server
import json
import os
import socketserver
import ssl
import sys
import tempfile
import threading
import time
import unittest
import zlib
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _net  # noqa: E402,F401  (a longer listen backlog for the local test servers)
import httpclient as hc  # noqa: E402


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"       # keep-alive, like a real server

    def log_message(self, *a, **k):
        pass

    def send_body(self, body, status=200, ctype="text/html; charset=utf-8", headers=None, chunked=False):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(0, len(data), 7):
                piece = data[i:i + 7]
                self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

    def redirect(self, location, status=302):
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        srv = self.server
        path, _, query = self.path.partition("?")
        srv.log.append((path, query, {k.lower(): v for k, v in self.headers.items()}, self.client_address[1]))
        n = srv.counts[path] = srv.counts.get(path, 0) + 1
        if path == "/ok":
            return self.send_body("hello")
        if path == "/gzip":
            return self.send_body(gzip.compress(b"<a href='/x'>gzip page</a>" * 50), headers={"Content-Encoding": "gzip"})
        if path == "/deflate":
            return self.send_body(zlib.compress(b"deflate page" * 20), headers={"Content-Encoding": "deflate"})
        if path == "/rawdeflate":
            c = zlib.compressobj(wbits=-15)
            return self.send_body(c.compress(b"raw deflate page" * 20) + c.flush(), headers={"Content-Encoding": "deflate"})
        if path == "/chunked":
            return self.send_body("chunked body " * 30, chunked=True)
        if path == "/gzip-chunked":
            return self.send_body(gzip.compress(b"gzip and chunked " * 100), headers={"Content-Encoding": "gzip"}, chunked=True)
        if path == "/bomb":                                      # 60 MB of zeros in ~60 KB
            return self.send_body(gzip.compress(b"\0" * (60 * 1024 * 1024)), headers={"Content-Encoding": "gzip"})
        if path == "/big":
            return self.send_body(b"x" * (5 * 1024 * 1024), ctype="text/html")
        if path == "/slow":                                      # trickles one byte at a time for far too long
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", "100")
            self.end_headers()
            try:
                for _ in range(100):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.2)
            except OSError:
                pass
            return
        if path == "/hang":                                      # accepts the request and never answers
            time.sleep(5)
            return
        if path == "/redir-abs":
            return self.redirect(f"http://127.0.0.1:{srv.server_address[1]}/ok", 301)
        if path == "/redir-rel":
            return self.redirect("ok?x=1", 302)
        if path == "/redir-308":
            return self.redirect("/ok", 308)
        if path == "/redir-303":
            return self.redirect("/ok", 303)
        if path == "/loop-a":
            return self.redirect("/loop-b")
        if path == "/loop-b":
            return self.redirect("/loop-a")
        if path.startswith("/chain/"):
            k = int(path.rsplit("/", 1)[1])
            return self.redirect(f"/chain/{k + 1}") if k < 30 else self.send_body("end")
        if path == "/redir-cross":
            return self.redirect(srv.other + "/echo")
        if path == "/redir-file":
            return self.redirect("file:///etc/passwd")
        if path == "/redir-js":
            return self.redirect("javascript:alert(1)")
        if path == "/redir-nolocation":
            self.send_response(302)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/echo":
            return self.send_body(json.dumps({k.lower(): v for k, v in self.headers.items()}), ctype="application/json")
        if path == "/retry-num":
            return self.send_body("slow down", 429, headers={"Retry-After": "0"}) if n == 1 else self.send_body("ok now")
        if path == "/retry-date":
            when = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() + 3))
            return self.send_body("busy", 503, headers={"Retry-After": when}) if n == 1 else self.send_body("ok now")
        if path == "/always-429":
            return self.send_body("no", 429, headers={"Retry-After": "20"})
        if path == "/stale":                                     # answers, then silently drops the connection while saying keep-alive
            self.send_body("fresh")
            self.close_connection = True
            return
        if path == "/204":
            self.send_response(204)
            self.end_headers()
            return
        if path == "/304":
            self.send_response(304)
            self.end_headers()
            return
        if path == "/latin1":
            return self.send_body("café crème".encode("latin-1"), ctype="text/html; charset=iso-8859-1")
        if path == "/meta-charset":
            return self.send_body(b"<meta charset='windows-1252'><p>na\xefve \x93quoted\x94</p>", ctype="text/html")
        if path == "/bad-utf8":
            return self.send_body(b"<p>caf\xe9</p>", ctype="text/html")
        if path == "/bom":
            return self.send_body(b"\xef\xbb\xbf<p>bom</p>", ctype="text/html")
        if path == "/cookies":
            self.send_response(200)
            self.send_header("Set-Cookie", "a=1; Path=/")
            self.send_header("Set-Cookie", "b=2; Path=/; Secure")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if path == "/json-small":
            return self.send_body('{"a": 1}', ctype="application/json")
        if path == "/json-big":
            return self.send_body(b"x" * (1024 * 1024), ctype="application/json")
        if path == "/close-delimited":                           # no Content-Length: the body ends when the connection does
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"until the end")
            self.close_connection = True
            return
        if path == "/huge-header":
            self.send_response(200)
            self.send_header("X-Big", "a" * 70000)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path.startswith("/path"):
            return self.send_body(self.path, ctype="text/plain")
        return self.send_body("not found", 404)


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(other=""):
    srv = Server(("127.0.0.1", 0), Handler)
    srv.log, srv.counts, srv.other = [], {}, other
    srv.base = f"http://127.0.0.1:{srv.server_address[1]}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.other = serve()
        cls.srv = serve(cls.other.base)
        cls.base = cls.srv.base

    @classmethod
    def tearDownClass(cls):
        for s in (cls.srv, cls.other):
            s.shutdown()
            s.server_close()

    def setUp(self):
        self.srv.log.clear()
        self.srv.counts.clear()
        self.other.log.clear()
        self.c = hc.Client("WebCrawler/test", timeout=5)
        self.addCleanup(self.c.close)

    # ------------------------------------------------------------------ connections
    def test_one_connection_serves_many_requests(self):
        for _ in range(6):
            self.assertEqual(self.c.get(self.base + "/ok").body, b"hello")
        self.assertEqual((self.c.pool.created, self.c.pool.reused), (1, 5))
        self.assertEqual(len({port for _, _, _, port in self.srv.log}), 1)    # the server saw a single client connection

    def test_parallel_use_needs_at_most_as_many_connections_as_threads(self):
        errs = []

        def work():
            for _ in range(8):
                r = self.c.get(self.base + "/ok")
                if r.body != b"hello":
                    errs.append(r.error)
        ts = [threading.Thread(target=work) for _ in range(4)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errs, [])
        self.assertLessEqual(self.c.pool.created, 4)
        self.assertEqual(self.c.requests, 32)

    def test_a_stale_pooled_connection_is_retried_on_a_new_one(self):
        self.assertEqual(self.c.get(self.base + "/stale").body, b"fresh")     # the server drops the connection after this
        time.sleep(0.2)
        r = self.c.get(self.base + "/ok")
        self.assertEqual((r.status, r.body, r.error), (200, b"hello", ""))
        self.assertFalse(r.reused)                                            # the retry had to use a fresh connection

    def test_connection_close_and_close_delimited_bodies(self):
        r = self.c.get(self.base + "/close-delimited")
        self.assertEqual((r.status, r.body), (200, b"until the end"))
        self.assertEqual(self.c.get(self.base + "/ok").body, b"hello")
        self.assertEqual(self.c.pool.created, 2)                              # a Connection: close response is never reused

    def test_head_204_and_304_have_no_body_and_keep_the_connection(self):
        self.assertEqual((self.c.head(self.base + "/ok").status, self.c.head(self.base + "/ok").body), (200, b""))
        self.assertEqual(self.c.get(self.base + "/204").status, 204)
        self.assertEqual(self.c.get(self.base + "/304").status, 304)
        self.assertEqual(self.c.get(self.base + "/ok").body, b"hello")
        self.assertEqual(self.c.pool.created, 1)

    def test_a_body_that_is_not_wanted_is_skipped_and_big_ones_close_the_connection(self):
        r = self.c.get(self.base + "/json-small", read_body="html")
        self.assertEqual((r.status, r.body), (200, b""))
        self.assertEqual(self.c.get(self.base + "/ok").body, b"hello")
        self.assertEqual(self.c.pool.created, 1)                              # small body drained: connection reused
        self.c.get(self.base + "/json-big", read_body="html")
        self.c.get(self.base + "/ok")
        self.assertEqual(self.c.pool.created, 2)                              # big body not drained: connection dropped
        self.assertEqual(self.c.get(self.base + "/ok", read_body="html").body, b"hello")   # html-ish content types are read

    # ------------------------------------------------------------------ compression and size limits
    def test_it_asks_for_compression_and_decodes_it(self):
        self.c.get(self.base + "/echo")
        self.assertEqual(self.srv.log[-1][2]["accept-encoding"], "gzip, deflate")
        self.assertEqual(self.srv.log[-1][2]["user-agent"], "WebCrawler/test")
        r = self.c.get(self.base + "/gzip")
        self.assertEqual((r.encoding, r.body), ("gzip", b"<a href='/x'>gzip page</a>" * 50))
        self.assertLess(r.wire_bytes, len(r.body))
        self.assertEqual(self.c.get(self.base + "/deflate").body, b"deflate page" * 20)
        self.assertEqual(self.c.get(self.base + "/rawdeflate").body, b"raw deflate page" * 20)

    def test_chunked_transfer_and_chunked_gzip(self):
        self.assertEqual(self.c.get(self.base + "/chunked").body, b"chunked body " * 30)
        self.assertEqual(self.c.get(self.base + "/gzip-chunked").body, b"gzip and chunked " * 100)

    def test_a_compression_bomb_is_cut_off_not_expanded(self):
        r = self.c.get(self.base + "/bomb", max_body=1024 * 1024)
        self.assertTrue(r.truncated)
        self.assertEqual(len(r.body), 1024 * 1024)                            # 60 MB of zeros became 1 MB, not 60
        self.assertLess(r.wire_bytes, 200 * 1024)

    def test_an_oversized_plain_body_is_truncated(self):
        r = self.c.get(self.base + "/big", max_body=100000)
        self.assertEqual((r.truncated, len(r.body)), (True, 100000))
        self.assertEqual(self.c.get(self.base + "/ok").body, b"hello")        # and the client carries on normally afterwards

    def test_zero_limit_never_means_unlimited(self):
        d = hc._Decoder("gzip")
        self.assertEqual(d.feed(gzip.compress(b"a" * 100), 0), (b"", True))

    def test_unsupported_encoding_keeps_status_and_headers(self):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Encoding", "br")
                self.send_header("X-Test", "kept")
                self.send_header("Content-Length", "3")
                self.end_headers()
                self.wfile.write(b"abc")
        s = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (s.shutdown(), s.server_close()))
        r = self.c.get(f"http://127.0.0.1:{s.server_address[1]}/")
        self.assertEqual((r.status, r.header("x-test")), (200, "kept"))
        self.assertIn("unsupported content encoding", r.error)

    # ------------------------------------------------------------------ time limits
    def test_a_response_that_trickles_in_hits_the_overall_deadline(self):
        c = hc.Client("t", timeout=2, total_timeout=1.5)
        self.addCleanup(c.close)
        t = time.time()
        r = c.get(self.base + "/slow")
        self.assertIn("timed out", r.error)
        self.assertLess(time.time() - t, 4)                                   # each byte arrives within the 2 s read timeout, yet it gives up

    def test_a_server_that_never_answers_times_out(self):
        c = hc.Client("t", timeout=1)
        self.addCleanup(c.close)
        t = time.time()
        r = c.get(self.base + "/hang")
        self.assertEqual((r.status, r.error), (0, "timed out"))
        self.assertLess(time.time() - t, 3)

    def test_connection_refused_and_bad_urls_do_not_raise(self):
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        r = self.c.get(f"http://127.0.0.1:{port}/")
        self.assertEqual(r.status, 0)
        self.assertTrue(r.error)
        for bad in ("not a url", "http://", "ftp://example.com/x", "", "http://exa mple.com/"):
            r = self.c.get(bad)
            self.assertEqual(r.status, 0, bad)
            self.assertTrue(r.error, bad)

    def test_an_absurd_header_is_an_error_not_a_crash(self):
        r = self.c.get(self.base + "/huge-header")
        self.assertEqual(r.status, 0)
        self.assertTrue(r.error)

    # ------------------------------------------------------------------ redirects
    def test_redirect_flavours(self):
        for path in ("/redir-abs", "/redir-rel", "/redir-308", "/redir-303"):
            r = self.c.get(self.base + path)
            self.assertEqual((r.status, r.body, r.final_url.startswith(self.base + "/ok")), (200, b"hello", True), path)
            self.assertEqual(len(r.chain), 1, path)
        self.assertEqual([s for _, s in self.c.get(self.base + "/redir-308").chain], [308])

    def test_loops_hop_limits_and_bad_locations(self):
        r = self.c.get(self.base + "/loop-a")
        self.assertEqual(r.error, "redirect loop")
        r = self.c.get(self.base + "/chain/0")
        self.assertEqual(r.error, "too many redirects")
        self.assertEqual(len(r.chain), 11)
        self.assertEqual(self.c.get(self.base + "/chain/15", max_redirects=10).error, "too many redirects")   # 15 hops to go
        self.assertEqual(self.c.get(self.base + "/chain/22", max_redirects=10).body, b"end")               # 8 hops to go
        for path in ("/redir-file", "/redir-js"):
            self.assertIn("unsupported", self.c.get(self.base + path).error, path)
        r = self.c.get(self.base + "/redir-nolocation")
        self.assertEqual((r.status, r.error), (302, ""))

    def test_follow_false_returns_the_redirect_itself(self):
        r = self.c.get(self.base + "/redir-abs", follow=False)
        self.assertEqual((r.status, r.chain, r.header("Location").endswith("/ok")), (301, [], True))

    def test_secret_headers_are_dropped_when_a_redirect_leaves_the_host(self):
        hdrs = {"Authorization": "Bearer s3cr3t", "X-Token": "t", "X-Plain": "ok"}
        r = self.c.get(self.base + "/redir-cross", hdrs, secret_headers=["authorization", "X-Token"])
        seen = json.loads(r.body)
        self.assertEqual(r.final_url, self.other.base + "/echo")
        self.assertNotIn("authorization", seen)
        self.assertNotIn("x-token", seen)
        self.assertEqual(seen["x-plain"], "ok")                               # only the secret ones are removed
        sent = [h for p, q, h, _ in self.srv.log if p == "/redir-cross"][0]
        self.assertEqual((sent["authorization"], sent["x-token"]), ("Bearer s3cr3t", "t"))   # the first host did get them

    def test_secret_headers_survive_a_redirect_within_the_host(self):
        r = self.c.get(self.base + "/redir-rel", {"Authorization": "Bearer s3cr3t"}, secret_headers=["authorization"])
        self.assertEqual(r.status, 200)
        self.assertEqual([h.get("authorization") for p, q, h, _ in self.srv.log if p == "/ok"], ["Bearer s3cr3t"])

    # ------------------------------------------------------------------ retry-after
    def test_429_with_numeric_retry_after_is_retried(self):
        r = self.c.get(self.base + "/retry-num")
        self.assertEqual((r.status, r.body, r.retries), (200, b"ok now", 1))

    def test_503_with_an_http_date_retry_after_is_retried(self):
        t = time.time()
        r = self.c.get(self.base + "/retry-date")
        self.assertEqual((r.status, r.retries), (200, 1))
        self.assertGreaterEqual(time.time() - t, 1.5)                         # it waited for the date (3 s away, whole-second precision)

    def test_giving_up_is_reported_and_stop_ends_the_wait(self):
        stop = threading.Event()
        threading.Timer(0.4, stop.set).start()
        t = time.time()
        r = self.c.get(self.base + "/always-429", stop=stop)
        self.assertEqual(r.status, 429)
        self.assertLess(time.time() - t, 3)                                   # Retry-After said 20 s; stop cut it short
        r = self.c.get(self.base + "/always-429", retries=0)
        self.assertEqual((r.status, r.retries), (429, 0))

    def test_retry_after_parsing(self):
        self.assertEqual(hc.parse_retry_after("7"), 7.0)
        self.assertEqual(hc.parse_retry_after("500"), 30.0)                   # capped
        self.assertEqual(hc.parse_retry_after("soon", default=3.0), 3.0)
        self.assertEqual(hc.parse_retry_after("", default=2.0), 2.0)
        when = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() + 10))
        self.assertTrue(8 <= hc.parse_retry_after(when) <= 10.5)
        past = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() - 100))
        self.assertEqual(hc.parse_retry_after(past), 0.0)

    # ------------------------------------------------------------------ text, headers, URLs
    def test_text_decoding(self):
        self.assertEqual(hc.decode_text(self.c.get(self.base + "/latin1").body, "text/html; charset=iso-8859-1"), "café crème")
        r = self.c.get(self.base + "/meta-charset")
        self.assertIn("naïve “quoted”", hc.decode_text(r.body, r.header("Content-Type")))     # from <meta charset>
        self.assertEqual(hc.decode_text(self.c.get(self.base + "/bad-utf8").body, "text/html"), "<p>café</p>")   # invalid UTF-8 falls back
        self.assertEqual(hc.decode_text(self.c.get(self.base + "/bom").body), "<p>bom</p>")
        self.assertEqual(hc.decode_text(b"", "text/html"), "")
        self.assertEqual(hc.decode_text(b"ok", "text/html; charset=no-such-charset"), "ok")

    def test_duplicate_headers_are_kept(self):
        r = self.c.get(self.base + "/cookies")
        self.assertEqual(r.headers_all("set-cookie"), ["a=1; Path=/", "b=2; Path=/; Secure"])
        self.assertEqual(r.header("SET-COOKIE"), "a=1; Path=/")

    def test_unusual_characters_in_urls_are_encoded(self):
        r = self.c.get(self.base + "/path/café bar?q=é&x=a b")
        self.assertEqual(r.body.decode(), "/path/caf%C3%A9%20bar?q=%C3%A9&x=a%20b")
        r = self.c.get(self.base + "/path/already%20encoded%2Fslash#fragment")
        self.assertEqual(r.body.decode(), "/path/already%20encoded%2Fslash")     # existing escapes untouched, fragment never sent

    def test_custom_headers_override_defaults(self):
        self.c.get(self.base + "/echo", {"User-Agent": "Custom/1", "X-Extra": "1"})
        h = self.srv.log[-1][2]
        self.assertEqual((h["user-agent"], h["x-extra"]), ("Custom/1", "1"))

    def test_accept_encoding_can_be_switched_off(self):
        c = hc.Client("t", timeout=5, accept_encoding=False)
        self.addCleanup(c.close)
        c.get(self.base + "/echo")
        self.assertEqual(self.srv.log[-1][2]["accept-encoding"], "identity")   # http.client says so explicitly: no compression asked for

    # ------------------------------------------------------------------ proxy
    def test_http_proxy_gets_an_absolute_request_target(self):
        seen = []

        class Proxy(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                seen.append((self.path, self.headers.get("Proxy-Authorization"), self.headers.get("Host")))
                body = b"via proxy"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        p = http.server.HTTPServer(("127.0.0.1", 0), Proxy)
        threading.Thread(target=p.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (p.shutdown(), p.server_close()))
        env = {"http_proxy": f"http://user:pw@127.0.0.1:{p.server_address[1]}", "no_proxy": "", "NO_PROXY": ""}
        with mock.patch.dict(os.environ, env):
            r = hc.Client("t", timeout=5).get("http://example.test:8080/page?x=1")
            self.assertEqual((r.status, r.body), (200, b"via proxy"))
            self.assertEqual(seen[0][0], "http://example.test:8080/page?x=1")
            self.assertTrue(seen[0][1].startswith("Basic "))
            self.assertEqual(seen[0][2], "example.test:8080")
            seen.clear()
            r = hc.Client("t", timeout=5, use_proxy=False).get("http://127.0.0.1:1/")      # opting out ignores the proxy
            self.assertEqual(seen, [])
        with mock.patch.dict(os.environ, {**env, "no_proxy": "example.test", "NO_PROXY": "example.test"}):
            hc.Client("t", timeout=2).get("http://example.test:8080/x")                    # NO_PROXY is honoured
            self.assertEqual(seen, [])


class TlsTests(unittest.TestCase):
    def test_certificate_errors_are_reported_and_can_be_overridden(self):
        from test_checks import make_cert
        d = tempfile.mkdtemp()
        pair = make_cert(d)
        if not pair:
            self.skipTest("openssl is not available to make a test certificate")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*pair)

        class H(Handler):
            pass
        srv = Server(("127.0.0.1", 0), H)
        srv.log, srv.counts, srv.other = [], {}, ""
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close()))
        url = f"https://localhost:{srv.server_address[1]}/ok"
        r = hc.Client("t", timeout=5).get(url)
        self.assertEqual(r.status, 0)
        self.assertTrue(r.tls_error)
        self.assertIn("certificate verify failed", r.error)
        c = hc.Client("t", timeout=5, verify_tls=False)
        self.addCleanup(c.close)
        r = c.get(url)
        self.assertEqual((r.status, r.body, r.error), (200, b"hello", ""))
        self.assertEqual(c.get(url).reused, True)                                   # keep-alive works over TLS too


if __name__ == "__main__":
    unittest.main()
