"""httpclient.py: the small HTTP client the quick scanner is built on.

Why not urllib: a crawler makes thousands of requests to the same few hosts, and urllib opens a new connection (and a new TLS
handshake) for every one, never asks for compressed responses, cannot be told to give up on a response that trickles in, and
follows redirects with no way to stop credentials travelling to another site. This client:

  * keeps connections alive and pools them per origin, retrying once on a fresh connection if a reused one turns out to be stale
  * asks for gzip/deflate and decodes it (and decodes it when a server compresses anyway), with a hard cap on the decoded size,
    so a "compression bomb" cannot exhaust memory
  * enforces an overall deadline per request, not just a per-read timeout
  * follows redirects itself: relative and absolute Location, 308, loops, a hop limit, and secret headers dropped when the
    redirect leaves the host
  * honours Retry-After (seconds or a date) on 429/503
  * goes through an HTTP(S) proxy from the usual environment variables, with CONNECT tunnelling for https
  * never raises: every failure comes back in Response.error with status 0

It uses only the standard library.
"""
from __future__ import annotations

import base64
import email.utils
import http.client
import re
import socket
import ssl
import threading
import time
import urllib.request
import zlib
from dataclasses import dataclass, field
from urllib.parse import quote, unquote, urljoin, urlsplit

REDIRECTS = (301, 302, 303, 307, 308)
SAFE_PATH = "/%:@!$&'()*+,;=~-._"
SAFE_QUERY = "/%:@!$&'()*+,;=~-._?[]"
DRAIN_LIMIT = 128 * 1024          # a body we do not want is still read if it is this small, so the connection can be reused


@dataclass
class Response:
    url: str                                   # what was asked for
    final_url: str = ""                        # where the redirects ended
    status: int = 0                            # 0 = no HTTP answer (see error)
    reason: str = ""
    headers: list = field(default_factory=list)   # [(name, value)], in order, duplicates kept (several Set-Cookie lines)
    body: bytes = b""
    chain: list = field(default_factory=list)  # [(url, status)] for each redirect hop before the final answer
    error: str = ""
    tls_error: bool = False                    # the failure was a certificate problem
    elapsed: float = 0.0
    truncated: bool = False                    # the body was cut at the size limit
    reused: bool = False                       # the connection had been used before
    encoding: str = ""                         # content-encoding that was decoded
    wire_bytes: int = 0                        # bytes actually received (before decompression)
    retries: int = 0                           # times the request was repeated after 429/503

    def header(self, name: str, default: str = "") -> str:
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return default

    def headers_all(self, name: str) -> list[str]:
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]


# ---------------------------------------------------------------------------------------------- decoding

class _Decoder:
    """Incremental gzip/deflate decoder that will not produce more than it is allowed to."""

    def __init__(self, encoding: str) -> None:
        self.encoding = encoding
        self.d = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding in ("gzip", "x-gzip") else zlib.decompressobj()
        self.first = True

    def feed(self, chunk: bytes, limit: int) -> tuple[bytes, bool]:
        """(decoded bytes, overflow). At most `limit` bytes come out; overflow is True if the stream had more to give.
        A limit of 0 is handled here because zlib reads max_length=0 as "no limit", which is exactly what must never happen."""
        if limit <= 0:
            return b"", bool(chunk)
        try:
            out = self.d.decompress(chunk, limit)
        except zlib.error:
            if self.encoding == "deflate" and self.first:          # some servers send raw deflate with no zlib header
                self.d = zlib.decompressobj(-zlib.MAX_WBITS)
                out = self.d.decompress(chunk, limit)
            else:
                raise
        self.first = False
        return out, bool(self.d.unconsumed_tail) or (len(out) >= limit and not self.d.eof)


def decode_text(data: bytes, content_type: str = "") -> str:
    """Bytes to text the way a browser would: BOM, then the declared charset, then a <meta> charset, then UTF-8, then Windows-1252."""
    if not data:
        return ""
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    cs = None
    m = re.search(r"charset\s*=\s*[\"']?([\w.:-]+)", content_type or "", re.I)
    if m:
        cs = m.group(1)
    else:
        m = re.search(rb"<meta[^>]+charset\s*=\s*[\"']?([\w.:-]+)", data[:4096], re.I)
        if m:
            cs = m.group(1).decode("ascii", "ignore")
    if cs:
        try:
            return data.decode(cs, errors="replace")
        except LookupError:
            pass
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


def parse_retry_after(value: str, cap: float = 30.0, default: float = 2.0) -> float:
    """Retry-After as seconds, from either form the standard allows: a number of seconds or an HTTP date."""
    v = (value or "").strip()
    if re.fullmatch(r"\d+(\.\d+)?", v):
        return min(cap, float(v))
    try:
        when = email.utils.parsedate_to_datetime(v)
        if when is not None:
            return max(0.0, min(cap, when.timestamp() - time.time()))
    except (TypeError, ValueError, IndexError):
        pass
    return default


# ---------------------------------------------------------------------------------------------- the pool

class Pool:
    """Idle keep-alive connections, per origin. A connection is used by one thread at a time."""

    def __init__(self, max_idle: int = 8, idle_timeout: float = 20.0) -> None:
        self.max_idle, self.idle_timeout = max_idle, idle_timeout
        self._idle: dict[tuple, list] = {}
        self._lock = threading.Lock()
        self.created = self.reused = 0

    def acquire(self, key: tuple):
        now = time.monotonic()
        with self._lock:
            lst = self._idle.get(key, [])
            while lst:
                conn, t = lst.pop()
                if now - t <= self.idle_timeout and conn.sock is not None:
                    self.reused += 1
                    return conn
                _close(conn)
        return None

    def release(self, key: tuple, conn) -> None:
        with self._lock:
            lst = self._idle.setdefault(key, [])
            if len(lst) < self.max_idle:
                lst.append((conn, time.monotonic()))
                return
        _close(conn)

    def count_created(self) -> None:
        with self._lock:
            self.created += 1

    def close(self) -> None:
        with self._lock:
            conns = [c for lst in self._idle.values() for c, _ in lst]
            self._idle.clear()
        for c in conns:
            _close(c)


def _close(conn) -> None:
    try:
        conn.close()
    except Exception:
        pass


def _proxy_for(scheme: str, host: str):
    """(proxy host, port, 'user:pass' or '') from the environment, honouring NO_PROXY, or None."""
    try:
        proxies = urllib.request.getproxies()
        p = proxies.get(scheme)
        if not p or urllib.request.proxy_bypass(host):
            return None
        if "//" not in p:
            p = "http://" + p
        u = urlsplit(p)
        if not u.hostname:
            return None
        cred = f"{unquote(u.username or '')}:{unquote(u.password or '')}" if u.username else ""
        return u.hostname, u.port or (443 if u.scheme == "https" else 80), cred
    except Exception:
        return None


# ---------------------------------------------------------------------------------------------- the client

class Client:
    def __init__(self, user_agent: str = "WebCrawler/2.0", timeout: float = 15.0, verify_tls: bool = True, max_idle: int = 8,
                 accept_encoding: bool = True, total_timeout: float | None = None, use_proxy: bool = True) -> None:
        self.user_agent, self.timeout, self.verify_tls = user_agent, timeout, verify_tls
        self.accept_encoding, self.use_proxy = accept_encoding, use_proxy
        self.total_timeout = total_timeout or max(timeout * 3, 30.0)
        self.pool = Pool(max_idle)
        self._ctx = self._make_context(verify_tls)
        self.requests = 0
        self.bytes = 0
        self._lock = threading.Lock()

    @staticmethod
    def _make_context(verify: bool) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def close(self) -> None:
        self.pool.close()

    @property
    def stats(self) -> dict:
        return {"requests": self.requests, "connections": self.pool.created, "reused": self.pool.reused, "bytes": self.bytes}

    # ---------------------------------------------------------------- public
    def get(self, url: str, headers: dict | None = None, **kw) -> Response:
        return self.request(url, "GET", headers, **kw)

    def head(self, url: str, headers: dict | None = None, **kw) -> Response:
        return self.request(url, "HEAD", headers, **kw)

    def request(self, url: str, method: str = "GET", headers: dict | None = None, *, max_body: int = 2 * 1024 * 1024,
                read_body: "bool | str" = True, stop: threading.Event | None = None, secret_headers=(), max_redirects: int = 10,
                retries: int = 2, follow: bool = True) -> Response:
        """One request, with redirects followed. read_body: True = read it, False = skip it, "html" = read it only if it looks
        like HTML or XML. Never raises."""
        t0 = time.monotonic()
        deadline = t0 + self.total_timeout
        secret = {s.lower() for s in secret_headers}
        r = Response(url, url)
        for attempt in range(retries + 1):
            r = self._follow(url, method, dict(headers or {}), max_body, read_body, deadline, secret, max_redirects, follow)
            r.retries = attempt
            if r.status in (429, 503) and attempt < retries and not r.error:
                wait = parse_retry_after(r.header("Retry-After"), 30.0, 2.0 * (attempt + 1))
                if time.monotonic() + wait > deadline:
                    break
                if (stop.wait(wait) if stop is not None else (time.sleep(wait) or False)):
                    break
                continue
            break
        r.elapsed = time.monotonic() - t0
        with self._lock:
            self.requests += 1
            self.bytes += r.wire_bytes
        return r

    # ---------------------------------------------------------------- redirects
    def _follow(self, url, method, headers, max_body, read_body, deadline, secret, max_redirects, follow) -> Response:
        chain: list = []
        seen = {url}
        cur = url
        r = Response(url, url)
        for _ in range(max_redirects + 1):
            r = self._once(cur, method, headers, max_body, read_body, deadline)
            r.url = url
            r.chain = list(chain)
            if r.error or r.status not in REDIRECTS or not follow:
                return r
            loc = r.header("Location")
            if not loc:
                return r
            nxt = urljoin(cur, loc.strip())
            sp = urlsplit(nxt)
            if sp.scheme not in ("http", "https") or not sp.hostname:
                r.error = f"redirect to an unsupported address ({sp.scheme or 'none'}:)"
                return r
            nxt = nxt.split("#", 1)[0]
            chain.append((cur, r.status))
            if nxt in seen:
                r.error, r.chain = "redirect loop", list(chain)
                return r
            seen.add(nxt)
            if urlsplit(cur).netloc.lower() != sp.netloc.lower():      # leaving the site: credentials stay behind
                headers = {k: v for k, v in headers.items() if k.lower() not in secret}
            if r.status == 303 and method not in ("GET", "HEAD"):
                method = "GET"
            cur = nxt
        r.error, r.chain = "too many redirects", list(chain)
        return r

    # ---------------------------------------------------------------- one request/response
    def _target(self, sp) -> str:
        path = quote(sp.path or "/", safe=SAFE_PATH)
        return path + ("?" + quote(sp.query, safe=SAFE_QUERY) if sp.query else "")

    def _key(self, scheme, host, port, proxy):
        return (scheme, host, port, self.verify_tls, proxy[:2] if proxy else None)

    def _connect(self, scheme, host, port, proxy):
        timeout = self.timeout
        if proxy:
            ph, pp, _ = proxy
            if scheme == "https":
                conn = http.client.HTTPSConnection(ph, pp, timeout=timeout, context=self._ctx)
                conn.set_tunnel(host, port)
            else:
                conn = http.client.HTTPConnection(ph, pp, timeout=timeout)
        elif scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=self._ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        self.pool.count_created()
        return conn

    def _once(self, url, method, headers, max_body, read_body, deadline) -> Response:
        r = Response(url, url)
        try:
            sp = urlsplit(url)
            scheme = sp.scheme.lower()
            host = (sp.hostname or "").encode("idna").decode("ascii")
            port = sp.port or (443 if scheme == "https" else 80)
        except (ValueError, UnicodeError) as e:
            r.error = f"bad URL: {e}"
            return r
        if scheme not in ("http", "https") or not host:
            r.error = "not an http(s) URL"
            return r
        if not re.fullmatch(r"[A-Za-z0-9._\-:\[\]%]+", host):
            r.error = "bad URL: invalid characters in the host name"
            return r
        proxy = _proxy_for(scheme, host) if self.use_proxy else None
        target = self._target(sp)
        if proxy and scheme == "http":
            target = f"{scheme}://{sp.netloc}{target}"
        hdrs = {"User-Agent": self.user_agent, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.5", "Accept-Language": "en"}
        if self.accept_encoding:
            hdrs["Accept-Encoding"] = "gzip, deflate"
        if proxy and proxy[2] and scheme == "http":
            hdrs["Proxy-Authorization"] = "Basic " + base64.b64encode(proxy[2].encode()).decode()
        hdrs.update(headers)
        key = self._key(scheme, host, port, proxy)
        conn = self.pool.acquire(key)
        reused = conn is not None
        raw = None
        for attempt in (0, 1):
            try:
                if conn is None:
                    conn, reused = self._connect(scheme, host, port, proxy), False
                conn.timeout = min(self.timeout, max(0.5, deadline - time.monotonic()))
                if conn.sock is not None:
                    conn.sock.settimeout(conn.timeout)
                conn.request(method, target, headers=hdrs)
                raw = conn.getresponse()
                break
            except (http.client.RemoteDisconnected, ConnectionResetError, ConnectionAbortedError, BrokenPipeError, http.client.CannotSendRequest,
                    http.client.ResponseNotReady, ssl.SSLEOFError) as e:
                _close(conn)
                conn = None
                if reused and attempt == 0 and method in ("GET", "HEAD"):   # a stale keep-alive connection: try once on a fresh one
                    continue
                r.error = _describe(e)
                return r
            except ssl.SSLCertVerificationError as e:
                _close(conn)
                r.error, r.tls_error = "certificate verify failed: " + (getattr(e, "verify_message", "") or str(e))[:100], True
                return r
            except (socket.timeout, TimeoutError):
                _close(conn)
                r.error = "timed out"
                return r
            except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as e:
                _close(conn)
                r.error = _describe(e)
                return r
        r.reused = reused
        r.status, r.reason = raw.status, raw.reason or ""
        r.headers = list(raw.getheaders())
        ctype = r.header("Content-Type")
        want = read_body is True or (read_body == "html" and (not ctype or re.search(r"html|xml", ctype, re.I) is not None))
        keep = True
        try:
            if method == "HEAD" or r.status in (204, 304) or 100 <= r.status < 200:
                raw.read()   # there is no body, but http.client only lets the connection be reused once the response has been "read"
            elif want:
                keep = self._read(raw, r, max_body, deadline, conn)
            else:
                try:
                    cl = int(r.header("Content-Length", "-1"))
                except ValueError:
                    cl = -1
                if 0 <= cl <= DRAIN_LIMIT and not raw.will_close:
                    raw.read(cl)
                else:
                    keep = False
        except (socket.timeout, TimeoutError):
            r.error, keep = "timed out reading the response", False
        except (OSError, ssl.SSLError, http.client.HTTPException, zlib.error) as e:
            r.error, keep = "response was cut off: " + _describe(e), False
        if keep and not raw.will_close and not r.error:
            self.pool.release(key, conn)
        else:
            _close(conn)
        return r

    def _read(self, raw, r: Response, max_body: int, deadline: float, conn) -> bool:
        """Read the body into r.body, decoding gzip/deflate, within max_body bytes and the deadline. True if the connection is reusable."""
        enc = r.header("Content-Encoding").strip().lower()
        if "," in enc:
            enc = enc.split(",")[0].strip()
        dec = None
        if enc in ("gzip", "x-gzip", "deflate"):
            dec = _Decoder(enc)
            r.encoding = enc
        elif enc not in ("", "identity"):
            r.error = f"unsupported content encoding ({enc})"
            return False
        out, size = [], 0
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                r.error = "timed out reading the response"
                return False
            if conn.sock is not None:
                conn.sock.settimeout(min(self.timeout, left))
            chunk = raw.read1(65536)   # whatever has arrived: read() would wait for all 64 KB and never let the deadline be checked
            if not chunk:
                break
            r.wire_bytes += len(chunk)
            if dec is None:
                room = max_body - size
                out.append(chunk[:max(room, 0)])
                size += min(len(chunk), max(room, 0))
                if len(chunk) > room:
                    r.truncated = True
                    break
                continue
            piece, overflow = dec.feed(chunk, max_body - size)
            out.append(piece)
            size += len(piece)
            if overflow:
                r.truncated = True
                break
        r.body = b"".join(out)
        if not r.truncated:
            raw.read()   # read1() never marks a fixed-length response as finished, and the connection cannot be reused until it is
        return not r.truncated


def _describe(e: Exception) -> str:
    s = str(e) or e.__class__.__name__
    if isinstance(e, http.client.RemoteDisconnected):
        s = "connection closed by the server"
    return s[:140]


def get(url: str, user_agent: str = "WebCrawler/2.0", timeout: float = 15.0, max_body: int = 512 * 1024, headers: dict | None = None,
        verify_tls: bool = True) -> Response:
    """One-off GET with no pooling (robots.txt, sitemaps)."""
    c = Client(user_agent, timeout, verify_tls, max_idle=1)
    try:
        return c.get(url, headers, max_body=max_body)
    finally:
        c.close()
