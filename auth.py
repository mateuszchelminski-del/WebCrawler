"""auth.py: let a crawl see what a logged-in user sees.

You give it a session you already have (cookies, an Authorization header, or a browser profile); it never logs in for you
and never stores credentials: nothing in here is written to a session file, a report or a log. The two rules that matter:

  * credentials go only to the site being crawled, never to another host, including after a redirect;
  * logout links are excluded by default, so the crawler does not end its own session.
"""
from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

import frontier as fr

TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
NOT_SETTABLE = {"host", "content-length", "transfer-encoding", "connection", "user-agent"}
MAX_FILE = 1024 * 1024

# a crawler that clicks "log out" ends its own session and then maps the anonymous site; never do that by accident
LOGOUT_PATTERNS = [r"log[-_ ]?out", r"sign[-_ ]?out", r"log[-_ ]?off", r"/exit\b", r"/session/(destroy|end)", r"[?&]action=logout"]


def parse_header_line(line: str) -> tuple[str, str]:
    """'Authorization: Bearer abc' -> ('Authorization', 'Bearer abc'). Rejects anything that could smuggle another header."""
    if ":" not in line:
        raise ValueError(f"not a header (expected 'Name: value'): {line[:30]!r}")
    name, value = (x.strip() for x in line.split(":", 1))
    if not TOKEN.match(name):
        raise ValueError(f"invalid header name: {name[:30]!r}")
    if name.lower() in NOT_SETTABLE:
        raise ValueError(f"header {name} cannot be set")
    if re.search(r"[\r\n\x00]", value):
        raise ValueError("header values cannot contain line breaks")
    return name, value


def parse_cookie_string(s: str, domain: str = "") -> list[dict]:
    """'a=1; b=2' (or a whole 'Cookie: a=1; b=2' line, as copied from browser dev tools) -> cookie dicts."""
    s = re.sub(r"^\s*cookie\s*:\s*", "", s.strip(), flags=re.I)
    out = []
    for part in s.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name, value = name.strip(), value.strip()
        if name and re.fullmatch(r"[^\s=;,\x00-\x1f]+", name) and not re.search(r"[\r\n\x00]", value):
            out.append({"name": name, "value": value, "domain": domain, "path": "/"})
    if not out and s:
        raise ValueError("no cookies found: expected name=value pairs separated by semicolons")
    return out


def load_cookie_file(path: str, domain: str = "") -> list[dict]:
    """Cookies from a file: a JSON export (browser extensions, Playwright storage_state), a Netscape cookies.txt, or one 'a=1; b=2' line."""
    p = Path(path).expanduser()
    if p.stat().st_size > MAX_FILE:
        raise ValueError("cookie file is larger than 1 MB")
    text = p.read_text(encoding="utf-8", errors="replace").strip()
    if text[:1] in "[{":
        data = json.loads(text)
        items = data.get("cookies", []) if isinstance(data, dict) else data
        out = []
        for c in items:
            if isinstance(c, dict) and c.get("name") and "value" in c:
                out.append({"name": str(c["name"]), "value": str(c["value"]), "domain": (c.get("domain") or domain or ""), "path": c.get("path") or "/",
                            "secure": bool(c.get("secure", False)), "httpOnly": bool(c.get("httpOnly", False))})
        if not out:
            raise ValueError("no cookies found in that JSON file")
        return out
    rows = []
    for line in text.splitlines():
        line = line.strip()
        http_only = line.startswith("#HttpOnly_")
        if http_only:
            line = line[len("#HttpOnly_"):]
        if not line or line.startswith("#"):
            continue
        f = line.split("\t")
        if len(f) >= 7:
            rows.append({"name": f[5], "value": f[6], "domain": f[0], "path": f[2] or "/", "secure": f[3].upper() == "TRUE", "httpOnly": http_only})
    return rows or parse_cookie_string(text, domain)


def _host_match(cookie_domain: str, host: str) -> bool:
    d = cookie_domain.lstrip(".").lower()
    return not d or host == d or host.endswith("." + d)


@dataclass
class AuthConfig:
    cookies: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        return not self.cookies and not self.headers

    def cookie_header(self, url: str) -> str:
        u = urlparse(url)
        host = (u.hostname or "").lower()
        pairs = [f"{c['name']}={c['value']}" for c in self.cookies
                 if _host_match(c.get("domain", ""), host) and (u.path or "/").startswith(c.get("path") or "/") and (not c.get("secure") or u.scheme == "https")]
        return "; ".join(pairs)

    def headers_for(self, url: str, root: str, scope: str = "host") -> dict:
        """The headers to send to `url`: empty unless it is on the crawled site (never on another host, whatever the crawl scope)."""
        if self.empty or not fr.in_scope(fr.normalize(url), fr.normalize(root), "subdomains" if scope == "subdomains" else "host"):
            return {}
        h = dict(self.headers)
        c = self.cookie_header(url)
        if c:
            h["Cookie"] = c
        return h

    def secret_header_names(self) -> set:
        names = {n.lower() for n in self.headers}
        if self.cookies:
            names.add("cookie")
        return names | {"authorization"}

    def for_playwright(self, start: str) -> list[dict]:
        out = []
        for c in self.cookies:
            d = {"name": c["name"], "value": c["value"], "secure": bool(c.get("secure")), "httpOnly": bool(c.get("httpOnly"))}
            if c.get("domain"):
                d.update(domain=c["domain"], path=c.get("path") or "/")
            else:
                d["url"] = start
            out.append(d)
        return out

    def describe(self) -> str:
        """For logs: what is configured, never the values."""
        bits = []
        if self.cookies:
            bits.append(f"{len(self.cookies)} cookie(s): " + ", ".join(sorted({c['name'] for c in self.cookies})[:6]))
        if self.headers:
            bits.append("header(s): " + ", ".join(sorted(self.headers)))
        return "; ".join(bits) or "none"

    @classmethod
    def build(cls, cookie: str = "", cookie_file: str = "", headers=(), domain: str = "") -> "AuthConfig":
        cookies = []
        if cookie:
            cookies += parse_cookie_string(cookie, domain)
        if cookie_file:
            cookies += load_cookie_file(cookie_file, domain)
        return cls(cookies, dict(parse_header_line(h) for h in headers if h.strip()))


def logout_excludes() -> list[str]:
    return list(LOGOUT_PATTERNS)


HEADER_TYPES = ("document", "xhr", "fetch")      # page loads and API calls: the requests a bearer token or API key is meant for


def install_login(ctx, cfg: AuthConfig, start: str, scope: str = "host", block: tuple = ()) -> None:
    """Give a Playwright browser context the login, and optionally block resource types (images, fonts...) to make it faster.

    Cookies go in as they are. Extra headers are added to page loads and XHR/fetch calls to the crawled site and nothing else.
    Chromium keeps an overridden header across a redirect, which would carry a credential to another site, so a request that
    needs a header is made by Playwright with redirects switched off: the browser then follows each redirect itself, and the
    request to the other site is not intercepted at all. Requests that need nothing go straight through."""
    if cfg.cookies:
        ctx.add_cookies(cfg.for_playwright(start))
    extra = dict(cfg.headers)
    if not extra and not block:
        return
    try:
        chromium = ctx.browser is None or ctx.browser.browser_type.name == "chromium"     # a persistent profile has no .browser: that is Chromium
    except Exception:
        chromium = True

    def on_site(url: str) -> bool:
        return bool(extra) and bool(cfg.headers_for(url, start, scope))

    def handler(route, request):
        try:
            if request.resource_type in block:
                route.abort()
            elif extra and request.resource_type in HEADER_TYPES and on_site(request.url):
                resp = route.fetch(headers={**request.headers, **extra}, max_redirects=0)
                where = resp.headers.get("location", "")
                if not chromium and 300 <= resp.status < 400 and where and request.resource_type == "document":
                    # WebKit and Firefox refuse a hand-made redirect, so a page load that redirects is replayed as a page that goes straight
                    # on to the next address: a new request, which gets the login headers again only if it is still the crawled site
                    nxt = html.escape(urljoin(request.url, where), quote=True)
                    route.fulfill(status=200, content_type="text/html", body=f'<!doctype html><meta http-equiv="refresh" content="0;url={nxt}">')
                else:
                    route.fulfill(response=resp)
            else:
                route.continue_()
        except Exception:
            try:
                route.fallback()
            except Exception:
                pass
    # when only headers are involved, requests to other sites are never intercepted, so nothing can leak through them
    ctx.route(on_site if (extra and not block) else "**/*", handler)
