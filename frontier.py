"""frontier.py: the rules of a crawl, shared by the browser crawler and the quick (no-browser) scanner.

CrawlOptions says how far, how fast and how wide to go. Frontier decides which URLs are worth visiting (scope, include and
exclude patterns, de-duplication, depth, robots.txt). Pacer spaces requests out. Nothing here touches a network or a browser,
so all of it is unit tested.
"""
from __future__ import annotations

import random
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field, replace
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

SKIP_EXT = re.compile(r"\.(pdf|zip|gz|tar|7z|rar|exe|msi|dmg|iso|apk|docx?|xlsx?|pptx?|csv|png|jpe?g|gif|svg|webp|ico|mp3|mp4|mov|webm|avi|woff2?|ttf|eot)$", re.I)
TRACKING = re.compile(r"^(utm_[a-z]+|fbclid|gclid|msclkid|mc_eid|mc_cid|igshid|_hsenc|_hsmi)$", re.I)
DEFAULT_UA = "WebCrawler/2.0 (security recon tool; respects robots.txt)"
# for your own sites when a firewall refuses unknown clients (shorthand for --user-agent)
UA_ALIASES = {
    "chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
}


@dataclass
class CrawlOptions:
    depth: int = 2                  # how many link-hops from the start page
    max_pages: int = 100            # stop after this many pages
    max_duration: float = 0.0       # seconds; 0 = no limit
    delay_min: float = 0.5          # seconds between requests (global), random between min and max
    delay_max: float = 1.5
    max_rps: float = 0.0            # hard cap on requests per second; 0 = off
    concurrency: int = 4            # parallel downloads (quick scan only)
    timeout: float = 15.0           # seconds per request
    scope: str = "host"             # host | subdomains | any
    include: list = field(default_factory=list)   # regex; when set, a URL must match one
    exclude: list = field(default_factory=list)   # regex; a match skips the URL
    ignore_robots: bool = False
    strategy: str = "bfs"           # bfs (level by level) | dfs (follow a branch to the end)
    check_external: bool = False    # quick scan: HEAD-check external links for breakage
    user_agent: str = DEFAULT_UA
    scroll_speed: int = 600         # browser crawl: px/s while scrolling
    use_sitemap: bool = True        # also visit pages listed in robots.txt / sitemap.xml (finds pages nothing links to)
    probe_files: bool = False       # request a short list of well-known paths (.git, .env, security.txt...): only on sites you own
    check_tls: bool = True          # check the HTTPS certificate and protocol of the start site
    resolve_hosts: bool = True      # look up the subdomains the site refers to, to flag names that no longer resolve
    check_dns: bool = False         # read the domain's SPF / DMARC / CAA / DNSSEC records through a public DNS-over-HTTPS resolver (opt-in: it names the domain to that resolver)
    check_ct: bool = False          # list subdomains from public certificate logs (crt.sh): opt-in, it names the domain to that service
    ct_url: str = ""                # the search URL for check_ct ("" = crt.sh); {domain} is replaced
    doh_url: str = ""               # the DNS-over-HTTPS resolver for check_dns ("" = Cloudflare)
    render: str = "auto"            # quick scan: render script-built pages in a headless browser: auto (judge each page) | never | always
    render_limit: int = 100         # at most this many pages are rendered in one scan
    verify_tls: bool = True         # False crawls sites whose certificate does not verify (self-signed, internal); the problem is still reported
    max_query_variants: int = 20    # crawler-trap guard: at most this many different ?query strings are followed for one path (0 = no limit)

    def clamped(self) -> "CrawlOptions":
        o = replace(self)
        o.depth = max(0, min(int(o.depth), 25))
        o.max_pages = max(1, min(int(o.max_pages), 100000))
        o.delay_min = max(0.0, float(o.delay_min))
        o.delay_max = max(o.delay_min, float(o.delay_max))
        o.concurrency = max(1, min(int(o.concurrency), 64))
        o.timeout = max(1.0, float(o.timeout))
        o.max_duration = max(0.0, float(o.max_duration))
        o.max_rps = max(0.0, float(o.max_rps))
        o.scroll_speed = max(50, min(int(o.scroll_speed), 5000))
        o.max_query_variants = max(0, int(o.max_query_variants))
        if o.render not in ("auto", "never", "always"):
            o.render = "auto"
        o.render_limit = max(0, int(o.render_limit))
        if o.scope not in ("host", "subdomains", "any"):
            o.scope = "host"
        if o.strategy not in ("bfs", "dfs"):
            o.strategy = "bfs"
        return o


# how aggressively to crawl; "blitz" is for your own servers only
PRESETS = {
    "stealth":  dict(delay_min=5.0, delay_max=15.0, concurrency=1, max_rps=0.0, scroll_speed=250),
    "polite":   dict(delay_min=1.0, delay_max=3.0, concurrency=2, max_rps=0.0, scroll_speed=400),
    "balanced": dict(delay_min=0.4, delay_max=1.2, concurrency=4, max_rps=0.0, scroll_speed=600),
    "fast":     dict(delay_min=0.05, delay_max=0.15, concurrency=8, max_rps=20.0, scroll_speed=1200),
    "blitz":    dict(delay_min=0.0, delay_max=0.0, concurrency=16, max_rps=0.0, scroll_speed=2400),
}


def with_preset(name: str, base: CrawlOptions | None = None) -> CrawlOptions:
    o = replace(base or CrawlOptions())
    for k, v in PRESETS[name].items():
        setattr(o, k, v)
    return o.clamped()


def normalize(url: str) -> str:
    """Canonical form used for de-duplication: no fragment, lower-case host, no default port, no tracking parameters."""
    u = urlparse(url.strip())
    scheme, host = u.scheme.lower(), (u.hostname or "").lower()
    if scheme not in ("http", "https", "file"):
        return url.strip()
    port = u.port
    netloc = host if port in (None, 80 if scheme == "http" else 443) else f"{host}:{port}"
    if u.username:
        netloc = f"{u.username}@{netloc}"
    q = urlencode([(k, v) for k, v in parse_qsl(u.query, keep_blank_values=True) if not TRACKING.match(k)])
    path = u.path or ("/" if scheme != "file" else "")
    return urlunparse((scheme, netloc, path, u.params, q, ""))


def _base_domain(host: str) -> str:
    host = host.lower().removeprefix("www.")
    return host


def in_scope(url: str, root: str, scope: str) -> bool:
    u, r = urlparse(url), urlparse(root)
    if scope == "any":
        return u.scheme in ("http", "https", "file")
    if u.scheme != r.scheme and not (u.scheme in ("http", "https") and r.scheme in ("http", "https") and scope == "subdomains"):
        return False
    if u.scheme == "file":
        return u.path.startswith(r.path.rsplit("/", 1)[0] + "/")
    uh, rh = (u.hostname or "").lower(), (r.hostname or "").lower()
    if scope == "subdomains":
        b = _base_domain(rh)
        return uh == b or uh.endswith("." + b)
    return _base_domain(uh) == _base_domain(rh) and u.port == r.port


def compile_patterns(patterns) -> list:
    out = []
    for p in patterns or []:
        p = p.strip()
        if p:
            out.append(re.compile(p, re.I))
    return out


class Frontier:
    """The queue of pages still to visit. push() applies every rule; pop() hands out the next URL."""

    MAX_DEFERRED = 50000

    def __init__(self, start: str, opts: CrawlOptions, robots=None, push_root: bool = True) -> None:
        self.opts = opts
        self.root = normalize(start)
        self.robots = robots
        self._include = compile_patterns(opts.include)
        self._exclude = compile_patterns(opts.exclude)
        self._q: deque = deque()
        self.queued: set[str] = set()
        self.visited: set[str] = set()
        self.skipped: dict[str, int] = {}
        self.deferred: list = []      # acceptable URLs that were one hop too deep: a later, deeper crawl can still use them
        self.variants: dict[tuple, set] = {}    # (host, path) -> the distinct query strings already queued, for the trap guard
        if push_root:
            self.push(self.root, 0, None, force=True)

    # -- saving and resuming a crawl
    def to_state(self) -> dict:
        return {"root": self.root, "queue": [list(x) for x in self._q], "visited": sorted(self.visited), "skipped": dict(self.skipped),
                "deferred": [list(x) for x in self.deferred]}

    @classmethod
    def from_state(cls, state: dict, opts: CrawlOptions, robots=None) -> "Frontier":
        f = cls(state.get("root", ""), opts, robots, push_root=False)
        f.visited = set(state.get("visited", []))
        f.skipped = dict(state.get("skipped", {}))
        for u, d, p in state.get("queue", []):
            f.push(u, d, p)
        for u, d, p in state.get("deferred", []):   # the user may have raised the depth since the crawl was saved
            f.push(u, d, p)
        return f

    def _skip(self, why: str) -> bool:
        self.skipped[why] = self.skipped.get(why, 0) + 1
        return False

    def push(self, url: str, depth: int, parent: str | None, force: bool = False) -> bool:
        u = normalize(url)
        if u in self.queued or u in self.visited:
            return False  # duplicates are normal, not worth counting
        if not force:
            if urlparse(u).scheme not in ("http", "https", "file"):
                return self._skip("not a web page")
            if SKIP_EXT.search(urlparse(u).path):
                return self._skip("file download")
            if "/cdn-cgi/" in urlparse(u).path:       # Cloudflare's own endpoints (email protection, challenges, RUM): not part of the site
                return self._skip("platform endpoint")
            if not in_scope(u, self.root, self.opts.scope):
                return self._skip("out of scope")
            if self._include and not any(p.search(u) for p in self._include):
                return self._skip("not included")
            if any(p.search(u) for p in self._exclude):
                return self._skip("excluded")
            if depth > self.opts.depth:
                if len(self.deferred) < self.MAX_DEFERRED:
                    self.deferred.append((u, depth, parent))
                return self._skip("too deep")
        if self.opts.max_query_variants:
            pu = urlparse(u)
            if pu.query:
                seen = self.variants.setdefault((pu.netloc, pu.path), set())
                if not force and u not in seen and len(seen) >= self.opts.max_query_variants:
                    return self._skip("too many parameter variants")
                seen.add(u)
        self.queued.add(u)
        self._q.append((u, depth, parent))
        return True

    def __len__(self) -> int:
        return len(self._q)

    def requeue(self, url: str, depth: int, parent: str | None) -> None:
        """Put a page that was started but not finished back at the front, so it is the next one handed out."""
        u = normalize(url)
        self.visited.discard(u)
        if u in self.queued:
            return
        self.queued.add(u)
        (self._q.appendleft if self.opts.strategy == "bfs" else self._q.append)((u, depth, parent))

    def pop(self):
        """Next (url, depth, parent) that is allowed by robots.txt, or None when the frontier is empty or full."""
        while self._q and len(self.visited) < self.opts.max_pages:
            u, d, p = self._q.popleft() if self.opts.strategy == "bfs" else self._q.pop()
            self.queued.discard(u)
            if self.robots is not None and not self.opts.ignore_robots and not self.robots.allowed(u):
                self._skip("blocked by robots.txt")
                continue
            self.visited.add(u)
            return u, d, p
        return None


class Pacer:
    """Spaces request starts out by a random delay between min and max, and never faster than max_rps. Thread-safe."""

    def __init__(self, opts: CrawlOptions, clock=time.monotonic, rng=random.random, min_floor: float = 0.0) -> None:
        self.opts, self.clock, self.rng = opts, clock, rng
        self.floor = min_floor  # e.g. a robots.txt Crawl-delay
        self.penalty = 0.0      # extra seconds between requests while the server is struggling or refusing (429/503/timeouts)
        self._next = 0.0
        self._lock = threading.Lock()

    def slow_down(self) -> bool:
        """The server pushed back: double the extra delay (1 s up to 30 s). True if it just got longer."""
        with self._lock:
            new = min(max(self.penalty * 2, 1.0), 30.0)
            changed = new > self.penalty
            self.penalty = new
            return changed

    def speed_up(self) -> None:
        """A normal answer: let the extra delay fade away."""
        with self._lock:
            self.penalty = self.penalty * 0.85 if self.penalty > 0.2 else 0.0

    def reserve(self) -> float:
        """Claim the next request slot and return how many seconds to wait before using it."""
        with self._lock:
            now = self.clock()
            lo, hi = max(self.opts.delay_min, self.floor), max(self.opts.delay_max, self.floor)
            gap = lo + (hi - lo) * self.rng() + self.penalty
            if self.opts.max_rps > 0:
                gap = max(gap, 1.0 / self.opts.max_rps)
            start = max(now, self._next)
            self._next = start + gap
            return max(0.0, start - now)
