"""httpscan.py: the quick scanner. Crawls a site with plain HTTP requests, no browser, several pages at once.

It is the fast, unattended sibling of the browser crawler: it cannot run JavaScript, so links that a script builds
are not seen, but it is light enough to map hundreds of pages in a minute, and it reports the same things:
links, link risks, response-header and markup findings, technologies, broken pages and the site graph.

Everything it learns goes to the same queue the GUI already listens to (see engine.py for the event list), plus
    ("broken", url, status, referrer, reason)      a page or checked link that failed (status 0 = no answer)
    ("progress", {pages, queued, errors, links, elapsed, rps})
and into the shared objects it is given: the LinkStore, the SiteGraph and the SiteInfo (TLS, technologies, exposed files).

Network access goes through httpclient.py: pooled keep-alive connections, gzip, redirects that never carry credentials to
another host. When a server pushes back (429, 503, timeouts) the scanner slows itself down and recovers when the server calms.
"""
from __future__ import annotations

import queue
import re
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import analysis
import auth as auth_mod
import checks
import content
import dnscheck
import frontier as fr
import graph as gr
import httpclient
import render as render_mod
import webcrawler as wc

MAX_BODY = 2 * 1024 * 1024
MAX_RAW = 256 * 1024                 # probes and robots.txt
MAX_SITEMAP = checks.MAX_SITEMAP_BYTES   # a sitemap may legitimately be tens of megabytes
REASONS = {400: "bad request", 401: "login required", 403: "forbidden", 404: "not found", 405: "method not allowed", 410: "gone", 429: "rate limited",
           500: "server error", 502: "bad gateway", 503: "service unavailable", 504: "gateway timeout"}


class LinkParser(HTMLParser):
    """Collects <a>/<area> links with their text, the page title and any <base href>. Understands Cloudflare's protected e-mail markup."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict] = []
        self.title = ""
        self.base = ""
        self._in_title = False
        self._a: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if self._a is not None and a.get("data-cfemail"):
            self._a["cf"] = wc.decode_cf_email(a["data-cfemail"])
        if tag == "title":
            self._in_title = True
        elif tag == "base" and a.get("href") and not self.base:
            self.base = a["href"]
        elif tag in ("a", "area") and a.get("href") is not None:
            self._a = {"href": a["href"], "text": a.get("aria-label") or a.get("title") or a.get("alt") or "", "rel": a.get("rel") or ""}
            if a.get("data-cfemail"):
                self._a["cf"] = wc.decode_cf_email(a["data-cfemail"])
            self.links.append(self._a)
            if tag == "area":
                self._a = None
        elif tag == "img" and self._a is not None and not self._a["text"].strip():
            self._a["text"] = a.get("alt") or ""

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "a":
            self._a = None

    def handle_data(self, data):
        if self._in_title and len(self.title) < 200:
            self.title += data
        elif self._a is not None and data.strip():
            self._a["_plain"] = (self._a.get("_plain") or "") + data

    def close(self):
        super().close()
        for l in self.links:
            plain = re.sub(r"\s+", " ", l.pop("_plain", "") or "").strip()
            cf = l.pop("cf", "")
            if cf and re.search(r"\[email\s*(&#160;|\xa0)?\s*protected\]", plain):
                plain = cf                       # show the real address instead of Cloudflare's placeholder
            l["text"] = plain or l["text"]
        self.title = re.sub(r"\s+", " ", self.title).strip()


def parse_html(text: str) -> LinkParser:
    p = LinkParser()
    try:
        p.feed(text)
        p.close()
    except Exception:  # broken markup must not kill a crawl
        pass
    return p


@dataclass
class Fetched:
    url: str
    final_url: str = ""
    status: int = 0
    headers: list = field(default_factory=list)
    body: str = ""
    raw: bytes = b""
    error: str = ""
    elapsed: float = 0.0
    chain: list = field(default_factory=list)    # [(url, status)] redirect hops before the final answer
    html: bool = False
    tls_error: bool = False
    retries: int = 0
    wire_bytes: int = 0
    truncated: bool = False


def fetch(url: str, opts: fr.CrawlOptions, method: str = "GET", stop: threading.Event | None = None, headers: dict | None = None,
          raw: bool = False, secret_headers=(), client: "httpclient.Client | None" = None, max_raw: int = MAX_RAW) -> Fetched:
    """One HTTP request. Never raises: failures come back in .error with status 0. `raw` reads any content type (for probes)."""
    own = client is None
    if own:
        client = httpclient.Client(opts.user_agent, opts.timeout, opts.verify_tls, max_idle=1)
    try:
        r = client.request(url, method, headers, max_body=max_raw if raw else MAX_BODY, read_body=True if raw else "html", stop=stop,
                           secret_headers=secret_headers)
    finally:
        if own:
            client.close()
    f = Fetched(url, r.final_url or url, r.status, r.headers, error=r.error, elapsed=r.elapsed, chain=r.chain, tls_error=r.tls_error,
                retries=r.retries, wire_bytes=r.wire_bytes, truncated=r.truncated)
    ctype = r.header("Content-Type")
    f.html = method == "GET" and r.status > 0 and (not ctype or re.search(r"html|xml", ctype, re.I) is not None)
    if raw:
        f.raw = r.body
    elif f.html and r.body:
        f.body = httpclient.decode_text(r.body, ctype)
    return f


def reason_for(r: Fetched) -> str:
    """Why a response counts as a problem, in words: 'not found (HTTP 404)', 'timed out', 'rate limited (HTTP 429)'."""
    if r.error:
        return r.error
    word = REASONS.get(r.status, "server error" if r.status >= 500 else "error")
    return f"{word} (HTTP {r.status})"


def run_discovery(start: str, opts: fr.CrawlOptions, cfg: "auth_mod.AuthConfig", pacer: "fr.Pacer", stop: threading.Event,
                  info: "checks.SiteInfo", site: "gr.SiteGraph", emit, client: "httpclient.Client | None" = None) -> list[str]:
    """The checks done once per site before crawling: TLS, robots.txt and sitemaps, and (opt-in) well-known files.
    Fills `info`, records the sitemap in the graph, and returns the page URLs the site lists about itself. Blocks on the network,
    so run it on a worker thread; `stop` ends it early."""
    u = urlparse(start)
    root = f"{u.scheme}://{u.netloc}"
    own = client is None
    if own:
        client = httpclient.Client(opts.user_agent, opts.timeout, opts.verify_tls, max_idle=2)

    def getter(as_bytes: bool):
        def get(url: str):
            if stop.wait(pacer.reserve()):
                return 0, b"" if as_bytes else ""
            r = fetch(url, opts, "GET", stop, cfg.headers_for(url, start, opts.scope), True, cfg.secret_header_names(), client,
                      MAX_SITEMAP if as_bytes else MAX_RAW)
            if r.truncated and as_bytes:
                return 413, b""      # "too large": reported as such, rather than as XML that mysteriously fails to parse
            return r.status, (r.raw if as_bytes else r.raw.decode("latin-1", errors="replace"))
        return get
    pages: list[str] = []
    try:
        if opts.check_tls and u.scheme == "https" and not stop.is_set():
            emit("status", f"Checking the TLS certificate of {u.hostname}…")
            info.add_tls(checks.tls_info(u.hostname, u.port or 443, min(opts.timeout, 8)))
        if opts.check_dns and not stop.is_set():
            emit("status", f"Reading the DNS records of {u.hostname}…")
            rep = dnscheck.run(u.hostname or "", opts.doh_url or dnscheck.DEFAULT_DOH, None, min(opts.timeout, 8), opts.user_agent)
            if rep is not None:
                info.add_dns(rep)
                for e in rep.errors[:2]:
                    emit("status", "DNS: " + e)
            else:
                emit("status", f"DNS records skipped: {u.hostname} is not a public host name")
        if opts.check_ct and not stop.is_set() and checks.is_public_host(u.hostname or ""):
            emit("status", f"Listing subdomains of {checks.registrable(u.hostname)} from certificate logs…")
            names, err = dnscheck.ct_subdomains(checks.registrable(u.hostname), opts.ct_url or dnscheck.CT_URL, None, max(opts.timeout, 20.0), opts.user_agent)
            for n in names:
                info.add_host(n, "certificate-log", u.hostname)
            emit("status", f"Certificate logs: {len(names)} name(s)" if not err else "Certificate log search failed: " + err)
        if opts.use_sitemap and not stop.is_set():
            seeds = checks.discover_seeds(start, getter(True))
            info.set_seeds(seeds, root + "/robots.txt")
            if seeds.pages:
                for sm in seeds.sitemaps[:1] or [root + "/sitemap.xml"]:
                    site.add_source(sm, seeds.pages)
                pages = seeds.pages
            for e in seeds.errors[:3]:
                emit("status", "Sitemap: " + e)
        if opts.probe_files and not stop.is_set():
            emit("status", "Probing well-known files…")
            info.add_probes(checks.probe(start, getter(False)))
    finally:
        if own:
            client.close()
    return pages


class QuickScanner(threading.Thread):
    def __init__(self, start: str, opts: fr.CrawlOptions, store: "wc.LinkStore", site: "gr.SiteGraph", events: queue.Queue,
                 security: dict | None = None, info: "checks.SiteInfo | None" = None, auth: "auth_mod.AuthConfig | None" = None,
                 resume: dict | None = None) -> None:
        super().__init__(daemon=True, name="quick-scanner")
        self.start_url = start
        self.opts = opts.clamped()
        self.auth = auth or auth_mod.AuthConfig()
        if not self.auth.empty:  # a crawler that follows "log out" ends its own session
            self.opts.exclude = list(dict.fromkeys(list(self.opts.exclude) + auth_mod.logout_excludes()))
        self.store, self.graph, self.events = store, site, events
        self.security = security if security is not None else {}
        self.info = info if info is not None else checks.SiteInfo()
        self.stop_event = threading.Event()
        self.robots = wc.Robots(not self.opts.ignore_robots, agent=self.opts.user_agent, timeout=min(self.opts.timeout, 8), verify_tls=self.opts.verify_tls)
        self.pacer = fr.Pacer(self.opts)
        self.client = httpclient.Client(self.opts.user_agent, self.opts.timeout, self.opts.verify_tls, max_idle=max(2, self.opts.concurrency * 2))
        self.resuming = resume is not None
        self.frontier = fr.Frontier.from_state(resume, self.opts, self.robots) if resume else fr.Frontier(start, self.opts, self.robots)
        self.pages = len(self.frontier.visited) if resume else 0
        self.errors = 0
        self.responses = self.refused = self.throttled = 0
        self.start_host = urlparse(start).hostname or ""
        self.renderer: "render_mod.Renderer | None" = None
        self.rendered = 0
        self._render_budget = self.opts.render_limit if self.opts.render != "never" else 0
        self._render_lock = threading.Lock()
        self.t0 = 0.0
        self.summary: dict = {}
        self.resume_state: dict | None = None

    def stop(self) -> None:
        self.stop_event.set()

    def emit(self, *ev) -> None:
        self.events.put(ev)

    # ------------------------------------------------------------------ worker side (network only)
    def _secret_names(self):
        return self.auth.secret_header_names()

    def _feedback(self, r: Fetched) -> None:
        """Adapt to how the server is coping: back off on 429/503/timeouts, recover on normal answers."""
        self.responses += 1
        if r.status in (403, 429):
            self.refused += 1
        if r.status in (429, 503) or r.retries or r.error in ("timed out", "timed out reading the response"):
            if self.pacer.slow_down():
                self.throttled += 1
                self.emit("status", f"The server is pushing back ({r.status or 'timeouts'}): waiting longer between requests (+{self.pacer.penalty:g}s).")
        elif r.status and r.status < 500:
            self.pacer.speed_up()

    def _fetch_paced(self, url: str, method: str = "GET", raw: bool = False) -> Fetched:
        if self.stop_event.wait(self.pacer.reserve()):
            return Fetched(url, url, error="stopped")
        r = fetch(url, self.opts, method, self.stop_event, self.auth.headers_for(url, self.start_url, self.opts.scope), raw, self._secret_names(), self.client)
        self._feedback(r)
        return r

    def _render_if_needed(self, r: "Fetched", parsed) -> "render_mod.Rendered | None":
        """Render the page in a browser if it looks like JavaScript builds its links, within the budget. Runs on a worker thread."""
        if not (parsed and r.body and r.status and r.status < 400 and not r.error) or self.stop_event.is_set():
            return None
        final = r.final_url or r.url
        internal = sum(1 for l in parsed.links if (a := wc.resolve(l["href"], final)) and wc.classify(a, final) == "internal")
        why = render_mod.needs_js(r.body, internal, self.opts.render)
        if not why:
            return None
        with self._render_lock:
            if self._render_budget <= 0 or (self.renderer is not None and self.renderer.unavailable):
                return None
            self._render_budget -= 1
            if self.renderer is None:
                self.renderer = render_mod.Renderer(self.opts.user_agent, self.opts.verify_tls, self.auth, self.start_url, self.opts.scope,
                                                    timeout=self.opts.timeout, emit=self.emit)
        res = self.renderer.render(final, self.stop_event)
        if res.error and "imeout" in res.error and not self.stop_event.is_set():
            res = self.renderer.render(final, self.stop_event)            # the first page a cold browser opens can be slow: one more try
        if res.error:
            self.emit("status", f"Could not render {final} ({res.error}); using the page as it was served")
            return None
        res.why = why
        return res

    def _task(self, url: str, depth: int, parent: str | None):
        r = self._fetch_paced(url)
        parsed = parse_html(r.body) if r.html and r.body else None
        rendered = self._render_if_needed(r, parsed) if parsed is not None else None
        return url, depth, parent, r, parsed, rendered

    # ------------------------------------------------------------------ site-wide checks (run once, before the crawl)
    def _discover(self) -> None:
        pages = run_discovery(self.start_url, self.opts, self.auth, self.pacer, self.stop_event, self.info, self.graph, self.emit, self.client)
        n = sum(1 for p in pages if self.frontier.push(p, 1, None))
        if pages:
            self.emit("status", f"Sitemap lists {len(pages)} page(s); {n} queued.")

    # ------------------------------------------------------------------ manager side (all shared state lives here)
    def run(self) -> None:
        self.t0 = time.monotonic()
        self.graph.set_root(self.start_url)
        self.emit("auto", True)
        self.emit("status", ("Resuming quick scan: " if self.resuming else "Quick scan started: ") + self.start_url)
        if not self.auth.empty:
            self.emit("status", "Using your login (" + self.auth.describe() + "); logout links are skipped.")
        if not self.opts.verify_tls:
            self.emit("status", "HTTPS certificates are not being verified (the TLS check still reports problems).")
        if not self.opts.ignore_robots:
            self.pacer.floor = min(self.robots.crawl_delay(self.start_url), 30.0)
        limit_hit = ""
        try:
            if not self.resuming:
                self._discover()
            with ThreadPoolExecutor(max_workers=self.opts.concurrency, thread_name_prefix="scan") as ex:
                pending: dict = {}
                while not self.stop_event.is_set():
                    if self.opts.max_duration and time.monotonic() - self.t0 > self.opts.max_duration:
                        limit_hit = "time limit"
                        break
                    while len(pending) < self.opts.concurrency:
                        item = self.frontier.pop()
                        if item is None:
                            break
                        pending[ex.submit(self._task, *item)] = item
                        self.emit("page", item[0], len(self.frontier.visited), self.opts.max_pages)
                    if not pending:
                        break
                    done, _ = wait(list(pending), timeout=0.2, return_when=FIRST_COMPLETED)
                    for f in done:
                        item = pending.pop(f)
                        try:
                            self._process(*f.result())
                        except Exception as e:  # one bad page must not stop the crawl
                            self.errors += 1
                            self.emit("status", f"Skipped a page after an internal error: {e}")
                    self._progress()
                for f in list(pending):  # let in-flight requests finish (bounded by the timeout)
                    item = pending.pop(f)
                    try:
                        self._process(*f.result(timeout=self.opts.timeout * 3 + 5))
                    except Exception:
                        pass
                if self.opts.check_external and not self.stop_event.is_set() and not limit_hit:
                    self._check_external(ex)
        finally:
            self._finish(limit_hit)

    def _process(self, url: str, depth: int, parent: str | None, r: "Fetched", parsed, rendered=None) -> None:
        if r.error == "stopped":
            self.frontier.visited.discard(fr.normalize(url))  # never fetched: put it back so a resume does it
            self.frontier.push(url, depth, parent)
            return
        self.pages += 1
        final = r.final_url or url
        for hop, code in r.chain:                       # record redirects as pages that point on to the next URL
            self.graph.visit(hop, depth, code)
            self.graph.link(hop, final, "internal")
        if parent:
            self.graph.link(parent, url, "internal")
        title = parsed.title if parsed else ""
        self.graph.visit(final, depth, r.status, title)
        if r.status in (401, 403) and not r.error:
            self._restricted(final, r)
        elif r.error or r.status == 0 or r.status >= 400:
            self.errors += 1
            self.emit("broken", final, r.status, parent or "", reason_for(r))
        if urlparse(final).scheme in ("http", "https") and r.headers:
            findings, shown = analysis.check_headers(final, r.headers, r.status)
            if r.body:
                findings = findings + checks.analyze_html(final, r.body)
                self.info.add_tech(checks.fingerprint(r.headers, r.body), final)
            else:
                self.info.add_tech(checks.fingerprint(r.headers, ""), final)
            if rendered is not None and rendered.html:      # what the page looks like once its JavaScript has run
                known = {(f.code, f.detail) for f in findings}
                findings = findings + [f for f in checks.analyze_html(final, rendered.html) if (f.code, f.detail) not in known]
                self.info.add_tech(checks.fingerprint([], rendered.html), final)
            self.info.add_forms(checks.extract_forms(final, r.body))
            seen_html = rendered.html if rendered is not None and rendered.html else r.body
            if rendered is not None and rendered.html:
                self.info.add_forms(checks.extract_forms(final, rendered.html))
            self.graph.set_content(final, *content.fingerprint(seen_html))
            self.info.add_scripts(final, content.script_hosts(final, seen_html))
            for k, v in r.headers:
                if k.lower() in ("content-security-policy", "access-control-allow-origin"):
                    for h in checks.hosts_in_policy(v):
                        self.info.add_host(h, "csp" if k.lower().startswith("content") else "cors", self.start_host)
            sec = analysis.PageSecurity(final, r.status, findings, shown)
            self.security[final] = sec
            self.emit("security", sec)
        if not parsed:
            return
        base = urljoin(final, parsed.base) if parsed.base else final
        in_scope_here = fr.in_scope(fr.normalize(final), self.frontier.root, self.opts.scope)
        links = list(parsed.links)
        if rendered is not None:
            self.rendered += 1
            self.graph.mark_rendered(final)
            if self.rendered == 1:
                self.emit("status", f"Rendering in a browser: {rendered.why} ({final}).")
            links += [l for l in rendered.links]
            if rendered.base and rendered.base != final:
                base = rendered.base
        for l in links:
            absu = wc.resolve(l["href"], base)
            if not absu:
                continue
            kind = wc.classify(absu, final)
            self.graph.link(final, absu, kind)
            res = self.store.add({"href": absu, "text": l["text"], "rel": l["rel"], "page": final})
            if res and res[0]:
                findings = analysis.assess_link(res[1].href, res[1].kind, final, l["rel"])
                self.graph.set_risk(res[1].href, analysis.risk_score(findings))
                self.info.add_params(res[1].href)
                self.info.add_host(urlparse(absu).hostname or "", "link", self.start_host)
                self.emit("link", res[1], findings)
            if in_scope_here and kind == "internal":
                self.frontier.push(absu, depth + 1, final)

    def _restricted(self, url: str, r: "Fetched") -> None:
        """A page that wants a login (401) or refuses us (403) is not a broken link: it is part of the site's attack surface."""
        challenge = next((v for k, v in r.headers if k.lower() == "www-authenticate"), "")
        scheme = challenge.split(" ", 1)[0] if challenge else ""
        self.info.add_finding(analysis.Finding("restricted", "info", f"Restricted page (HTTP {r.status}" + (f", {scheme} authentication" if scheme else "") + ")",
                                               "Part of the attack surface: check what it protects"), url)
        if r.status == 401 and scheme.lower() == "basic" and urlparse(url).scheme == "http":
            self.info.add_finding(analysis.Finding("basic-auth-http", "high", "HTTP Basic authentication over an unencrypted connection",
                                                   "The username and password are sent in clear text (base64 is not encryption)"), url)

    def _check_external(self, ex) -> None:
        urls = []
        for l in self.store.all():
            if l.kind == "external" and urlparse(l.href).scheme in ("http", "https") and l.href not in urls:
                urls.append(l.href)
        urls = urls[:300]
        if not urls:
            return
        self.emit("status", f"Checking {len(urls)} external link(s)…")

        def head(u):
            r = self._fetch_paced(u, "HEAD")
            if r.status in (403, 405, 501) and not r.error:
                r = self._fetch_paced(u, "GET")
            return u, r
        futs = [ex.submit(head, u) for u in urls]
        for f in futs:
            if self.stop_event.is_set():
                break
            try:
                u, r = f.result(timeout=self.opts.timeout * 3 + 10)
            except Exception:
                continue
            if r.error == "stopped":
                continue
            self.graph.set_status(u, r.status)
            if r.error or r.status == 0 or r.status >= 400:
                self.errors += 1
                src = next((p for (p, d) in self.graph.edges if d == fr.normalize(u)), "")
                self.emit("broken", u, r.status, src, reason_for(r))
            self._progress()

    def _progress(self) -> None:
        el = max(time.monotonic() - self.t0, 0.001)
        self.emit("progress", {"pages": self.pages, "queued": len(self.frontier), "errors": self.errors, "links": len(self.store),
                               "elapsed": el, "rps": self.pages / el})

    def _finish(self, limit_hit: str) -> None:
        el = time.monotonic() - self.t0
        net = self.client.stats
        self.client.close()
        if self.renderer is not None:
            self.renderer.close()
        if self.opts.resolve_hosts and not self.stop_event.is_set():
            self.info.resolve_hosts()
        self.resume_state = self.frontier.to_state()
        done = not len(self.frontier) and not self.stop_event.is_set() and not limit_hit
        if done and self.opts.use_sitemap:
            for u in self.graph.orphans():
                n = self.graph.nodes.get(u)
                if n and n.visited and (n.status or 0) < 400:
                    self.info.add_finding(analysis.Finding("orphan-page", "low", "Page is in the sitemap but nothing links to it", "Forgotten or unlisted content is a common recon find"), u)
        blocked = self.responses >= 3 and self.refused / self.responses >= 0.5
        self.summary = {"pages": self.pages, "links": len(self.store), "errors": self.errors, "seconds": el,
                        "stopped": self.stop_event.is_set(), "limit": limit_hit, "skipped": dict(self.frontier.skipped), "net": net,
                        "throttled": self.throttled, "blocked": blocked, "rendered": self.rendered,
                        "resumable": not done and (len(self.frontier) > 0 or self.stop_event.is_set() or bool(limit_hit))}
        why = "stopped" if self.stop_event.is_set() else (f"{limit_hit} reached" if limit_hit else "finished")
        self._progress()
        eff = f" ({net['requests']} requests on {net['connections']} connection(s), {net['bytes'] / 1024:.0f} KB received)" if net["requests"] else ""
        if self.rendered:
            eff += f"; {self.rendered} page(s) rendered in a browser"
        self.emit("status", f"Quick scan {why}: {self.pages} page(s), {len(self.store)} links, {self.errors} problem(s) in {el:.1f}s{eff}.")
        if blocked:
            self.emit("status", "The site is refusing this crawler (mostly 403/429). If it is yours, allow the user agent in its firewall, "
                                "or use --user-agent chrome. Otherwise respect the refusal.")
        self.emit("scan_done", self.summary)
        self.emit("auto", False)  # last, so anyone waiting for "scan finished" has already seen the summary
