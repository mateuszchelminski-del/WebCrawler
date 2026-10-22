#!/usr/bin/env python3
"""webcrawler.py: summon an animated crawler on any page, in the browser you already use.

It opens a real browser window (Chrome, Edge, Firefox, Chromium or WebKit), draws a crawler over the page and
captures every link that scrolls into view, then writes the results to JSON, CSV and TXT. It can also scroll by
itself (--auto), run headless, and follow same-site links to a chosen depth.

    python webcrawler.py https://example.com                      # interactive: you scroll, the crawler captures
    python webcrawler.py https://example.com --auto               # the crawler scrolls the page for you
    python webcrawler.py ./test-site/index.html --browser edge    # local files work too
    python webcrawler.py https://example.com --auto --headless --depth 2 --max-pages 30

Only crawl sites you own or have permission to test. robots.txt is respected when following links (--ignore-robots
turns that off for sites you control).
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import queue
import re
import sys
import threading
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from urllib import robotparser
from urllib.parse import urldefrag, urlparse, urljoin

import analysis
import version

HERE = Path(__file__).resolve().parent
KINDS = ("internal", "external", "anchor", "mailto", "tel", "file", "other")
SKINS = ("sentinel", "hacker", "spider", "packet", "lock", "drone", "radar", "bot")
FILE_EXT = re.compile(r"\.(pdf|zip|gz|tar|7z|rar|exe|msi|dmg|iso|docx?|xlsx?|pptx?|csv|txt|png|jpe?g|gif|svg|webp|mp3|mp4|mov|webm)$", re.I)

# name -> (playwright engine, installed-browser channel or None for the bundled build)
BROWSERS = {
    "chrome": ("chromium", "chrome"),
    "edge": ("chromium", "msedge"),
    "chromium": ("chromium", None),
    "firefox": ("firefox", None),
    "webkit": ("webkit", None),
}
AUTO_ORDER = ("chrome", "edge", "chromium", "firefox")


# --------------------------------------------------------------------------- pure logic (no browser needed)

def normalize_target(arg: str) -> str:
    """Turn a URL, a bare domain or a local path into a URL the browser can open."""
    arg = arg.strip()
    p = Path(arg).expanduser()
    if arg and p.exists():
        return p.resolve().as_uri()
    if not re.match(r"^[a-z][a-z0-9+.-]*:", arg, re.I):
        arg = "https://" + arg
    u = urlparse(arg)
    if u.scheme not in ("http", "https", "file") or (u.scheme != "file" and not u.netloc):
        raise ValueError(f"cannot crawl {arg!r}: only http(s) URLs and local files are supported")
    return arg


def serve_local(file_url: str):
    """A quick scan speaks HTTP, so a local file or folder is served on 127.0.0.1 for the length of the scan. Returns (start URL, server)."""
    import functools
    import http.server
    from urllib.parse import unquote
    from urllib.request import url2pathname
    path = Path(url2pathname(unquote(urlparse(file_url).path)))
    root, name = (path, "") if path.is_dir() else (path.parent, path.name)
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    handler.log_message = lambda *a, **k: None
    class Server(http.server.ThreadingHTTPServer):
        request_queue_size = 128            # parallel connections from the scanner must not overflow the default backlog of 5

    srv = Server(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}/{name}", srv


def decode_cf_email(hexstr: str) -> str:
    """Cloudflare's e-mail address protection hides an address as hex: the first byte is an XOR key for the rest."""
    try:
        data = bytes.fromhex(hexstr)
        key = data[0]
        return bytes(b ^ key for b in data[1:]).decode("utf-8")
    except (ValueError, IndexError, UnicodeDecodeError):
        return ""


def resolve(raw: str, base: str) -> str | None:
    """Absolute URL for a raw href, or None for things that are not links (javascript:, data:, empty).
    Cloudflare's obfuscated e-mail links (/cdn-cgi/l/email-protection#<hex>) come back as the mailto: link they stand for."""
    raw = (raw or "").strip()
    if not raw or re.match(r"^(javascript|data|vbscript|blob):", raw, re.I):
        return None
    try:
        url = urljoin(base, raw)
    except ValueError:
        return None
    m = re.search(r"/cdn-cgi/l/email-protection#([0-9a-fA-F]{6,})$", url)
    if m:
        addr = decode_cf_email(m.group(1))
        return "mailto:" + addr if addr else None
    return url


def classify(url: str, page_url: str) -> str:
    u, p = urlparse(url), urlparse(page_url)
    if u.scheme == "mailto":
        return "mailto"
    if u.scheme == "tel":
        return "tel"
    if u.scheme not in ("http", "https", "file"):
        return "other"
    if (u.scheme, u.netloc, u.path, u.query) == (p.scheme, p.netloc, p.path, p.query) and u.fragment:
        return "anchor"
    if FILE_EXT.search(u.path):
        return "file"
    if u.scheme == "file" and p.scheme == "file":
        return "internal"
    return "internal" if (u.scheme, u.netloc.lower()) == (p.scheme, p.netloc.lower()) else "external"


@dataclass
class Link:
    n: int
    href: str
    text: str
    kind: str
    host: str
    count: int
    nofollow: bool
    page: str


class LinkStore:
    """De-duplicated, ordered collection of captured links. Thread-safe (browser callbacks vs. the main loop)."""

    def __init__(self) -> None:
        self._links: dict[str, Link] = {}
        self._lock = threading.Lock()

    def add(self, rec: dict) -> tuple[bool, Link] | None:
        page = rec.get("page") or ""
        href = resolve(rec.get("href", ""), page or "about:blank")
        if not href:
            return None
        text = re.sub(r"\s+", " ", str(rec.get("text") or "")).strip()[:120]
        with self._lock:
            hit = self._links.get(href)
            if hit:
                hit.count += 1
                if not hit.text and text:
                    hit.text = text
                return False, hit
            link = Link(len(self._links) + 1, href, text, classify(href, page), urlparse(href).netloc,
                        1, bool(re.search(r"\bnofollow\b", rec.get("rel") or "", re.I)), page)
            self._links[href] = link
            return True, link

    def __len__(self) -> int:
        return len(self._links)

    def clear(self) -> None:
        with self._lock:
            self._links.clear()

    def load(self, rows: list[dict]) -> None:
        """Replace the contents with links saved earlier (see snapshot.py), keeping their numbers."""
        with self._lock:
            self._links = {r["href"]: Link(int(r["n"]), r["href"], r.get("text", ""), r.get("kind", "other"), r.get("host", ""),
                                           int(r.get("count", 1)), bool(r.get("nofollow", False)), r.get("page", "")) for r in rows}

    def all(self) -> list[Link]:
        with self._lock:
            return list(self._links.values())

    def stats(self) -> dict:
        by = {k: 0 for k in KINDS}
        hosts = set()
        for l in self.all():
            by[l.kind] += 1
            if l.kind == "external" and l.host:
                hosts.add(l.host)
        return {"total": len(self), "by_kind": by, "external_hosts": len(hosts)}


def _cell(v) -> str:
    s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s  # stop spreadsheets running a link's text as a formula


def to_csv(links: list[Link]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["#", "url", "text", "type", "host", "seen", "nofollow", "found_on", "risk", "findings"])
    for l in links:
        f = analysis.assess_link(l.href, l.kind, l.page)
        w.writerow([l.n, _cell(l.href), _cell(l.text), l.kind, l.host, l.count, "yes" if l.nofollow else "no", l.page,
                    analysis.rating(analysis.risk_score(f)), "; ".join(x.title for x in f)])
    return buf.getvalue()


def to_json(links: list[Link], start_url: str) -> str:
    rows = []
    for l in links:
        f = analysis.assess_link(l.href, l.kind, l.page)
        rows.append({**asdict(l), "risk": analysis.rating(analysis.risk_score(f)), "risk_score": analysis.risk_score(f),
                     "findings": [{"code": x.code, "severity": x.severity, "title": x.title, "detail": x.detail} for x in f]})
    return json.dumps({"start": start_url, "count": len(links), "links": rows}, indent=2)


def to_txt(links: list[Link]) -> str:
    return "".join(l.href + "\n" for l in links)


def same_site(url: str, root: str) -> bool:
    """Is url on the same site as the start page? Local files must live under the start file's folder."""
    u, r = urlparse(url), urlparse(root)
    if u.scheme != r.scheme:
        return False
    if u.scheme == "file":
        return u.path.startswith(r.path.rsplit("/", 1)[0] + "/")
    return u.netloc.lower() == r.netloc.lower()


class Robots:
    """robots.txt checks, cached per origin. If robots.txt cannot be read (404, 403, timeout...) the site is treated as open.

    Python's own RobotFileParser.read() treats a 401/403 as "everything is forbidden", which wrongly blocks sites that merely
    refuse unknown clients, so the file is fetched here and only parsed by the standard library.
    """

    def __init__(self, enabled: bool = True, agent: str = "*", timeout: float = 8.0, verify_tls: bool = True) -> None:
        self.enabled, self.ua, self.timeout, self.verify_tls, self._cache = enabled, agent, timeout, verify_tls, {}
        self.agent = "*" if agent == "*" else (re.split(r"[/\s]", agent.strip())[0] or "*")  # product token, e.g. "WebCrawler"

    def _parser(self, url: str):
        u = urlparse(url)
        if not self.enabled or u.scheme not in ("http", "https"):
            return False
        origin = f"{u.scheme}://{u.netloc}"
        rp = self._cache.get(origin)
        if rp is None:
            rp = self._cache[origin] = self._load(origin)
        return rp

    def _load(self, origin: str):
        import httpclient
        r = httpclient.get(origin + "/robots.txt", self.ua, self.timeout, 512 * 1024, verify_tls=self.verify_tls)
        if r.error or r.status != 200:
            return False       # 404, 403, a timeout...: nothing is forbidden
        rp = robotparser.RobotFileParser()
        rp.parse(httpclient.decode_text(r.body, r.header("Content-Type")).splitlines())
        return rp

    def allowed(self, url: str) -> bool:
        rp = self._parser(url)
        return True if rp is False else rp.can_fetch(self.agent, url)

    def crawl_delay(self, url: str) -> float:
        rp = self._parser(url)
        if rp is False:
            return 0.0
        d = rp.crawl_delay(self.agent)
        return float(d) if d else 0.0


def follow_candidates(links: list[Link], page_url: str, root: str, visited: set[str], robots: Robots) -> list[str]:
    """Same-site pages linked from page_url that have not been visited yet, in the order they were found."""
    out, seen = [], set()
    for l in links:
        if l.page != page_url or l.kind != "internal":
            continue
        target = urldefrag(l.href)[0]
        if target in visited or target in seen or not same_site(target, root) or not robots.allowed(target):
            continue
        seen.add(target)
        out.append(target)
    return out


# --------------------------------------------------------------------------- browser driving

def overlay_script(skin: str, mode: str, summoned: bool) -> str:
    cfg = json.dumps({"skin": skin, "mode": mode, "summoned": summoned})
    return f"window.__WC_CONFIG = {cfg};\n" + (HERE / "overlay.js").read_text(encoding="utf-8")


def _playwright():
    try:
        from playwright.sync_api import Error as PWError, sync_playwright
    except ImportError:
        sys.exit("Playwright is not installed. Run:  pip install -r requirements.txt")
    return sync_playwright, PWError


def _playwright_or_raise():
    """Like _playwright() but raises instead of exiting, for use from a GUI thread."""
    try:
        from playwright.sync_api import Error as PWError, sync_playwright
    except ImportError:
        raise RuntimeError("Playwright is not installed. Run:  pip install -r requirements.txt")
    return sync_playwright, PWError


def launch(pw, name: str, headless: bool, profile: str | None, ignore_https_errors: bool = False, user_agent: str | None = None):
    """(browser, context) for one named browser. Raises Playwright's Error if it cannot start."""
    engine_name, channel = BROWSERS[name]
    engine = getattr(pw, engine_name)
    kwargs: dict = {"headless": headless}
    if channel:
        kwargs["channel"] = channel
    if engine_name == "chromium" and not headless:
        kwargs["args"] = ["--start-maximized"]
    view: dict = {"viewport": {"width": 1280, "height": 800}} if headless else {"no_viewport": True}
    if ignore_https_errors:
        view["ignore_https_errors"] = True
    if user_agent:
        view["user_agent"] = user_agent
    if profile:
        if engine_name != "chromium":
            raise RuntimeError("A saved profile only works with Chrome, Edge or Chromium.")
        return None, engine.launch_persistent_context(profile, **kwargs, **view)
    browser = engine.launch(**kwargs)
    return browser, browser.new_context(**view)


def launch_any(pw, wanted: str, headless: bool, profile: str | None, PWError, **kw):
    """(name, browser, context) for the requested browser, or for the first of chrome, edge, chromium, firefox that starts when
    wanted is "auto". Raises RuntimeError with advice if none can."""
    if wanted == "auto" and os.environ.get("WEBCRAWLER_BROWSER", "").strip().lower() in BROWSERS:
        wanted = os.environ["WEBCRAWLER_BROWSER"].strip().lower()           # a default browser without typing --browser every time
    order = AUTO_ORDER if wanted == "auto" else (wanted,)
    last = None
    if profile and wanted != "auto" and BROWSERS[wanted][0] != "chromium":
        raise RuntimeError("A saved profile only works with Chrome, Edge or Chromium.")
    for name in order:
        if profile and BROWSERS[name][0] != "chromium":
            continue
        try:
            browser, ctx = launch(pw, name, headless, profile, **kw)
            return name, browser, ctx
        except PWError as e:
            last = e
            if wanted != "auto":
                engine, channel = BROWSERS[name]
                hint = (f"run: python -m playwright install {engine}" if channel is None
                        else f"install {name.capitalize()}, or pick Chromium after: python -m playwright install chromium")
                raise RuntimeError(f"Could not start {name}: {str(e).splitlines()[0]}\n{hint}")
    raise RuntimeError("No usable browser found. Install Chrome or Edge, or run: python -m playwright install chromium"
                       + (f"\n({str(last).splitlines()[0]})" if last else ""))


def build_options(args, base=None):
    """CrawlOptions from the command line. Start from a saved session's options (resume) or a preset, then apply every explicit flag."""
    import frontier as fr
    if base is not None:
        o = base
    elif args.preset:
        o = fr.with_preset(args.preset)
    else:
        o = fr.CrawlOptions()
    if args.depth is not None:
        o.depth = args.depth
    elif base is None:
        o.depth = 2 if args.quick else 0
    if args.max_pages is not None:
        o.max_pages = args.max_pages
    elif base is None:
        o.max_pages = 25
    if args.delay is not None:
        o.delay_min = o.delay_max = args.delay
    if args.delay_min is not None:
        o.delay_min = args.delay_min
    if args.delay_max is not None:
        o.delay_max = args.delay_max
    if args.delay_min is not None and args.delay_max is None and o.delay_max < o.delay_min:
        o.delay_max = o.delay_min
    for flag, attr in (("max_rps", "max_rps"), ("concurrency", "concurrency"), ("timeout", "timeout"), ("max_duration", "max_duration"),
                       ("scope", "scope"), ("strategy", "strategy"), ("user_agent", "user_agent"), ("speed", "scroll_speed")):
        v = getattr(args, flag)
        if v is not None:
            setattr(o, attr, v)
    if args.include:
        o.include = list(args.include)
    if args.exclude:
        o.exclude = list(args.exclude)
    if args.ignore_robots:
        o.ignore_robots = True
    if args.check_external:
        o.check_external = True
    if args.no_sitemap:
        o.use_sitemap = False
    if args.probe_files:
        o.probe_files = True
    if args.no_tls:
        o.check_tls = False
    if args.dns:
        o.check_dns = True
    if args.subdomains:
        o.check_ct = True
    if args.ct_url:
        o.check_ct, o.ct_url = True, args.ct_url
    if args.doh:
        o.check_dns, o.doh_url = True, args.doh
    if args.insecure:
        o.verify_tls = False
    if args.render:
        o.render = args.render
    if args.render_limit is not None:
        o.render_limit = args.render_limit
    if args.max_variants is not None:
        o.max_query_variants = args.max_variants
    o.user_agent = fr.UA_ALIASES.get((o.user_agent or "").lower(), o.user_agent)   # --user-agent chrome | firefox | edge
    try:
        fr.compile_patterns(o.include + o.exclude)
    except re.error as e:
        raise ValueError(f"bad --include/--exclude pattern: {e}")
    return o.clamped()


def build_auth(args, start: str):
    """A login from --cookie / --cookie-file / --header, or the WEBCRAWLER_COOKIE and WEBCRAWLER_HEADERS environment variables
    (which keep secrets out of your shell history and the process list)."""
    import os
    import auth as authmod
    host = urlparse(start).hostname or ""
    cookie = args.cookie or os.environ.get("WEBCRAWLER_COOKIE", "")
    headers = list(args.header or []) + [h for h in os.environ.get("WEBCRAWLER_HEADERS", "").splitlines() if h.strip()]
    return authmod.AuthConfig.build(cookie=cookie, cookie_file=args.cookie_file or "", headers=headers, domain=host)


def _print_event(ev: tuple, quiet: bool) -> None:
    kind = ev[0]
    if kind == "link" and not quiet:
        l = ev[1]
        print(f"  #{l.n:<4} {l.kind:<8} {l.href}" + (f"   ({l.text})" if l.text else ""))
    elif kind == "page":
        print(f"[{ev[2]}/{ev[3]}] {ev[1]}")
    elif kind == "broken":
        print(f"  ! {ev[4]}  {ev[1]}" + (f"   (linked from {ev[3]})" if ev[3] else ""))
    elif kind == "status" and not quiet:
        print(ev[1])


def run(args) -> int:
    import graph as gr
    import checks
    import snapshot
    resume_data = snapshot.load(args.resume) if args.resume else None
    if args.target:
        start = normalize_target(args.target)
    elif resume_data:
        start = resume_data["start"]
    else:
        raise ValueError("give a URL or local file to crawl")
    opts = build_options(args, snapshot.options_from(resume_data) if resume_data else None)
    login = build_auth(args, start)
    store, site, info = LinkStore(), gr.SiteGraph(), checks.SiteInfo()
    broken: list = []
    pages: dict = {}
    resume_state = None
    if resume_data:
        broken, resume_state = snapshot.restore(resume_data, store, site, pages, info)
        if resume_state is None:
            print("That session finished normally, so there is nothing to resume: crawling again from the start page with the same options.")
        else:
            print(f"Resuming {start}: {len(resume_state.get('queue', []))} page(s) were waiting, {len(resume_state.get('visited', []))} already done.")

    def pump(ev):
        if ev[0] == "broken":
            broken.append(ev[1:])
        elif ev[0] == "security":
            pages[ev[1].url] = ev[1]
        _print_event(ev, args.quiet)

    if not login.empty:
        print("Using your login (" + login.describe() + "); logout links are skipped, and credentials go only to " + (urlparse(start).hostname or "the site") + ".")
    state: dict | None = None
    local_server = None
    if args.quick and start.startswith("file:"):
        start, local_server = serve_local(start)
        print(f"A quick scan speaks HTTP, so the local files are served at {start} while it runs.")
    if args.quick:
        import httpscan
        events: queue.Queue = queue.Queue()
        scanner = httpscan.QuickScanner(start, opts, store, site, events, pages, info, login, resume_state)
        print(f"Quick scan of {start}  (no browser, {opts.concurrency} parallel, pause {opts.delay_min:g}-{opts.delay_max:g}s, depth {opts.depth})")
        scanner.start()
        try:
            while scanner.is_alive() or not events.empty():
                try:
                    pump(events.get(timeout=0.2))
                except queue.Empty:
                    pass
        except KeyboardInterrupt:
            print("\nInterrupted: finishing the requests in flight...")
            scanner.stop()
            scanner.join(timeout=opts.timeout + 5)
        state = scanner.resume_state if scanner.summary.get("resumable") else None
        try:
            return finish(store, start, args, list(pages.values()), broken, site, info, opts, state)
        finally:
            if local_server is not None:
                local_server.shutdown()
                local_server.server_close()

    import engine as eng
    e = eng.Engine(store, site, info)
    e.start()
    e.send("start", settings=eng.Settings(url=start, browser=args.browser, headless=args.headless, skin=args.skin, mode=args.mode, summoned=not args.no_summon,
                                          profile=args.profile, auto=args.auto, opts=opts, auth=login, resume=resume_state))
    if not args.auto:
        print(f"Opening {start}\nScroll the page; links that come into view are captured. Close the browser window (or Ctrl+C) to finish.\n"
              "In the page: Alt+Shift+C summon/dismiss, Alt+Shift+S change look, Alt+Shift+M switch capture mode.\n")
    code, running = 0, False
    try:
        while True:
            try:
                ev = e.events.get(timeout=0.2)
            except queue.Empty:
                if not e.is_alive():
                    break
                continue
            pump(ev)
            if ev[0] == "browser":
                if ev[1] == "error":
                    print(ev[2], file=sys.stderr)
                    code = 2
                    break
                if ev[1] == "running":
                    running = True
                    print(f"Browser: {ev[2].replace(' is open', '')}")
                elif ev[1] == "closed" and running:
                    break
            elif ev[0] == "scan_done" and args.auto:
                break
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        e.send("quit")
        e.join(timeout=15)
    if code:
        return code
    state = e.resume_state if e.last_summary.get("resumable") else None
    return finish(store, start, args, list(pages.values()) or list(e.security.values()), broken, site, info, opts, state)


def finish(store: LinkStore, start: str, args, pages=None, broken=None, site=None, info=None, opts=None, resume=None) -> int:
    import snapshot
    links = store.all()
    st = store.stats()
    print(f"\nCaptured {st['total']} unique links: " + ", ".join(f"{k} {v}" for k, v in st["by_kind"].items() if v)
          + (f"; {st['external_hosts']} external host(s)" if st["external_hosts"] else ""))
    if site is not None:
        g = site.stats()
        print(f"Site map: {g['pages']} page(s), {g['edges']} link(s)" + (f", {g['broken']} broken page(s)" if g["broken"] else ""))
    if info is not None and info.findings:
        n = {}
        for f, _ in info.findings:
            n[f.severity] = n.get(f.severity, 0) + 1
        print("Site-wide findings: " + ", ".join(f"{v} {k}" for k, v in sorted(n.items(), key=lambda kv: analysis.SEVERITIES.index(kv[0]))))
    if info is not None and (info.forms or info.params or info.hosts):
        print(f"Inputs: {len(info.forms)} form(s), {len(info.params)} URL parameter(s), {len(info.hosts)} related host name(s)")
    if broken:
        print(f"{len(broken)} broken link(s)/page(s) found (see report.html)")
    if resume:
        print("The crawl was not finished: it can be continued with --resume session.json")
    if not links and not (site and site.nodes):
        print("Nothing captured, so nothing was written.")
        return 1
    host = re.sub(r"[^A-Za-z0-9._-]+", "_", urlparse(start).netloc or Path(urlparse(start).path).stem or "page")
    out = Path(args.out) if args.out else Path("crawl-results") / f"{host}_{datetime.now():%Y%m%d-%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    import report
    sitedict = info.to_dict() if info is not None else None
    acc = _accepted(args)
    maker = {"json": ("links.json", lambda: to_json(links, start)), "csv": ("links.csv", lambda: to_csv(links)), "txt": ("links.txt", lambda: to_txt(links)),
             "html": ("report.html", lambda: report.build_html(start, links, pages, broken, site.stats() if site else None, sitedict, acc))}
    if site is not None:
        import graph as gr
        maker["map"] = ("sitemap.html", lambda: gr.to_html(site, "Site map: " + start))
        maker["graph"] = ("graph.json", site.to_json)
    data = None
    if site is not None and opts is not None:
        data = snapshot.build(start, opts, store, site, {p.url: p for p in (pages or [])}, broken or [], info, resume)
    if data is not None:
        import sarif
        maker["sarif"] = ("results.sarif", lambda: sarif.to_json(data, acc, args.sarif_prefix or ""))
        maker["junit"] = ("junit.xml", lambda: sarif.junit(data, acc))
    for f in args.format:
        if f in maker:
            fname, make = maker[f]
            (out / fname).write_text(make(), encoding="utf-8", newline="")
            print(f"Wrote {out / fname}")
        elif f in ("sarif", "junit"):
            print(f"Skipped {f}: it needs a crawl that followed links (use --quick, or --auto with --depth).")
    if data is not None:
        open_, done = acc.split(snapshot.all_findings(data)) if acc else (snapshot.all_findings(data), [])
        counts = {s: sum(1 for f in open_ if f["severity"] == s) for s in ("high", "medium", "low")}
        print("Open findings: " + (", ".join(f"{v} {k}" for k, v in counts.items() if v) or "none") + (f"  ({len(done)} accepted, not counted)" if done else ""))
        path = Path(args.save) if args.save else out / "session.json"
        if args.save or "session" in args.format:
            snapshot.save(str(path), data)
            print(f"Wrote {path}")
        change = None
        code = 0
        if args.compare:
            old = snapshot.load(args.compare)
            code = report_diff(old, data, args, out)
            change = snapshot.diff(old, data, acc)
        if args.fail_on and not code:
            rank = ("high", "medium", "low")
            bad = [f for f in open_ if f["severity"] in rank[:rank.index(args.fail_on) + 1]]
            if bad:
                print(f"{len(bad)} open finding(s) at {args.fail_on} or above: exiting with status 3.", file=sys.stderr)
                code = 3
        if args.history:
            import history
            h = history.History.load(args.history)
            h.add(history.summarize(data, acc, change), start)
            h.save(args.history)
            (out / "trend.html").write_text(history.trend_html(h), encoding="utf-8", newline="")
            print(f"Wrote {out / 'trend.html'}  ({len(h.runs)} crawl(s) in {args.history}; open problems are {h.direction()})")
        return code
    return 0


def _accepted(args):
    """The accepted-findings file given with --accepted, or None. Raises ValueError for a file that cannot be read."""
    import accepted
    path = getattr(args, "accepted", None) or os.environ.get("WEBCRAWLER_ACCEPTED", "")
    a = accepted.Accepted.load(path) if path else None
    return a if a else None


def accept_command(args) -> int:
    """--accept / --unaccept: edit the accepted-findings file and exit."""
    import accepted
    if not args.accepted:
        print("Say which file to keep the accepted findings in: --accepted accepted.json", file=sys.stderr)
        return 2
    a = accepted.Accepted.load(args.accepted)
    if args.unaccept:
        removed = a.remove(args.unaccept, args.where or "*")
        print(("Removed" if removed else "Nothing to remove for") + f" {args.unaccept} @ {args.where or '*'}")
    else:
        e = a.add(args.accept, args.where or "*", args.reason or "", args.expires or "")
        print(f"Accepted {e['code']} @ {e['where']}" + (f" until {e['expires']}" if e["expires"] else " (no expiry)") + (f": {e['reason']}" if e["reason"] else ""))
        if not e["reason"]:
            print("Tip: add --reason so the next person knows why this is fine.")
    a.save(args.accepted)
    print(f"Saved {args.accepted} ({len(a)} accepted).")
    return 0


def report_diff(old: dict, new: dict, args, out: Path | None) -> int:
    """Print what changed between two sessions, write changes.html / changes.json, and return the exit code (3 = regressions)."""
    import json as _json
    import report
    import snapshot
    d = snapshot.diff(old, new, _accepted(args))
    print("\n" + d.to_text(limit=0 if args.verbose else 15))
    if out is not None:
        out.mkdir(parents=True, exist_ok=True)
        (out / "changes.html").write_text(report.build_diff_html(d), encoding="utf-8", newline="")
        (out / "changes.json").write_text(_json.dumps(d.to_dict(), indent=2), encoding="utf-8", newline="")
        print(f"Wrote {out / 'changes.html'}")
    level = args.fail_on_regression
    if level and d.regressions(level):
        print(f"{len(d.regressions(level))} regression(s) at {level} or above: exiting with status 3.", file=sys.stderr)
        return 3
    return 0


def print_schedule(args, argv) -> int:
    """--print-schedule: show how to run this monitor every day. Prints only; creates no task."""
    import monitor
    if not args.monitor:
        print("--print-schedule is for monitor runs: add --monitor DIR (and the options you want).", file=sys.stderr)
        return 2
    try:
        cmds = monitor.schedule_commands(list(sys.argv[1:] if argv is None else argv), args.print_schedule, sys.executable, str(Path(__file__).resolve()), os.getcwd())
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    print(f"Nothing has been scheduled. These lines run this same monitor every day at {args.print_schedule}:\n")
    print('Windows (run once in a Command Prompt; remove later with: schtasks /Delete /TN "WebCrawler monitor"):\n  ' + cmds["windows"] + "\n")
    print("Linux / macOS (add with: crontab -e):\n  " + cmds["cron"] + "\n")
    if cmds["dropped"]:
        print("Left out on purpose, because a task definition is not a safe place for secrets: " + ", ".join(cmds["dropped"])
              + ". Set " + ", ".join(sorted(set(cmds["dropped"].values()))) + " in the task's environment instead.")
    print("A scheduled run has no one to type secrets, so pass them through the environment of the task: WEBCRAWLER_COOKIE, WEBCRAWLER_WEBHOOK, WEBCRAWLER_SMTP_PASSWORD.")
    print("For GitHub Actions use docs/examples/monitor.yml.")
    return 0


def list_browsers() -> int:
    sync_playwright, PWError = _playwright()
    with sync_playwright() as pw:
        for name, (engine, channel) in BROWSERS.items():
            try:
                kw = {"channel": channel} if channel else {}
                b = getattr(pw, engine).launch(headless=True, **kw)
                v = b.version
                b.close()
                print(f"  {name:<9} available (version {v})")
            except PWError:
                how = "install it normally" if channel else f"python -m playwright install {engine}"
                print(f"  {name:<9} not found  ->  {how}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    import frontier as fr
    p = argparse.ArgumentParser(description="Summon an animated crawler that captures the links on any page, follows them, audits what it finds, and compares crawls over time.",
                                epilog="Only crawl sites you own or have permission to test.")
    p.add_argument("target", nargs="?", help="URL, domain or local HTML file to open (optional with --resume)")
    how = p.add_argument_group("how to crawl")
    how.add_argument("--quick", action="store_true", help="no browser: fetch pages over HTTP, several at once (cannot run JavaScript, much faster)")
    how.add_argument("--auto", action="store_true", help="browser mode: the crawler scrolls by itself and follows links instead of waiting for you")
    how.add_argument("--headless", action="store_true", help="browser mode without a window (needs --auto)")
    how.add_argument("--browser", choices=("auto",) + tuple(BROWSERS), default="auto", help="browser to drive (default: first of chrome, edge, chromium, firefox that works)")
    how.add_argument("--profile", help="folder for a persistent browser profile, so logins are kept (chrome/edge/chromium)")
    reach = p.add_argument_group("how far")
    reach.add_argument("--depth", type=int, help="follow same-site links this many levels deep (default 0 in browser mode, 2 with --quick)")
    reach.add_argument("--max-pages", type=int, help="stop after this many pages (default 25)")
    reach.add_argument("--max-duration", type=float, help="stop after this many seconds")
    reach.add_argument("--scope", choices=("host", "subdomains", "any"), help="which links may be followed (default host)")
    reach.add_argument("--include", action="append", metavar="REGEX", help="only follow URLs matching this (repeatable)")
    reach.add_argument("--exclude", action="append", metavar="REGEX", help="never follow URLs matching this (repeatable)")
    reach.add_argument("--strategy", choices=("bfs", "dfs"), help="bfs = level by level (default), dfs = follow a branch to the end")
    reach.add_argument("--check-external", action="store_true", help="--quick: also check external links for breakage")
    reach.add_argument("--max-variants", type=int, help="crawler-trap guard: follow at most this many different ?query strings per path (default 20, 0 = no limit)")
    pace = p.add_argument_group("how fast")
    pace.add_argument("--preset", choices=tuple(fr.PRESETS), help="stealth / polite / balanced / fast / blitz (flags below override it)")
    pace.add_argument("--delay", type=float, help="fixed pause between requests, in seconds")
    pace.add_argument("--delay-min", type=float, help="random pause between requests: minimum seconds")
    pace.add_argument("--delay-max", type=float, help="random pause between requests: maximum seconds")
    pace.add_argument("--max-rps", type=float, help="never exceed this many requests per second")
    pace.add_argument("--concurrency", type=int, help="--quick: pages downloaded at once")
    pace.add_argument("--timeout", type=float, help="seconds before a request is abandoned")
    pace.add_argument("--speed", type=int, help="browser mode: scroll speed in pixels per second")
    pace.add_argument("--ignore-robots", action="store_true", help="do not consult robots.txt (only for sites you own)")
    pace.add_argument("--user-agent", help="User-Agent header to send; 'chrome', 'firefox' or 'edge' for a browser-like one (a firewall on a site you own may refuse unknown clients)")
    pace.add_argument("--insecure", action="store_true", help="do not verify HTTPS certificates, to crawl self-signed or internal sites (the TLS check still reports the problem)")
    disc = p.add_argument_group("site checks")
    disc.add_argument("--no-sitemap", action="store_true", help="do not read robots.txt / sitemap.xml to find pages nothing links to")
    disc.add_argument("--probe-files", action="store_true", help="request well-known paths (.git, .env, security.txt...): only for sites you own")
    disc.add_argument("--no-tls", action="store_true", help="skip the HTTPS certificate and protocol check")
    disc.add_argument("--dns", action="store_true", help="read the domain's SPF, DMARC, DKIM, CAA and DNSSEC records through Cloudflare's DNS-over-HTTPS (names the domain to that resolver)")
    disc.add_argument("--subdomains", action="store_true", help="list subdomains from public certificate logs (crt.sh) and check that they resolve (names the domain to crt.sh)")
    disc.add_argument("--ct-url", metavar="URL", help="use this certificate-log search instead of crt.sh; {domain} is replaced (implies --subdomains)")
    disc.add_argument("--doh", metavar="URL", help="use this DNS-over-HTTPS resolver for --dns instead of Cloudflare (implies --dns)")
    disc.add_argument("--render", choices=("auto", "never", "always"), help="--quick: render script-built pages in a headless browser: auto judges each page (default), never, always")
    disc.add_argument("--render-limit", type=int, help="--quick: render at most this many pages (default 100)")
    login = p.add_argument_group("logins (a session you already have; nothing is saved)")
    login.add_argument("--cookie", help="cookies to send, as 'name=value; name2=value2' (or set WEBCRAWLER_COOKIE to keep it out of your shell history)")
    login.add_argument("--cookie-file", help="cookies from a file: JSON export, Playwright storage state, or Netscape cookies.txt")
    login.add_argument("--header", action="append", metavar="'Name: value'", help="extra request header, e.g. 'Authorization: Bearer ...' (repeatable; or WEBCRAWLER_HEADERS)")
    mon = p.add_argument_group("saving, resuming and comparing")
    mon.add_argument("--save", metavar="FILE", help="write the session here (default: session.json in the output folder)")
    mon.add_argument("--resume", metavar="FILE", help="continue a session that was stopped before it finished")
    mon.add_argument("--compare", metavar="OLD", help="after crawling, show what changed since this earlier session")
    mon.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"), help="compare two saved sessions and exit")
    mon.add_argument("--fail-on-regression", nargs="?", const="medium", choices=("high", "medium", "low"), help="exit with status 3 if the comparison shows new problems at this level or above (default medium)")
    mon.add_argument("--verbose", action="store_true", help="list every change instead of the first few of each kind")
    acc = p.add_argument_group("accepted findings (things you looked at and decided to live with)")
    acc.add_argument("--accepted", metavar="FILE", help="a JSON file of accepted findings: they are listed apart, not counted, and never reported as new (or set WEBCRAWLER_ACCEPTED)")
    acc.add_argument("--accept", metavar="CODE", help="add a finding to the --accepted file and exit (code as shown in the report, e.g. no-csp; * patterns allowed)")
    acc.add_argument("--unaccept", metavar="CODE", help="remove an entry from the --accepted file and exit")
    acc.add_argument("--where", metavar="GLOB", help="with --accept/--unaccept: the URL or host the entry covers, e.g. 'https://example.com/docs/*' (default: everywhere)")
    acc.add_argument("--reason", help="with --accept: why it is fine")
    acc.add_argument("--expires", metavar="YYYY-MM-DD", help="with --accept: look at it again after this date")
    acc.add_argument("--history", metavar="FILE", help="append this crawl's numbers to a history file and write trend.html next to the results")
    sch = p.add_argument_group("monitoring (scheduled crawls that compare themselves with the last one)")
    sch.add_argument("--monitor", metavar="DIR", help="crawl, compare with the previous crawl kept in DIR, update DIR/history.json and DIR/latest/, and notify if it got worse (see --fail-on-regression)")
    sch.add_argument("--keep", type=int, default=30, metavar="N", help="--monitor: how many sessions to keep (default 30)")
    sch.add_argument("--notify-webhook", metavar="URL", help="--monitor: POST a JSON message here when there are regressions (Slack, Discord, Teams...; or set WEBCRAWLER_WEBHOOK)")
    sch.add_argument("--notify-email", action="append", metavar="ADDRESS", help="--monitor: e-mail this address (repeatable) with the changes report attached; needs --smtp-host")
    sch.add_argument("--smtp-host", metavar="HOST", help="mail server for --notify-email")
    sch.add_argument("--smtp-port", type=int, metavar="PORT", help="default 587 (465 with --smtp-security ssl)")
    sch.add_argument("--smtp-user", metavar="USER", help="log in to the mail server as this user; the password comes from WEBCRAWLER_SMTP_PASSWORD")
    sch.add_argument("--smtp-from", metavar="ADDRESS", help="the From address (default: the SMTP user)")
    sch.add_argument("--smtp-security", choices=("starttls", "ssl", "none"), default="starttls", help="default starttls")
    sch.add_argument("--notify-always", action="store_true", help="--monitor: notify after every run, not only when there are regressions")
    sch.add_argument("--print-schedule", metavar="HH:MM", help="print the Windows Task Scheduler and cron lines that run this same command daily at that time (nothing is scheduled)")
    look = p.add_argument_group("the crawler and the results")
    look.add_argument("--skin", choices=SKINS, default="sentinel", help="crawler look")
    look.add_argument("--mode", choices=("view", "line"), default="view", help="capture everything in view, or only at a scan line")
    look.add_argument("--no-summon", action="store_true", help="start with the crawler dismissed (Alt+Shift+C summons it)")
    look.add_argument("--out", help="output folder (default crawl-results/<host>_<time>)")
    look.add_argument("--format", nargs="+", choices=("json", "csv", "txt", "html", "map", "graph", "session", "sarif", "junit"), default=["json", "csv", "txt", "html", "map", "graph", "session"],
                      help="export formats (sarif: for GitHub code scanning and other security dashboards; junit: for CI test reports)")
    look.add_argument("--sarif-prefix", metavar="DIR", help="with sarif: the folder of your repository that holds the site's files, so each alert is placed on the file its page comes from (public/ maps /about to public/about)")
    look.add_argument("--fail-on", choices=("high", "medium", "low"), help="exit with status 3 if the crawl leaves any open finding (not accepted) at this level or worse")
    p.add_argument("--version", action="version", version=f"WebCrawler {version.VERSION}")
    look.add_argument("-q", "--quiet", action="store_true", help="do not print each captured link")
    p.add_argument("--list-browsers", action="store_true", help="show which browsers can be driven on this machine and exit")
    return p


def _tolerate_any_text() -> None:
    """Link text and page titles are whatever the site wrote. When output goes to a file or a pipe on Windows, Python picks the legacy
    code page, and one arrow or accent in a title would end the crawl with an encoding error: print a ? instead."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def main(argv: list[str] | None = None) -> int:
    _tolerate_any_text()
    ap = build_parser()
    args = ap.parse_args(argv)
    if args.list_browsers:
        return list_browsers()
    if args.print_schedule:
        return print_schedule(args, argv)
    if (args.notify_webhook or args.notify_email or args.smtp_host or args.notify_always) and not args.monitor:
        ap.error("notifications are sent by monitor runs: add --monitor DIR")
    if args.accept or args.unaccept:
        try:
            return accept_command(args)
        except (ValueError, OSError) as e:
            ap.error(str(e))
    if args.diff:
        import snapshot
        try:
            return report_diff(snapshot.load(args.diff[0]), snapshot.load(args.diff[1]), args, Path(args.out) if args.out else None)
        except (ValueError, OSError) as e:
            ap.error(str(e))
    if not args.target and not args.resume:
        ap.error("give a URL or local file to crawl (or --resume FILE, or --diff OLD NEW)")
    if args.quick and (args.auto or args.headless or args.profile):
        ap.error("--quick does not use a browser, so --auto, --headless and --profile do not apply")
    if (args.render or args.render_limit is not None) and not args.quick:
        ap.error("--render and --render-limit apply to --quick (the browser crawl always runs JavaScript)")
    if args.headless and not args.auto:
        ap.error("--headless needs --auto (nobody is there to scroll)")
    if args.no_summon and args.auto:
        ap.error("--auto needs the crawler summoned; drop --no-summon")
    try:
        _accepted(args)             # a bad accepted-findings file should stop the run now, not after a ten-minute crawl
        if args.monitor:
            import monitor
            return monitor.run(args, lambda: run(args))
        return run(args)
    except (ValueError, OSError) as e:
        ap.error(str(e))
        return 2


if __name__ == "__main__":
    sys.exit(main())
