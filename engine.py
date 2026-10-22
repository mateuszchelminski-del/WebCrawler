"""engine.py: runs the browser crawler on a worker thread so a GUI (or the CLI) can stay responsive.

Playwright's sync API must stay on one thread, so everything that touches the browser happens inside Engine.run().
Callers talk to it with Engine.send(command, **options) and read Engine.events, a queue of tuples:

    ("browser", "running" | "closed" | "error", message)
    ("status", message)
    ("link", Link, [Finding, ...])
    ("security", PageSecurity)
    ("page", url, number, limit)         an auto-crawl moved to a new page
    ("auto", True | False)               auto-crawl started / finished
    ("broken", url, status, referrer, reason)
    ("progress", {pages, queued, errors, links, elapsed, rps})
    ("scan_done", summary)               an auto-crawl finished (also sent by the quick scanner)
    ("cookies", [cookie, ...])           the cookies in the browser, after an "export_cookies" command (to reuse a login in a quick scan)

The site map being built lives in Engine.graph; the quick scanner (httpscan.py) fills the same graph and queue.
"""
from __future__ import annotations

import json
import queue
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urldefrag, urlparse

import analysis
import auth as auth_mod
import checks
import content
import frontier as fr
import graph as gr
import httpscan
import webcrawler as wc


@dataclass
class Settings:
    url: str = ""
    browser: str = "auto"
    headless: bool = False
    skin: str = "sentinel"
    mode: str = "view"
    summoned: bool = True
    profile: str | None = None
    auto: bool = False
    opts: fr.CrawlOptions = field(default_factory=fr.CrawlOptions)
    auth: auth_mod.AuthConfig = field(default_factory=auth_mod.AuthConfig)   # a login you already have; never saved anywhere
    resume: dict | None = None                                              # frontier state from a stopped crawl


APPLY_JS = """(s) => { const a = window.__wc_api; if (!a) return false;
  a.setSkin(s.skin); a.setMode(s.mode); if (s.summoned) a.summon(); else a.dismiss(); return true; }"""


class Engine(threading.Thread):
    def __init__(self, store: "wc.LinkStore | None" = None, site: "gr.SiteGraph | None" = None, info: "checks.SiteInfo | None" = None) -> None:
        super().__init__(daemon=True, name="crawler-engine")
        self.store = store if store is not None else wc.LinkStore()  # (an empty store is falsy, so no "or")
        self.graph = site if site is not None else gr.SiteGraph()
        self.info = info if info is not None else checks.SiteInfo()
        self.resume_state: dict | None = None
        self.last_summary: dict = {}
        self.events: queue.Queue = queue.Queue()
        self.cmds: queue.Queue = queue.Queue()
        self.security: dict[str, analysis.PageSecurity] = {}
        self.page_links: dict[str, list[str]] = {}
        self.settings = Settings()
        self.pw = self.browser = self.ctx = self.page = None
        self.closed = threading.Event()
        self.auto: dict | None = None
        self._quit = False
        self._last_progress = 0.0
        self._PWError = Exception
        self._sync_playwright = None
        self._pw_cm = None

    # ------------------------------------------------------------------ public (call from any thread)
    def send(self, cmd: str, **kw) -> None:
        self.cmds.put((cmd, kw))

    def emit(self, *event) -> None:
        self.events.put(event)

    # ------------------------------------------------------------------ thread body
    def run(self) -> None:
        try:
            self._sync_playwright, self._PWError = wc._playwright_or_raise()
        except RuntimeError as e:
            self.emit("browser", "error", str(e))
            return
        try:                    # Playwright's driver process is only started when a browser is first asked for (quick scans never need it)
            while not self._quit:
                self._drain()
                if self.ctx is not None and self.closed.is_set():
                    self._teardown("closed", "The browser window was closed.")
                if self.ctx is None:
                    time.sleep(0.05)
                    continue
                try:
                    if self.auto:
                        self._auto_tick()
                    else:
                        self._pump(100)
                except self._PWError as e:
                    if self.closed.is_set() or not self._pages():
                        self._teardown("closed", "The browser window was closed.")
                    else:
                        self.emit("status", "Browser error: " + str(e).splitlines()[0])
                        time.sleep(0.2)
            self._teardown()
        finally:
            if self._pw_cm is not None:
                try:
                    self._pw_cm.stop()
                except Exception:
                    pass

    # ------------------------------------------------------------------ commands
    def _drain(self) -> None:
        while True:
            try:
                cmd, kw = self.cmds.get_nowait()
            except queue.Empty:
                return
            try:
                getattr(self, "_cmd_" + cmd)(**kw)
            except self._PWError as e:
                self.emit("status", f"{cmd} failed: {str(e).splitlines()[0]}")
            except Exception as e:  # keep the engine alive whatever the caller sends
                self.emit("status", f"{cmd} failed: {e}")

    def _cmd_quit(self) -> None:
        self._quit = True

    def _cmd_start(self, settings: Settings) -> None:
        if self.ctx is not None:
            self._teardown("closed", "")
        self.settings = settings
        settings.opts = settings.opts.clamped()
        self.closed.clear()
        self.auto = None
        try:
            name, self.browser, self.ctx = self._launch(settings)
        except RuntimeError as e:
            self.emit("browser", "error", str(e))
            return
        ctx = self.ctx
        ctx.expose_binding("__wc_capture", self._on_capture)
        ctx.add_init_script(wc.overlay_script(settings.skin, settings.mode, settings.summoned))
        ctx.on("close", lambda *_: self.closed.set())
        ctx.on("page", self._watch_page)
        ctx.on("response", self._on_response)
        if self.browser:
            self.browser.on("disconnected", lambda *_: self.closed.set())
        self._apply_auth(settings)
        self.page = ctx.pages[0] if ctx.pages else ctx.new_page()
        for p in ctx.pages:
            self._watch_page(p)
        self.emit("browser", "running", f"{name} is open")
        if settings.auto:
            self._auto_begin(from_start=True, resume=settings.resume)
        elif settings.url:
            self._open(settings.url)

    def _apply_auth(self, s: Settings) -> None:
        """Give the browser the login (see auth.install_login for what is sent where)."""
        a = s.auth
        if a.empty or self.ctx is None:
            return
        try:
            auth_mod.install_login(self.ctx, a, s.url or (s.resume or {}).get("root", ""), s.opts.scope)
            self.emit("status", "Using your login (" + a.describe() + "); logout links are skipped.")
        except self._PWError as e:
            self.emit("status", "Could not apply the login: " + str(e).splitlines()[0])

    def _cmd_export_cookies(self) -> None:
        if self.ctx is not None:
            self.emit("cookies", self.ctx.cookies())

    def _cmd_goto(self, url: str) -> None:
        if self.ctx is not None:
            self._auto_end(None)
            self._open(url)

    def _cmd_summon(self, on: bool) -> None:
        self.settings.summoned = on
        self._apply_all()

    def _cmd_skin(self, skin: str) -> None:
        self.settings.skin = skin
        self._apply_all()

    def _cmd_mode(self, mode: str) -> None:
        self.settings.mode = mode
        self._apply_all()

    def _cmd_speed(self, speed: int) -> None:
        self.settings.opts.scroll_speed = speed
        if self.auto:
            self.auto["speed"] = speed

    def _cmd_auto(self, on: bool, opts: "fr.CrawlOptions | None" = None, resume: dict | None = None, auth: "auth_mod.AuthConfig | None" = None) -> None:
        if not on:
            self._auto_end("Auto-crawl stopped.")
            return
        if self.ctx is None:
            self.emit("status", "Launch a browser first.")
            return
        if opts is not None:
            self.settings.opts = opts.clamped()
        if auth is not None and not auth.empty and auth is not self.settings.auth:
            self.settings.auth = auth
            self._apply_auth(self.settings)
        if not self.settings.summoned:
            self.settings.summoned = True
            self._apply_all()
        self._auto_begin(from_start=False, resume=resume)

    def _cmd_reset(self) -> None:
        """Forget everything captured so far and let the pages be captured again."""
        self.store.clear()
        self.security.clear()
        self.graph.clear()
        self.info.clear()
        self.page_links.clear()
        self.resume_state = None
        for p in self._pages():
            try:
                p.evaluate("window.__wc_api && window.__wc_api.reset()")
            except Exception:
                pass

    def _cmd_stop_browser(self) -> None:
        self._teardown("closed", "Browser closed.")

    # ------------------------------------------------------------------ browser plumbing
    def _launch(self, s: Settings):
        if self.pw is None:
            self._pw_cm = self._sync_playwright()
            self.pw = self._pw_cm.start()
        return wc.launch_any(self.pw, s.browser, s.headless, s.profile, self._PWError, ignore_https_errors=not s.opts.verify_tls)

    def _pages(self):
        try:
            return self.ctx.pages if self.ctx else []
        except Exception:
            return []

    def _live_page(self):
        pages = self._pages()
        if self.page in pages:
            return self.page
        self.page = pages[-1] if pages else None
        return self.page

    def _watch_page(self, page) -> None:
        self.page = page
        try:
            page.on("load", lambda *_: self._apply(page))
        except Exception:
            pass

    def _apply(self, page) -> None:
        s = self.settings
        try:
            page.evaluate(APPLY_JS, {"skin": s.skin, "mode": s.mode, "summoned": s.summoned})
        except Exception:
            pass

    def _apply_all(self) -> None:
        for p in self._pages():
            self._apply(p)

    def _pump(self, ms: int) -> None:
        p = self._live_page()
        if p is None:
            time.sleep(ms / 1000)
            return
        p.wait_for_timeout(ms)

    def _goto(self, p, url: str):
        """Navigate and return (ok, status). status is None when the browser gave no response (e.g. a file)."""
        try:
            resp = p.goto(url, wait_until="domcontentloaded", timeout=int(self.settings.opts.timeout * 2000))
            try:
                p.wait_for_load_state("load", timeout=8000)
            except self._PWError:
                pass
            return True, (resp.status if resp else None)
        except self._PWError as e:
            self.emit("status", f"Could not open {url}: {str(e).splitlines()[0]}")
            return False, 0

    def _open(self, url: str) -> bool:
        p = self._live_page()
        if p is None:
            return False
        self.emit("status", "Opening " + url)
        u = urlparse(url)
        if self.settings.opts.check_tls and u.scheme == "https" and u.hostname not in self.info.tls:
            threading.Thread(target=lambda: self.info.add_tls(checks.tls_info(u.hostname, u.port or 443)), daemon=True).start()
        ok, status = self._goto(p, url)
        if ok:
            self._record_visit(p, 0, status, None)
        self.emit("status", ("Loaded " if ok else "Could not load ") + url)
        return ok

    def _record_visit(self, p, depth: int, status, parent) -> None:
        try:
            title = p.title()
        except self._PWError:
            title = ""
        here = p.url
        if not self.graph.root:
            self.graph.set_root(here)
        if parent:
            self.graph.link(parent, here, "internal")
        self.graph.visit(here, depth, status, title)
        if status is not None and status >= 400:
            self.emit("broken", here, status, parent or "", f"HTTP {status}")
        if urlparse(here).scheme in ("http", "https"):
            try:
                html = p.content()[:2_000_000]
            except self._PWError:
                html = ""
            sec = self.security.get(here) or self.security.get(urldefrag(here)[0])
            if html:
                if sec is not None:
                    known = {(f.code, f.detail) for f in sec.findings}
                    sec.findings += [f for f in checks.analyze_html(here, html) if (f.code, f.detail) not in known]
                    self.emit("security", sec)
                self.info.add_tech(checks.fingerprint(sec.pairs if sec is not None else [], html), here)
                self.info.add_forms(checks.extract_forms(here, html))
                self.graph.set_content(here, *content.fingerprint(html))
                self.info.add_scripts(here, content.script_hosts(here, html))
            if sec is not None:
                for k in ("content-security-policy",):
                    for h in checks.hosts_in_policy(sec.headers.get(k, "")):
                        self.info.add_host(h, "csp", urlparse(self.graph.root).hostname or "")

    def _teardown(self, state: str | None = None, message: str = "") -> None:
        if self.auto is not None:
            self.auto["stop"].set()
            self.resume_state = self._state_of(self.auto)
        self.auto = None
        was_open = self.ctx is not None
        for obj in (self.ctx, self.browser):
            if obj is not None:
                try:
                    obj.close()
                except Exception:
                    pass
        self.ctx = self.browser = self.page = None
        if state and was_open:
            self.emit("auto", False)
            self.emit("browser", state, message)

    # ------------------------------------------------------------------ callbacks from the page
    def _on_capture(self, _source, payload: str) -> int:
        for rec in json.loads(payload):
            page, href = rec.get("page", ""), rec.get("href", "")
            res = self.store.add(rec)
            if res and page and href:
                self.graph.link(page, href, res[1].kind)
                self.page_links.setdefault(fr.normalize(page), []).append(href)
            if res and res[0]:
                link = res[1]
                findings = analysis.assess_link(link.href, link.kind, link.page, rec.get("rel", ""))
                self.graph.set_risk(link.href, analysis.risk_score(findings))
                self.info.add_params(link.href)
                self.info.add_host(urlparse(link.href).hostname or "", "link", urlparse(self.graph.root).hostname or "")
                self.emit("link", link, findings)
        return len(self.store)

    def _on_response(self, resp) -> None:
        sec = analysis.security_from_response(resp)
        if sec:
            self.security[sec.url] = sec
            self.info.add_tech(checks.fingerprint(sec.pairs, ""), sec.url)
            self.emit("security", sec)

    # ------------------------------------------------------------------ auto-crawl state machine
    def _auto_begin(self, from_start: bool, resume: dict | None = None) -> None:
        s = self.settings
        o = s.opts
        if not s.auth.empty:  # a crawler that follows "log out" ends its own session
            o.exclude = list(dict.fromkeys(list(o.exclude) + auth_mod.logout_excludes()))
        p = self._live_page()
        if p is None:
            return
        here = urldefrag(p.url)[0]
        blank = here in ("", "about:blank")
        start = (resume or {}).get("root") or (urldefrag(s.url)[0] if (from_start or blank) and s.url else here)
        if not start or start == "about:blank":
            self.emit("status", "Enter a link to crawl first.")
            return
        robots = wc.Robots(not o.ignore_robots, agent=o.user_agent)
        f = fr.Frontier.from_state(resume, o, robots) if resume else fr.Frontier(start, o, robots)
        pacer = fr.Pacer(o, min_floor=0.0 if o.ignore_robots else min(robots.crawl_delay(start), 30.0))
        a = {"front": f, "pacer": pacer, "phase": "next", "speed": o.scroll_speed, "until": 0.0, "wait_until": 0.0, "stagnant": 0, "deadline": 0.0,
             "depth_now": 0, "t0": time.monotonic(), "pages": len(f.visited) if resume else 0, "errors": 0, "stop": threading.Event(), "disc": None, "seeds": []}
        if not self.graph.root or not resume:
            self.graph.set_root(start)
        if resume:
            self.emit("status", f"Resuming the crawl of {start}: {len(f)} page(s) waiting.")
        else:
            # TLS, robots.txt, sitemaps and (opt-in) well-known files run on their own thread, so the crawl starts at once
            def discover():
                try:
                    a["seeds"] = httpscan.run_discovery(start, o, s.auth, pacer, a["stop"], self.info, self.graph, self.emit)
                except Exception as e:  # discovery is a bonus: it must never take the crawl down
                    self.emit("status", f"Site checks failed: {e}")
            a["disc"] = threading.Thread(target=discover, daemon=True, name="discovery")
            a["disc"].start()
            if not from_start and not blank:
                f.pop()  # the start page is already open: crawl it in place instead of reloading it
                a.update(phase="scroll", stagnant=0, deadline=time.monotonic() + 180, pages=1)
                self._record_visit(p, 0, None, None)
                try:
                    p.evaluate("window.scrollTo(0, 0)")
                except self._PWError:
                    pass
                self.emit("page", here, 1, o.max_pages)
        self.auto = a
        self.emit("auto", True)
        self.emit("status", "Auto-crawl running.")

    @staticmethod
    def _state_of(a: dict) -> dict:
        """The frontier as it should be saved. A page that was only half scrolled goes back in the queue, so a resume does it again."""
        if a["phase"] in ("warm", "scroll", "settle") and a.get("cur"):
            url, depth, parent = a["cur"]
            a["front"].requeue(url, depth, parent)
            a["cur"] = None
        return a["front"].to_state()

    def _auto_end(self, message: str | None, limit: str = "", done: bool = False) -> None:
        a = self.auto
        if a is None:
            return
        self.auto = None
        a["stop"].set()
        el = time.monotonic() - a["t0"]
        f = a["front"]
        stopped = message == "Auto-crawl stopped."
        self.resume_state = self._state_of(a)
        if f.opts.resolve_hosts and not stopped:
            self.info.resolve_hosts()
        if done and f.opts.use_sitemap:
            for u in self.graph.orphans():
                n = self.graph.nodes.get(u)
                if n and n.visited and (n.status or 0) < 400:
                    self.info.add_finding(analysis.Finding("orphan-page", "low", "Page is in the sitemap but nothing links to it",
                                                           "Forgotten or unlisted content is a common recon find"), u)
        summary = {"pages": a["pages"], "links": len(self.store), "errors": a["errors"], "seconds": el, "stopped": stopped, "limit": limit,
                   "skipped": dict(f.skipped), "resumable": not done and (len(f) > 0 or stopped or bool(limit))}
        self.last_summary = summary
        if message:
            self.emit("status", message)
        self.emit("scan_done", summary)
        self.emit("auto", False)  # last, so anyone waiting for "auto finished" has already seen the summary

    def _progress(self, a: dict) -> None:
        now = time.monotonic()
        if now - self._last_progress < 0.5:
            return
        self._last_progress = now
        el = max(now - a["t0"], 0.001)
        self.emit("progress", {"pages": a["pages"], "queued": len(a["front"]), "errors": a["errors"], "links": len(self.store),
                               "elapsed": el, "rps": a["pages"] / el})

    def _auto_tick(self) -> None:
        a, now = self.auto, time.monotonic()
        o = self.settings.opts
        p = self._live_page()
        if p is None:
            return self._auto_end("Auto-crawl stopped: the page was closed.")
        self._progress(a)
        d = a["disc"]
        if d is not None and not d.is_alive():  # discovery finished: queue what the sitemap listed
            a["disc"] = None
            n = sum(1 for u in a["seeds"] if a["front"].push(u, 1, None))
            if a["seeds"]:
                self.emit("status", f"Sitemap lists {len(a['seeds'])} page(s); {n} queued.")
        ph = a["phase"]
        if o.max_duration and now - a["t0"] > o.max_duration and ph in ("next", "scroll", "settle"):
            return self._auto_end(f"Time limit reached after {a['pages']} page(s).", "time limit")
        if ph == "next":
            if now < a["wait_until"]:
                return self._pump(100)
            if not len(a["front"]) and a["disc"] is not None:
                return self._pump(100)  # nothing to visit yet, but the sitemap may still add pages
            item = a["front"].pop()
            if item is None:
                return self._auto_end(f"Crawl finished: {a['pages']} page(s), {len(self.store)} links.", done=not len(a["front"]))
            url, depth, parent = item
            self.emit("page", url, len(a["front"].visited), o.max_pages)
            a["cur"] = item  # the page being worked on, so a stop in the middle of it can put it back
            ok, status = self._goto(p, url)
            a["pages"] += 1
            if not ok:
                a["errors"] += 1
                self.graph.visit(url, depth, 0)
                self.emit("broken", url, 0, parent or "", "could not load")
                a["wait_until"] = now + a["pacer"].reserve()
                return
            if status is not None and status >= 400:
                a["errors"] += 1
            self._record_visit(p, depth, status, parent)
            a.update(phase="warm", until=now + 0.6, depth_now=depth)
        elif ph == "warm":
            self._pump(60)
            if now >= a["until"]:
                a.update(phase="scroll", stagnant=0, deadline=now + 180)
        elif ph == "scroll":
            step = max(4, int(a["speed"] * 0.04))
            y, h, total = p.evaluate("(d) => { window.scrollBy(0, d); const e = document.scrollingElement || document.documentElement;"
                                     " return [Math.ceil(e.scrollTop), innerHeight, e.scrollHeight]; }", step)
            p.wait_for_timeout(40)
            a["stagnant"] = a["stagnant"] + 1 if y + h >= total - 2 else 0
            if a["stagnant"] >= 8 or now > a["deadline"]:
                a.update(phase="settle", until=now + 0.7)
        elif ph == "settle":
            self._pump(60)
            if now >= a["until"]:
                here = urldefrag(p.url)[0]
                for href in self.page_links.get(fr.normalize(here), []):
                    if wc.classify(href, here) == "internal":
                        a["front"].push(href, a["depth_now"] + 1, here)
                # the pause before the next page: random, never below the site's Crawl-delay, never faster than max_rps
                a.update(phase="next", wait_until=now + a["pacer"].reserve())
