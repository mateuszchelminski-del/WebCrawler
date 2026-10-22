"""render.py: let the quick scanner see what JavaScript builds.

The quick scanner reads the HTML a server sends. A single-page app sends an empty shell and builds its links in the browser, so the
scanner sees almost nothing. This module decides which pages look like that (needs_js) and renders just those in a headless
browser (Renderer), returning the links and markup of the finished page. Everything else stays on the fast path.

The browser lives on its own thread (Playwright's sync API must not be shared between threads) and starts on first use, so a scan
that never meets a script-heavy page never starts a browser.
"""
from __future__ import annotations

import queue
import re
import threading
import time
from dataclasses import dataclass, field

import auth as auth_mod
import webcrawler as wc

# ================================================================================== which pages need a browser

SPA_ROOT = re.compile(r"<(div|main|section)[^>]+id=[\"'](root|app|__next|__nuxt|___gatsby|svelte|ember-app)[\"'][^>]*>\s*(<!--.*?-->\s*)*</\1>", re.I | re.S)
NEEDS_JS_NOTICE = re.compile(r"(enable|turn on|requires?|need)\s+(javascript|js)|javascript\s+(is|must be)\s+(required|enabled)|<noscript[^>]*>[^<]*javascript", re.I)
CUSTOM_ROOT = re.compile(r"<(app-root|ng-view|ion-app|vue-app|my-app)[\s>]", re.I)


def visible_text_length(html: str) -> int:
    """How much text a visitor without JavaScript would see."""
    h = re.sub(r"<(script|style|noscript|template|svg)\b.*?</\1\s*>", " ", html, flags=re.I | re.S)
    h = re.sub(r"<!--.*?-->", " ", h, flags=re.S)
    h = re.sub(r"<[^>]+>", " ", h)
    return len(re.sub(r"\s+", " ", h).strip())


def needs_js(html: str, internal_links: int, mode: str = "auto") -> str:
    """Why this page should be rendered in a browser, or "" if the HTML already has what the scanner needs.
    mode: "never", "auto" (judge the page) or "always"."""
    if mode == "never":
        return ""
    if mode == "always":
        return "rendering is switched on for every page"
    if internal_links > 8:                 # plenty of ordinary links: the server rendered the page
        return ""
    scripts = len(re.findall(r"<script\b", html, re.I))
    text = visible_text_length(html)
    if SPA_ROOT.search(html):
        return "an empty application shell (the page is built by JavaScript)"
    if CUSTOM_ROOT.search(html) and text < 400:
        return "a framework root element with almost no content"
    if NEEDS_JS_NOTICE.search(html) and internal_links <= 3:
        return "the page asks for JavaScript"
    if scripts >= 1 and text < 250 and internal_links <= 2:
        return f"very little content ({text} characters of text, {scripts} script(s))"
    return ""


# ================================================================================== the browser

@dataclass
class Rendered:
    url: str
    final_url: str = ""
    status: int = 0
    title: str = ""
    html: str = ""
    links: list = field(default_factory=list)       # [{"href", "text", "rel"}] as written in the page
    base: str = ""
    error: str = ""
    seconds: float = 0.0
    why: str = ""                                   # why the page was rendered (set by the scanner)


COLLECT_JS = """() => ({
  base: document.baseURI,
  links: Array.from(document.querySelectorAll('a[href],area[href]')).map(a => ({
    href: a.getAttribute('href'),
    text: ((a.textContent || '').trim() || a.getAttribute('aria-label') || a.getAttribute('title') || (a.querySelector('img') || {}).alt || '').replace(/\\s+/g, ' ').slice(0, 120),
    rel: a.getAttribute('rel') || ''
  }))
})"""
HEIGHT_JS = "() => { window.scrollTo(0, document.documentElement.scrollHeight); return document.documentElement.scrollHeight; }"


class Renderer:
    """Renders pages in a headless browser on a private thread. Thread-safe to call: jobs are queued and done one at a time."""

    def __init__(self, user_agent: str, verify_tls: bool = True, auth: "auth_mod.AuthConfig | None" = None, start: str = "", scope: str = "host",
                 browser: str = "auto", timeout: float = 20.0, emit=None, max_scrolls: int = 8) -> None:
        self.user_agent, self.verify_tls, self.auth, self.start, self.scope = user_agent, verify_tls, auth or auth_mod.AuthConfig(), start, scope
        self.browser_name, self.timeout, self.emit, self.max_scrolls = browser, timeout, emit or (lambda *a: None), max_scrolls
        self.jobs: queue.Queue = queue.Queue()
        self.thread: threading.Thread | None = None
        self.ready = threading.Event()
        self.unavailable = ""                    # why rendering cannot work here, once known
        self.rendered = 0
        self._lock = threading.Lock()
        self._closing = False

    # ---------------------------------------------------------------- public
    def render(self, url: str, stop: threading.Event | None = None) -> Rendered:
        """Render one page. Blocks until it is done. Never raises."""
        with self._lock:
            if self.unavailable:
                return Rendered(url, error=self.unavailable)
            if self.thread is None:
                self.thread = threading.Thread(target=self._run, daemon=True, name="renderer")
                self.thread.start()
        box: queue.Queue = queue.Queue(maxsize=1)
        self.jobs.put((url, box))
        end = time.monotonic() + self.timeout * 3 + 30            # start-up, load, scroll
        while time.monotonic() < end:
            try:
                return box.get(timeout=0.25)
            except queue.Empty:
                if (stop is not None and stop.is_set()) or self._closing or (self.thread and not self.thread.is_alive()):
                    break
        return Rendered(url, error=self.unavailable or "rendering did not finish")

    def close(self) -> None:
        self._closing = True
        if self.thread is not None:
            self.jobs.put(None)
            self.thread.join(timeout=10)

    # ---------------------------------------------------------------- the thread
    def _run(self) -> None:
        try:
            sync_playwright, PWError = wc._playwright_or_raise()
        except RuntimeError as e:
            self.unavailable = "JavaScript rendering is unavailable: " + str(e).splitlines()[0]
            self.emit("status", self.unavailable)
            self._drain_with_error()
            return
        try:
            with sync_playwright() as pw:
                try:
                    name, browser, ctx = wc.launch_any(pw, self.browser_name, True, None, PWError, ignore_https_errors=not self.verify_tls,
                                                       user_agent=self.user_agent)
                except RuntimeError as e:
                    self.unavailable = "JavaScript rendering is unavailable: " + str(e).splitlines()[0]
                    self.emit("status", self.unavailable)
                    self._drain_with_error()
                    return
                try:
                    auth_mod.install_login(ctx, self.auth, self.start, self.scope, block=("image", "media", "font"))
                    self.emit("status", f"Rendering script-heavy pages in headless {name}.")
                    while True:
                        job = self.jobs.get()
                        if job is None:
                            break
                        url, box = job
                        box.put(self._one(ctx, url, PWError))
                finally:
                    for obj in (ctx, browser):
                        try:
                            if obj:
                                obj.close()
                        except Exception:
                            pass
        except Exception as e:  # the renderer must never take the scan down
            self.unavailable = "JavaScript rendering stopped: " + str(e).splitlines()[0]
            self.emit("status", self.unavailable)
            self._drain_with_error()

    def _drain_with_error(self) -> None:
        while True:
            try:
                job = self.jobs.get(timeout=0.2)
            except queue.Empty:
                return
            if job is not None:
                job[1].put(Rendered(job[0], error=self.unavailable))

    def _one(self, ctx, url: str, PWError) -> Rendered:
        t0 = time.monotonic()
        out = Rendered(url)
        page = None
        try:
            page = ctx.new_page()
            resp = page.goto(url, wait_until="domcontentloaded", timeout=int(self.timeout * 1000))
            out.status = resp.status if resp else 0
            try:
                page.wait_for_load_state("networkidle", timeout=4000)     # best effort: some pages poll forever
            except PWError:
                pass
            last = -1
            for _ in range(self.max_scrolls):                              # trigger lazy loading and infinite scroll
                h = page.evaluate(HEIGHT_JS)
                page.wait_for_timeout(300)
                if h == last:
                    break
                last = h
            prev, calm, t1 = None, 0, time.monotonic()
            while time.monotonic() - t1 < 3.0 and calm < 3:               # a timer may still be about to add content: wait until the page holds still
                now = page.evaluate("document.getElementsByTagName('a').length + ':' + (document.body ? document.body.innerHTML.length : 0)")
                calm = calm + 1 if now == prev else 0
                prev = now
                page.wait_for_timeout(300)
            data = page.evaluate(COLLECT_JS)
            out.links, out.base = data["links"], data["base"]
            out.final_url = page.url
            out.title = page.title()
            out.html = page.content()[:2_000_000]
            self.rendered += 1
        except PWError as e:
            out.error = str(e).splitlines()[0][:140]
        except Exception as e:
            out.error = f"{e.__class__.__name__}: {str(e)[:100]}"
        finally:
            if page is not None:
                try:
                    page.close()
                except Exception:
                    pass
        out.seconds = time.monotonic() - t0
        return out
