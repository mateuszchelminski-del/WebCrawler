#!/usr/bin/env python3
"""webcrawler_gui.py: the WebCrawler desktop app.

Type a link and either watch an animated crawler work through it in a real browser, or run a quick scan with no browser
at all. Pages are followed link by link, every link and response header is checked for security problems, and the whole
site is drawn as a live map. Results export as CSV, JSON, TXT, an HTML report and an interactive HTML map.

    python webcrawler_gui.py [url]
"""
from __future__ import annotations

import math
import os
import queue
import re
import sys
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # pragma: no cover
    sys.exit("Tkinter is not available. On Windows and macOS it ships with Python; on Linux install python3-tk.")

import accepted as accepted_mod
import analysis
import auth as authmod
import checks
import frontier as fr
import graph as gr
import history as history_mod
import httpscan
import report
import snapshot
import webcrawler as wc
from engine import Engine, Settings

HERE = Path(__file__).resolve().parent
SKIN_NAMES = {"sentinel": "Sentinel", "hacker": "Hacker", "spider": "Cyber Spider", "packet": "Packet", "lock": "Padlock",
              "drone": "Recon Drone", "radar": "Radar", "bot": "Robot"}
MODES = {"Everything in view": "view", "Scan line only": "line"}
CRAWL_MODES = {"Browser (watch the crawler)": "browser", "Quick scan (no browser)": "quick"}
BROWSER_CHOICES = ["auto", "chrome", "edge", "chromium", "firefox", "webkit"]
PRESET_CHOICES = list(fr.PRESETS) + ["custom"]

C = {"bg": "#0b1020", "panel": "#121a30", "panel2": "#18223f", "line": "#25304f", "text": "#e8eefc", "mut": "#9aa8c7",
     "acc": "#3fd1ff", "ok": "#43ffb1", "high": "#ff6b6b", "medium": "#ffb454", "low": "#ffe082", "info": "#9aa8c7",
     "page": "#3fd1ff", "found": "#6f7fa8", "ext": "#ffb454", "file": "#ff7ad9", "bad": "#ff6b6b"}
FONT = ("Segoe UI", 10)
MONO = ("Consolas", 10)


UI = 1.0          # how much bigger than a 96-dpi screen this one is; set once the window exists (see apply_scaling)


def px(n: float) -> int:
    """A size in pixels that grows with the screen's scaling, so a 150% or 200% display gets bigger rows, columns and wrap widths along with its fonts."""
    return int(round(n * UI))


def work_area(root: tk.Misc) -> tuple[int, int, int, int]:
    """(left, top, width, height) of the part of the screen a window can use: on Windows everything except the taskbar, elsewhere the
    whole screen less a strip for a panel."""
    try:
        import ctypes
        from ctypes import wintypes
        r = wintypes.RECT()
        if ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(r), 0):          # SPI_GETWORKAREA
            return r.left, r.top, r.right - r.left, r.bottom - r.top
    except Exception:
        pass
    return 0, 0, root.winfo_screenwidth(), int(root.winfo_screenheight() * 0.94)


def screen_size(root: tk.Misc) -> tuple[int, int]:
    return work_area(root)[2:]


def fit_to_screen(w: float, h: float, sw: int, sh: int, share: float = 0.92) -> tuple[int, int]:
    """A window size that is never bigger than `share` of the screen."""
    return int(min(w, sw * share)), int(min(h, sh * share))


def apply_scaling(root: tk.Tk) -> float:
    """Work out the UI scale. WEBCRAWLER_TK_SCALING (Tk's pixels-per-point; 1.333 is a 96-dpi screen) overrides what Windows reports, for a screen that
    reports wrongly or to see how the window looks at another scaling."""
    global UI
    forced = os.environ.get("WEBCRAWLER_TK_SCALING", "").strip()
    if forced:
        try:
            root.tk.call("tk", "scaling", max(0.8, min(6.0, float(forced))))
        except (ValueError, tk.TclError):
            pass
    try:
        UI = max(0.75, min(4.0, float(root.tk.call("tk", "scaling")) / (96 / 72)))
    except (ValueError, tk.TclError):
        UI = 1.0
    return UI


class ScrollBody(ttk.Frame):
    """The contents of a dialog, in a frame that scrolls when the window is smaller than the contents (a small or heavily scaled screen).
    Put widgets in `.inner`; call fit() when they are all there."""

    def __init__(self, win: tk.Toplevel) -> None:
        super().__init__(win)
        self.win = win
        self.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(self, bg=C["bg"], highlightthickness=0)
        self.vs = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.hs = ttk.Scrollbar(self, orient="horizontal", command=self.canvas.xview)
        self.canvas.configure(yscrollcommand=self.vs.set, xscrollcommand=self.hs.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.vs.grid(row=0, column=1, sticky="ns")
        self.hs.grid(row=1, column=0, sticky="ew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.inner = ttk.Frame(self.canvas, style="Card.TFrame", padding=16)
        self._item = self.canvas.create_window(0, 0, window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", lambda e: self._sync())
        self.canvas.bind("<Configure>", lambda e: self._sync())
        win.bind("<MouseWheel>", lambda e: self.canvas.yview_scroll(-1 if e.delta > 0 else 1, "units") if self.vs.winfo_ismapped() else None)

    def _sync(self) -> None:
        cw, ch = self.canvas.winfo_width(), self.canvas.winfo_height()
        rw, rh = self.inner.winfo_reqwidth(), self.inner.winfo_reqheight()
        self.canvas.itemconfigure(self._item, width=max(cw, rw), height=max(ch, rh))      # no gap when the window is bigger than the contents
        self.canvas.configure(scrollregion=(0, 0, max(cw, rw), max(ch, rh)))
        (self.vs.grid if rh > ch + 1 else self.vs.grid_remove)()
        (self.hs.grid if rw > cw + 1 else self.hs.grid_remove)()

    def fit(self, parent: tk.Misc) -> None:
        """Size the window to its contents, but never beyond the screen, and centre it over its parent."""
        self.update_idletasks()
        x0, y0, sw, sh = work_area(self)
        w = min(self.inner.winfo_reqwidth() + 4, int(sw * 0.94))
        h = min(self.inner.winfo_reqheight() + 4, int(sh * 0.86))
        try:
            x = parent.winfo_rootx() + (parent.winfo_width() - w) // 2
            y = parent.winfo_rooty() + (parent.winfo_height() - h) // 3
        except tk.TclError:
            x, y = x0 + (sw - w) // 2, y0 + (sh - h) // 3
        self.win.geometry(f"{w}x{h}+{max(x0, min(x, x0 + sw - w))}+{max(y0, min(y, y0 + sh - h - 48))}")


def apply_theme(root: tk.Tk) -> None:
    st = ttk.Style(root)
    st.theme_use("clam")
    root.configure(bg=C["bg"])
    root.option_add("*TCombobox*Listbox.background", C["panel2"])
    root.option_add("*TCombobox*Listbox.foreground", C["text"])
    root.option_add("*TCombobox*Listbox.selectBackground", C["acc"])
    root.option_add("*TCombobox*Listbox.selectForeground", "#04101c")
    st.configure(".", background=C["bg"], foreground=C["text"], fieldbackground=C["panel2"], bordercolor=C["line"], lightcolor=C["line"],
                 darkcolor=C["line"], troughcolor=C["panel2"], font=FONT, focuscolor=C["acc"])
    st.configure("TFrame", background=C["bg"])
    st.configure("Card.TFrame", background=C["panel"], relief="flat")
    st.configure("TLabel", background=C["bg"], foreground=C["text"])
    st.configure("Card.TLabel", background=C["panel"])
    st.configure("Muted.TLabel", background=C["bg"], foreground=C["mut"])
    st.configure("CardMuted.TLabel", background=C["panel"], foreground=C["mut"])
    st.configure("Title.TLabel", background=C["bg"], font=("Segoe UI Semibold", 17))
    st.configure("Stat.TLabel", background=C["panel"], font=("Segoe UI Semibold", 15), foreground=C["acc"])
    st.configure("TButton", background=C["panel2"], foreground=C["text"], padding=(12, 6), borderwidth=1, relief="flat")
    st.map("TButton", background=[("active", C["line"]), ("disabled", C["panel"])], foreground=[("disabled", C["mut"])])
    st.configure("Small.TButton", background=C["panel2"], foreground=C["text"], padding=(9, 5))
    st.map("Small.TButton", background=[("active", C["line"])])
    st.configure("Accent.TButton", background=C["acc"], foreground="#04101c", font=("Segoe UI Semibold", 10))
    st.map("Accent.TButton", background=[("active", "#7fe3ff"), ("disabled", C["line"])])
    st.configure("Go.TButton", background=C["ok"], foreground="#04140d", font=("Segoe UI Semibold", 10))
    st.map("Go.TButton", background=[("active", "#8dffd0"), ("disabled", C["line"])])
    st.configure("Stop.TButton", background=C["high"], foreground="#1c0606", font=("Segoe UI Semibold", 10))
    st.map("Stop.TButton", background=[("active", "#ff9a9a")])
    st.configure("TEntry", fieldbackground=C["panel2"], foreground=C["text"], insertcolor=C["text"], padding=6)
    st.configure("TCombobox", fieldbackground=C["panel2"], background=C["panel2"], foreground=C["text"], arrowcolor=C["acc"], padding=4)
    st.map("TCombobox", fieldbackground=[("readonly", C["panel2"])], foreground=[("readonly", C["text"])])
    st.configure("TCheckbutton", background=C["panel"], foreground=C["text"])
    st.map("TCheckbutton", background=[("active", C["panel"])])
    st.configure("TSpinbox", fieldbackground=C["panel2"], foreground=C["text"], arrowcolor=C["acc"], padding=3)
    st.configure("Horizontal.TScale", background=C["panel"], troughcolor=C["panel2"])
    st.configure("TNotebook", background=C["bg"], borderwidth=0)
    st.configure("TNotebook.Tab", background=C["panel"], foreground=C["mut"], padding=(14, 7), borderwidth=0)
    st.map("TNotebook.Tab", background=[("selected", C["panel2"])], foreground=[("selected", C["acc"])])
    st.configure("Treeview", background=C["panel"], fieldbackground=C["panel"], foreground=C["text"], rowheight=px(25), borderwidth=0)
    st.map("Treeview", background=[("selected", "#24407a")], foreground=[("selected", "#ffffff")])
    st.configure("Treeview.Heading", background=C["panel2"], foreground=C["mut"], relief="flat", padding=5, font=("Segoe UI Semibold", 9))
    st.map("Treeview.Heading", background=[("active", C["line"])])
    st.configure("Vertical.TScrollbar", background=C["panel2"], troughcolor=C["panel"], arrowcolor=C["mut"], bordercolor=C["panel"])
    st.configure("Horizontal.TScrollbar", background=C["panel2"], troughcolor=C["panel"], arrowcolor=C["mut"], bordercolor=C["panel"])


class AdvancedDialog(tk.Toplevel):
    """Every crawl setting that does not fit on the main screen."""

    def __init__(self, parent: tk.Tk, opts: fr.CrawlOptions, headless: bool, login: "authmod.AuthConfig | None" = None, domain: str = "") -> None:
        super().__init__(parent)
        self.title("Crawl settings")
        self.domain = domain
        self.login = login or authmod.AuthConfig()
        self._file_cookies: list = list(self.login.cookies)
        self.configure(bg=C["bg"])
        self.transient(parent)
        self.result: tuple | None = None
        o = opts
        self.body = ScrollBody(self)
        f = self.body.inner
        self.v = {
            "delay_min": tk.StringVar(value=str(o.delay_min)), "delay_max": tk.StringVar(value=str(o.delay_max)),
            "max_rps": tk.StringVar(value=str(o.max_rps)), "concurrency": tk.StringVar(value=str(o.concurrency)),
            "timeout": tk.StringVar(value=str(o.timeout)), "max_duration": tk.StringVar(value=f"{o.max_duration / 60:g}"),
            "scope": tk.StringVar(value=o.scope), "strategy": tk.StringVar(value=o.strategy), "user_agent": tk.StringVar(value=o.user_agent),
            "robots": tk.BooleanVar(value=not o.ignore_robots), "check_external": tk.BooleanVar(value=o.check_external), "headless": tk.BooleanVar(value=headless),
            "use_sitemap": tk.BooleanVar(value=o.use_sitemap), "probe_files": tk.BooleanVar(value=o.probe_files), "check_tls": tk.BooleanVar(value=o.check_tls),
            "render": tk.StringVar(value=o.render), "insecure": tk.BooleanVar(value=not o.verify_tls), "max_query_variants": tk.StringVar(value=str(o.max_query_variants)),
            "check_dns": tk.BooleanVar(value=o.check_dns), "check_ct": tk.BooleanVar(value=o.check_ct), "resolve_hosts": tk.BooleanVar(value=o.resolve_hosts),
        }
        self.cookie_var = tk.StringVar()
        rows = [
            ("Pause between requests (s)", "delay_min", "to", "delay_max", "A random pause in this range before each request. Longer and more varied looks less like a bot."),
            ("Max requests per second", "max_rps", None, None, "A hard cap on top of the pause. 0 = no cap."),
            ("Parallel downloads", "concurrency", None, None, "Quick scan only: how many pages download at once."),
            ("Request timeout (s)", "timeout", None, None, "Give up on a page after this long."),
            ("Stop after (minutes)", "max_duration", None, None, "Time limit for the whole crawl. 0 = no limit."),
        ]
        r = 0
        for label, a, mid, b, tip in rows:
            ttk.Label(f, text=label, style="Card.TLabel").grid(row=r, column=0, sticky="w", pady=4)
            ttk.Entry(f, textvariable=self.v[a], width=8).grid(row=r, column=1, sticky="w", padx=8)
            if mid:
                ttk.Label(f, text=mid, style="CardMuted.TLabel").grid(row=r, column=2)
                ttk.Entry(f, textvariable=self.v[b], width=8).grid(row=r, column=3, sticky="w", padx=8)
            ttk.Label(f, text=tip, style="CardMuted.TLabel", wraplength=px(300)).grid(row=r, column=4, sticky="w", padx=(12, 0))
            r += 1
        ttk.Label(f, text="Which pages to follow", style="Card.TLabel").grid(row=r, column=0, sticky="w", pady=4)
        ttk.Combobox(f, textvariable=self.v["scope"], values=["host", "subdomains", "any"], width=11, state="readonly").grid(row=r, column=1, columnspan=2, sticky="w", padx=8)
        ttk.Label(f, text="host = this site only, subdomains = also blog.site.com, any = leave the site (careful)", style="CardMuted.TLabel", wraplength=px(300)).grid(row=r, column=4, sticky="w", padx=(12, 0))
        r += 1
        ttk.Label(f, text="Order", style="Card.TLabel").grid(row=r, column=0, sticky="w", pady=4)
        ttk.Combobox(f, textvariable=self.v["strategy"], values=["bfs", "dfs"], width=11, state="readonly").grid(row=r, column=1, columnspan=2, sticky="w", padx=8)
        ttk.Label(f, text="bfs = level by level (broad), dfs = follow one branch to the end", style="CardMuted.TLabel", wraplength=px(300)).grid(row=r, column=4, sticky="w", padx=(12, 0))
        r += 1
        ttk.Label(f, text="Only URLs matching (regex, one per line)", style="Card.TLabel").grid(row=r, column=0, sticky="nw", pady=4)
        self.inc = tk.Text(f, width=34, height=3, bg=C["panel2"], fg=C["text"], insertbackground=C["text"], relief="flat", font=MONO)
        self.inc.grid(row=r, column=1, columnspan=3, padx=8, pady=4)
        self.inc.insert("1.0", "\n".join(o.include))
        r += 1
        ttk.Label(f, text="Skip URLs matching (regex, one per line)", style="Card.TLabel").grid(row=r, column=0, sticky="nw", pady=4)
        self.exc = tk.Text(f, width=34, height=3, bg=C["panel2"], fg=C["text"], insertbackground=C["text"], relief="flat", font=MONO)
        self.exc.grid(row=r, column=1, columnspan=3, padx=8, pady=4)
        self.exc.insert("1.0", "\n".join(o.exclude))
        ttk.Label(f, text="for example /logout or \\?replytocom=", style="CardMuted.TLabel").grid(row=r, column=4, sticky="w", padx=(12, 0))
        r += 1
        ttk.Label(f, text="User agent", style="Card.TLabel").grid(row=r, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=self.v["user_agent"], width=44).grid(row=r, column=1, columnspan=3, sticky="w", padx=8)
        r += 1
        ttk.Label(f, text="Login: cookies", style="Card.TLabel").grid(row=r, column=0, sticky="w", pady=(10, 4))
        ttk.Entry(f, textvariable=self.cookie_var, width=44, show="•").grid(row=r, column=1, columnspan=3, sticky="w", padx=8, pady=(10, 4))
        ttk.Button(f, text="Load cookies file…", style="Small.TButton", command=self._pick_cookie_file).grid(row=r, column=4, sticky="w", padx=(12, 0), pady=(10, 4))
        r += 1
        ttk.Label(f, text="Login: headers (one per line)", style="Card.TLabel").grid(row=r, column=0, sticky="nw", pady=4)
        self.hdr = tk.Text(f, width=34, height=2, bg=C["panel2"], fg=C["text"], insertbackground=C["text"], relief="flat", font=MONO)
        self.hdr.grid(row=r, column=1, columnspan=3, padx=8, pady=4)
        self.hdr.insert("1.0", "\n".join(f"{k}: {v}" for k, v in self.login.headers.items()))
        ttk.Label(f, text="Use a session you already have. It goes only to the site being crawled, is never saved, and logout links are skipped.",
                  style="CardMuted.TLabel", wraplength=px(300)).grid(row=r, column=4, sticky="w", padx=(12, 0))
        r += 1
        self.login_lbl = ttk.Label(f, text="", style="CardMuted.TLabel")
        self.login_lbl.grid(row=r, column=1, columnspan=3, sticky="w", padx=8)
        ttk.Button(f, text="Clear login", style="Small.TButton", command=self._clear_login).grid(row=r, column=4, sticky="w", padx=(12, 0))
        self._login_label()
        r += 1
        checks = ttk.Frame(f, style="Card.TFrame")
        checks.grid(row=r, column=0, columnspan=5, sticky="w", pady=(8, 0))
        ttk.Checkbutton(checks, text="Respect robots.txt (and its Crawl-delay)", variable=self.v["robots"]).pack(side="left", padx=(0, 16))
        ttk.Checkbutton(checks, text="Check external links for breakage (quick scan)", variable=self.v["check_external"]).pack(side="left", padx=(0, 16))
        ttk.Checkbutton(checks, text="Headless browser (no window)", variable=self.v["headless"]).pack(side="left")
        r += 1
        checks2 = ttk.Frame(f, style="Card.TFrame")
        checks2.grid(row=r, column=0, columnspan=5, sticky="w", pady=(4, 0))
        ttk.Checkbutton(checks2, text="Read robots.txt and sitemaps to find unlinked pages", variable=self.v["use_sitemap"]).pack(side="left", padx=(0, 16))
        ttk.Checkbutton(checks2, text="Check the TLS certificate", variable=self.v["check_tls"]).pack(side="left", padx=(0, 16))
        ttk.Checkbutton(checks2, text="Probe well-known files (.git, .env, security.txt): only your own sites", variable=self.v["probe_files"]).pack(side="left")
        r += 1
        checks3 = ttk.Frame(f, style="Card.TFrame")
        checks3.grid(row=r, column=0, columnspan=5, sticky="w", pady=(4, 0))
        ttk.Label(checks3, text="Quick scan: render script-heavy pages", style="Card.TLabel").pack(side="left", padx=(0, 6))
        ttk.Combobox(checks3, textvariable=self.v["render"], values=["auto", "never", "always"], width=7, state="readonly").pack(side="left", padx=(0, 16))
        ttk.Label(checks3, text="Max ?query variants per page", style="Card.TLabel").pack(side="left", padx=(0, 6))
        ttk.Entry(checks3, textvariable=self.v["max_query_variants"], width=5).pack(side="left", padx=(0, 16))
        ttk.Checkbutton(checks3, text="Do not verify HTTPS certificates (self-signed sites)", variable=self.v["insecure"]).pack(side="left")
        r += 1
        checks4 = ttk.Frame(f, style="Card.TFrame")
        checks4.grid(row=r, column=0, columnspan=5, sticky="w", pady=(4, 0))
        ttk.Checkbutton(checks4, text="Read SPF / DMARC / CAA / DNSSEC records (asks Cloudflare's public DNS about the domain)", variable=self.v["check_dns"]).pack(side="left", padx=(0, 16))
        ttk.Checkbutton(checks4, text="Look up the subdomains the site mentions", variable=self.v["resolve_hosts"]).pack(side="left", padx=(0, 16))
        ttk.Checkbutton(checks4, text="List subdomains from certificate logs (asks crt.sh)", variable=self.v["check_ct"]).pack(side="left")
        r += 1
        btns = ttk.Frame(f, style="Card.TFrame")
        btns.grid(row=r, column=0, columnspan=5, sticky="e", pady=(14, 0))
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right", padx=(8, 0))
        ttk.Button(btns, text="Apply", style="Accent.TButton", command=self._ok).pack(side="right")
        self.bind("<Escape>", lambda e: self.destroy())
        self.body.fit(parent)
        self.grab_set()

    def _login_label(self) -> None:
        n = len(self._file_cookies)
        self.login_lbl.configure(text=("Cookies loaded: " + str(n) + "   ") if n else "")

    def _pick_cookie_file(self) -> None:
        path = filedialog.askopenfilename(title="Cookies file (JSON or cookies.txt)", parent=self)
        if path:
            try:
                self._file_cookies = authmod.load_cookie_file(path, self.domain)
            except (ValueError, OSError) as e:
                messagebox.showerror("Cookies file", str(e), parent=self)
                return
            self._login_label()

    def _clear_login(self) -> None:
        self._file_cookies = []
        self.cookie_var.set("")
        self.hdr.delete("1.0", "end")
        self._login_label()

    def build_login(self) -> "authmod.AuthConfig":
        cookies = list(self._file_cookies)
        if self.cookie_var.get().strip():
            cookies += authmod.parse_cookie_string(self.cookie_var.get(), self.domain)
        headers = dict(authmod.parse_header_line(l) for l in self.hdr.get("1.0", "end").splitlines() if l.strip())
        return authmod.AuthConfig(cookies, headers)

    def parse(self) -> dict:
        v = self.v
        new = {"delay_min": float(v["delay_min"].get()), "delay_max": float(v["delay_max"].get()), "max_rps": float(v["max_rps"].get()),
               "concurrency": int(float(v["concurrency"].get())), "timeout": float(v["timeout"].get()),
               "max_duration": float(v["max_duration"].get()) * 60, "scope": v["scope"].get(), "strategy": v["strategy"].get(),
               "user_agent": v["user_agent"].get().strip() or fr.DEFAULT_UA, "ignore_robots": not v["robots"].get(),
               "check_external": v["check_external"].get(), "use_sitemap": v["use_sitemap"].get(), "probe_files": v["probe_files"].get(), "check_tls": v["check_tls"].get(),
               "render": v["render"].get(), "verify_tls": not v["insecure"].get(), "max_query_variants": int(float(v["max_query_variants"].get())),
               "check_dns": v["check_dns"].get(), "check_ct": v["check_ct"].get(), "resolve_hosts": v["resolve_hosts"].get(),
               "include": [l.strip() for l in self.inc.get("1.0", "end").splitlines() if l.strip()],
               "exclude": [l.strip() for l in self.exc.get("1.0", "end").splitlines() if l.strip()]}
        fr.compile_patterns(new["include"] + new["exclude"])  # raises re.error on a bad pattern
        return new

    def _ok(self) -> None:
        try:
            new = self.parse()
            login = self.build_login()
        except (ValueError, re.error) as e:
            messagebox.showerror("Crawl settings", f"Check the values: {e}", parent=self)
            return
        self.result = (new, self.v["headless"].get(), login)
        self.destroy()


class AcceptDialog(tk.Toplevel):
    """Ask why a finding is fine, where the decision applies and for how long. `result` is (code, where, reason, expires) or None."""

    def __init__(self, parent: tk.Tk, code: str, title: str, where: str) -> None:
        super().__init__(parent)
        self.title("Accept this finding")
        self.configure(bg=C["bg"])
        self.transient(parent)
        self.resizable(False, False)
        self.result: tuple | None = None
        self.code = code
        f = ttk.Frame(self, style="Card.TFrame", padding=16)
        f.pack(fill="both", expand=True, padx=10, pady=10)
        ttk.Label(f, text=title, style="Card.TLabel", wraplength=px(480)).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(f, text=f"({code})", style="CardMuted.TLabel").grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 10))
        self.scope = tk.StringVar(value="here")
        self.where = tk.StringVar(value=where)
        self.reason = tk.StringVar()
        self.expires = tk.StringVar()
        ttk.Radiobutton(f, text="Only here:", variable=self.scope, value="here").grid(row=2, column=0, sticky="w")
        ttk.Entry(f, textvariable=self.where, width=56).grid(row=2, column=1, sticky="we", padx=8, pady=3)
        ttk.Radiobutton(f, text="Everywhere on every site", variable=self.scope, value="all").grid(row=3, column=0, columnspan=2, sticky="w")
        ttk.Label(f, text="Why it is fine", style="Card.TLabel").grid(row=4, column=0, sticky="w", pady=(10, 3))
        ent = ttk.Entry(f, textvariable=self.reason, width=56)
        ent.grid(row=4, column=1, sticky="we", padx=8, pady=(10, 3))
        ttk.Label(f, text="Look again after", style="Card.TLabel").grid(row=5, column=0, sticky="w", pady=3)
        ttk.Entry(f, textvariable=self.expires, width=14).grid(row=5, column=1, sticky="w", padx=8, pady=3)
        ttk.Label(f, text="YYYY-MM-DD, or leave empty for no expiry. * in the place matches anything, e.g. https://example.com/docs/*", style="CardMuted.TLabel",
                  wraplength=px(480)).grid(row=6, column=0, columnspan=2, sticky="w")
        btns = ttk.Frame(f, style="Card.TFrame")
        btns.grid(row=7, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right", padx=(8, 0))
        ttk.Button(btns, text="Accept", style="Accent.TButton", command=self._ok).pack(side="right")
        self.bind("<Escape>", lambda e: self.destroy())
        self.bind("<Return>", lambda e: self._ok())
        self.grab_set()
        ent.focus_set()

    def _ok(self) -> None:
        where = "*" if self.scope.get() == "all" else (self.where.get().strip() or "*")
        exp = self.expires.get().strip()
        try:
            accepted_mod.Accepted().add(self.code, where, self.reason.get(), exp)         # validates the date
        except ValueError as e:
            messagebox.showerror("Accept this finding", str(e), parent=self)
            return
        self.result = (self.code, where, self.reason.get().strip(), exp)
        self.destroy()


class App(tk.Tk):
    def __init__(self, start_url: str = "") -> None:
        super().__init__()
        self.accepted = accepted_mod.Accepted()          # findings you decided to live with
        self.accepted_path = ""
        self.show_accepted = tk.BooleanVar(value=False)
        self._flat: dict[str, tuple] = {}                 # Findings-tab row -> (code, place, title, accepted?)
        self.title("WebCrawler: link and security recon")
        apply_scaling(self)
        x0, y0, sw, sh = work_area(self)
        w, h = fit_to_screen(1300 * UI, 900 * UI, sw, sh, 0.90)           # the title bar and window frame come on top of this
        self.geometry(f"{w}x{h}+{x0 + max(0, (sw - w) // 2)}+{y0 + max(0, (sh - h) // 4)}")
        self.minsize(*fit_to_screen(1120 * UI, 720 * UI, sw, sh, 0.85))
        self.compact = h / UI < 780              # a short window (small laptop, or a big scaling factor): thumbnails give way to the lists below
        apply_theme(self)
        try:
            self._icon = tk.PhotoImage(master=self, file=str(HERE / "assets" / "icon.png"))
            self.iconphoto(True, self._icon)
        except tk.TclError:
            self._icon = None

        self.engine = Engine()
        self.engine.start()
        self.graph: gr.SiteGraph = self.engine.graph
        self.info: checks.SiteInfo = self.engine.info
        self.auth = authmod.AuthConfig()   # a login you supplied; lives only in memory
        self.resume_state: dict | None = None
        self._kind = "browser"             # which kind of crawl ran last: "browser" or "quick"
        self.diff = None                   # the last comparison shown in the Changes tab
        self._info_ver = -1
        self.scanner: httpscan.QuickScanner | None = None
        self.settings = Settings(skin="sentinel", mode="view", summoned=True)
        self.opts = fr.with_preset("balanced")
        self.opts.depth, self.opts.max_pages = 2, 50
        self.headless = False
        self.running = False          # browser open
        self.auto_on = False          # a crawl (either kind) is running
        self.rows: list[tuple] = []   # (Link, findings, score)
        self.broken: list[tuple] = []  # (url, status, referrer, reason)
        self.sec: dict[str, analysis.PageSecurity] = {}
        self.skin_buttons: dict[str, tk.Button] = {}
        self.thumbs: dict[str, tk.PhotoImage] = {}
        self._dirty_findings = False
        self._sort = ("n", False)
        self.mv = {"kx": 1.0, "ky": 1.0, "ox": 0.0, "oy": 0.0, "fitted": False}   # map view transform
        self._map_cache: tuple | None = None
        self._map_ver = -1
        self._map_drawn = 0.0
        self._map_gap = 0.7
        self._map_sel: str | None = None
        self._map_screen: dict = {}
        self._drag = None

        self._build()
        self.url_var.set(start_url or "")
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.bind("<Return>", lambda e: self._launch() if self.focus_get() is self.url_entry else None)
        self._poll_id = self.after(100, self._poll)

    # ------------------------------------------------------------------ layout
    def _build(self) -> None:
        self._build_menu()
        pad = {"padx": 16}
        head = ttk.Frame(self)
        head.pack(fill="x", pady=(10, 4), **pad)
        if self._icon:
            ttk.Label(head, image=(self._icon.subsample(3, 3) if UI < 1.75 else self._icon.subsample(2, 2))).pack(side="left", padx=(0, 10))
        ttk.Label(head, text="WebCrawler", style="Title.TLabel").pack(side="left")
        ttk.Label(head, text="   Summon a crawler, map the site, audit what it finds.", style="Muted.TLabel").pack(side="left", pady=(6, 0))
        self.pill = ttk.Label(head, text="● Idle", style="Muted.TLabel")
        self.pill.pack(side="right")
        self._top = [head]

        # --- launch card
        card = ttk.Frame(self, style="Card.TFrame", padding=9)
        card.pack(fill="x", pady=4, **pad)
        self._top.append(card)
        r1 = ttk.Frame(card, style="Card.TFrame")
        r1.pack(fill="x")
        ttk.Label(r1, text="Page", style="Card.TLabel").pack(side="left", padx=(0, 8))
        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(r1, textvariable=self.url_var, font=("Segoe UI", 11))
        self.url_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Label(r1, text="Browser", style="CardMuted.TLabel").pack(side="left", padx=(0, 6))
        self.browser_var = tk.StringVar(value="auto")
        ttk.Combobox(r1, textvariable=self.browser_var, values=BROWSER_CHOICES, width=9, state="readonly").pack(side="left", padx=(0, 12))
        self.launch_btn = ttk.Button(r1, text="Launch", style="Accent.TButton", command=self._launch)
        self.launch_btn.pack(side="left", padx=(0, 6))
        self.close_btn = ttk.Button(r1, text="Close browser", command=lambda: self.engine.send("stop_browser"), state="disabled")
        self.close_btn.pack(side="left")

        # --- crawler card (look + auto-crawl)
        card2 = ttk.Frame(self, style="Card.TFrame", padding=9)
        card2.pack(fill="x", pady=4, **pad)
        self._top.append(card2)
        skins = ttk.Frame(card2, style="Card.TFrame")
        skins.grid(row=0, column=0, sticky="w")
        for i, sid in enumerate(SKIN_NAMES):
            f = tk.Frame(skins, bg=C["panel"])
            f.grid(row=0, column=i, padx=3)
            try:
                img = None if self.compact else tk.PhotoImage(master=self, file=str(HERE / "assets" / "skins" / f"{sid}.png"))
                if img is not None and UI >= 1.75:
                    img = img.zoom(2)                       # crisp, not blurred, on a 200% screen
            except tk.TclError:
                img = None
            self.thumbs[sid] = img
            b = tk.Button(f, image=img, text=SKIN_NAMES[sid], compound="top" if img else "none", bg=C["panel"], fg=C["mut"], activebackground=C["panel2"],
                          activeforeground=C["text"], relief="flat", bd=0, highlightthickness=2, highlightbackground=C["panel"],
                          highlightcolor=C["acc"], font=("Segoe UI", 8), width=px(84) if img else 11, cursor="hand2", command=lambda s=sid: self._pick_skin(s))
            b.pack()
            self.skin_buttons[sid] = b
        self._pick_skin("sentinel", send=False)
        ctl = ttk.Frame(card2, style="Card.TFrame")
        ctl.grid(row=0, column=1, sticky="nsew", padx=(24, 0))
        card2.columnconfigure(1, weight=1)
        self.summon_btn = ttk.Button(ctl, text="Dismiss crawler", style="Stop.TButton", command=self._toggle_summon)
        self.summon_btn.grid(row=0, column=0, sticky="w", pady=2)
        self.mode_var = tk.StringVar(value="Everything in view")
        ttk.Label(ctl, text="Capture", style="CardMuted.TLabel").grid(row=0, column=1, padx=(18, 6))
        mode = ttk.Combobox(ctl, textvariable=self.mode_var, values=list(MODES), width=18, state="readonly")
        mode.grid(row=0, column=2)
        mode.bind("<<ComboboxSelected>>", lambda e: self._send_mode())

        card3 = ttk.Frame(card2, style="Card.TFrame")
        card3.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        self.auto_btn = ttk.Button(card3, text="▶  Start crawl", style="Accent.TButton", command=self._toggle_auto)
        self.auto_btn.grid(row=0, column=0, rowspan=2, sticky="nsw", padx=(0, 14))
        ttk.Label(card3, text="How", style="CardMuted.TLabel").grid(row=0, column=1, sticky="w")
        self.crawl_mode_var = tk.StringVar(value="Browser (watch the crawler)")
        ttk.Combobox(card3, textvariable=self.crawl_mode_var, values=list(CRAWL_MODES), width=26, state="readonly").grid(row=1, column=1, sticky="w", padx=(0, 12))
        ttk.Label(card3, text="Pace", style="CardMuted.TLabel").grid(row=0, column=2, sticky="w")
        self.preset_var = tk.StringVar(value="balanced")
        pc = ttk.Combobox(card3, textvariable=self.preset_var, values=PRESET_CHOICES, width=9, state="readonly")
        pc.grid(row=1, column=2, sticky="w", padx=(0, 12))
        pc.bind("<<ComboboxSelected>>", lambda e: self._preset_changed())
        self.depth_var, self.pages_var = tk.IntVar(value=2), tk.IntVar(value=50)
        for col, (label, var, lo, hi, w) in enumerate((("Depth", self.depth_var, 0, 25, 4), ("Max pages", self.pages_var, 1, 100000, 6))):
            ttk.Label(card3, text=label, style="CardMuted.TLabel").grid(row=0, column=3 + col, sticky="w")
            ttk.Spinbox(card3, from_=lo, to=hi, textvariable=var, width=w).grid(row=1, column=3 + col, sticky="w", padx=(0, 12))
        ttk.Label(card3, text="Scroll speed", style="CardMuted.TLabel").grid(row=0, column=5, sticky="w")
        self.speed_var = tk.IntVar(value=self.opts.scroll_speed)
        ttk.Scale(card3, from_=100, to=2400, variable=self.speed_var, length=130, command=lambda v: self._speed_changed()).grid(row=1, column=5, sticky="w")
        self.speed_lbl = ttk.Label(card3, text=f"{self.opts.scroll_speed} px/s", style="CardMuted.TLabel", width=9)
        self.speed_lbl.grid(row=1, column=6, padx=(4, 12))
        ttk.Button(card3, text="Settings…", style="Small.TButton", command=self._advanced).grid(row=1, column=7, sticky="w")
        self.opts_lbl = ttk.Label(card3, text="", style="CardMuted.TLabel")
        self.opts_lbl.grid(row=0, column=7, sticky="w")
        self._refresh_opts_label()

        # --- bottom bar first, so a short window never hides it
        bar = ttk.Frame(self, style="Card.TFrame", padding=(12, 8))
        bar.pack(side="bottom", fill="x", pady=(4, 14), **pad)
        for text, cmd in (("Clear", self._clear), ("All…", self._export_all), ("Map", lambda: self._export("map")), ("Report", lambda: self._export("html")),
                          ("JSON", lambda: self._export("json")), ("CSV", lambda: self._export("csv"))):
            ttk.Button(bar, text=text, command=cmd, style="Accent.TButton" if text == "CSV" else "Small.TButton").pack(side="right", padx=3)
        self.stat = {}
        for key, label in (("links", "Links"), ("external", "External"), ("risky", "Risky"), ("pages", "Pages"), ("broken", "Broken")):
            f = ttk.Frame(bar, style="Card.TFrame")
            f.pack(side="left", padx=(0, 12))
            self.stat[key] = ttk.Label(f, text="0", style="Stat.TLabel")
            self.stat[key].pack(anchor="w")
            ttk.Label(f, text=label, style="CardMuted.TLabel").pack(anchor="w")
        self.status_var = tk.StringVar(value="Ready. Enter a link, then Launch (browser) or Start crawl.")
        ttk.Label(bar, textvariable=self.status_var, style="CardMuted.TLabel", wraplength=px(260)).pack(side="left", fill="x", expand=True, padx=(4, 8))

        # --- notebook
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, pady=(8, 4), **pad)
        self._build_links_tab()
        self._build_map_tab()
        self._build_findings_tab()
        self._build_site_tab()
        self._build_inputs_tab()
        self._build_security_tab()
        self._build_changes_tab()
        self._build_log_tab()
        self.nb.bind("<<NotebookTabChanged>>", lambda e: (self._refresh_findings(), self._refill_site(), self._refill_inputs(), self._map_redraw(force=True)))

    def _build_menu(self) -> None:
        m = tk.Menu(self)
        self.config(menu=m)
        s = tk.Menu(m, tearoff=0)
        m.add_cascade(label="Session", menu=s)
        s.add_command(label="New (clear everything)", command=lambda: self._clear())
        s.add_command(label="Open session…", command=self._open_session)
        s.add_command(label="Save session…", command=self._save_session)
        s.add_separator()
        s.add_command(label="Copy the login from the open browser (for quick scans)", command=self._copy_login)
        s.add_command(label="Forget the saved login", command=self._forget_login)
        s.add_separator()
        s.add_command(label="Open accepted findings…", command=self._open_accepted)
        s.add_command(label="Save accepted findings as…", command=self._save_accepted_as)
        s.add_checkbutton(label="Show accepted findings in the Findings tab", variable=self.show_accepted, command=lambda: self._refresh_findings(force=True))
        c = tk.Menu(m, tearoff=0)
        m.add_cascade(label="Compare", menu=c)
        c.add_command(label="This crawl with a saved session…", command=self._compare_with)
        c.add_command(label="Two saved sessions…", command=self._compare_two)
        c.add_separator()
        c.add_command(label="Save the changes as an HTML report…", command=self._export_changes)
        c.add_separator()
        c.add_command(label="Add this crawl to a history file and show the trend…", command=lambda: self._trend(add=True))
        c.add_command(label="Show the trend of a history file…", command=lambda: self._trend(add=False))
        k = tk.Menu(m, tearoff=0)
        m.add_cascade(label="Crawl", menu=k)
        k.add_command(label="Start / stop", command=self._toggle_auto)
        k.add_command(label="Discard the paused crawl (start over)", command=self._start_over)
        k.add_command(label="Settings…", command=self._advanced)

    def _build_site_tab(self) -> None:
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  Site  ")
        ttk.Label(tab, text="What the crawl learned about the site as a whole: certificate, technologies, well-known files, sitemap.", style="Muted.TLabel").pack(anchor="w", pady=(8, 6))
        cols = (("cat", "Kind"), ("item", "Item"), ("detail", "Detail"), ("sev", "Severity"))
        wrap, self.site_tv = self._tree(tab, cols, (110, 260, 640, 90), {"sev": "center"}, height=14)
        wrap.pack(fill="both", expand=True)

    def _build_inputs_tab(self) -> None:
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  Inputs  ")
        ttk.Label(tab, text="Every place the site takes input: forms, URL parameters and the subdomains it refers to. Read from the pages; nothing is ever submitted.",
                  style="Muted.TLabel").pack(anchor="w", pady=(8, 6))
        cols = (("kind", "Kind"), ("where", "Where"), ("detail", "Detail"), ("flags", "Notes"))
        wrap, self.inputs_tv = self._tree(tab, cols, (90, 330, 470, 240), height=14)
        wrap.pack(fill="both", expand=True)
        self.inputs_tv.tag_configure("warn", foreground=C["medium"])

    def _build_changes_tab(self) -> None:
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  Changes  ")
        top = ttk.Frame(tab)
        top.pack(fill="x", pady=(8, 6))
        self.diff_lbl = ttk.Label(top, text="Use Compare ▸ to see what changed between two crawls.", style="Muted.TLabel")
        self.diff_lbl.pack(side="left")
        ttk.Button(top, text="Save as HTML…", style="Small.TButton", command=self._export_changes).pack(side="right")
        cols = (("sev", "Severity"), ("what", "What"), ("subject", "Where"), ("detail", "Detail"))
        wrap, self.ctv = self._tree(tab, cols, (90, 200, 480, 330), height=14)
        wrap.pack(fill="both", expand=True)
        self.ctv.tag_configure("good", foreground=C["ok"])

    def _tree(self, parent, columns, widths, anchors=None, height=10):
        wrap = ttk.Frame(parent)
        tv = ttk.Treeview(wrap, columns=[c[0] for c in columns], show="headings", height=height, selectmode="browse")
        for (cid, head), w in zip(columns, widths):
            tv.heading(cid, text=head)
            tv.column(cid, width=px(w), anchor=(anchors or {}).get(cid, "w"), stretch=cid in ("url", "text", "title", "link", "page", "detail", "subject"))
        ys = ttk.Scrollbar(wrap, orient="vertical", command=tv.yview)
        xs = ttk.Scrollbar(wrap, orient="horizontal", command=tv.xview)
        tv.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        tv.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)
        for tag in ("high", "medium", "low"):
            tv.tag_configure(tag, foreground=C[tag])
        tv.tag_configure("info", foreground=C["info"])
        return wrap, tv

    def _detail_box(self, parent, height=5):
        t = tk.Text(parent, height=height, bg=C["panel"], fg=C["text"], insertbackground=C["text"], relief="flat", font=MONO, wrap="word",
                    padx=10, pady=8, state="disabled", highlightthickness=0)
        for tag in ("high", "medium", "low", "info"):
            t.tag_configure(tag, foreground=C[tag], font=("Consolas", 10, "bold"))
        t.tag_configure("h", foreground=C["acc"], font=("Consolas", 10, "bold"))
        return t

    @staticmethod
    def _write(box: tk.Text, parts) -> None:
        box.configure(state="normal")
        box.delete("1.0", "end")
        for text, tag in parts:
            box.insert("end", text, tag or ())
        box.configure(state="disabled")

    def _build_links_tab(self) -> None:
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  Links  ")
        top = ttk.Frame(tab)
        top.pack(fill="x", pady=(8, 6))
        ttk.Label(top, text="Filter", style="Muted.TLabel").pack(side="left", padx=(0, 6))
        self.q_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.q_var, width=30).pack(side="left", padx=(0, 10))
        self.q_var.trace_add("write", lambda *_: self._refill())
        self.kind_var = tk.StringVar(value="all types")
        k = ttk.Combobox(top, textvariable=self.kind_var, values=["all types"] + list(wc.KINDS), width=11, state="readonly")
        k.pack(side="left", padx=(0, 10))
        k.bind("<<ComboboxSelected>>", lambda e: self._refill())
        self.risky_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Risky only", variable=self.risky_var, command=self._refill).pack(side="left")
        self.shown_lbl = ttk.Label(top, text="", style="Muted.TLabel")
        self.shown_lbl.pack(side="right")
        cols = (("n", "#"), ("risk", "Risk"), ("kind", "Type"), ("url", "URL"), ("text", "Link text"), ("page", "Found on"))
        self.detail = self._detail_box(tab, height=4)
        self.detail.pack(side="bottom", fill="x", pady=(6, 4))
        wrap, self.tv = self._tree(tab, cols, (48, 70, 80, 430, 230, 260), {"n": "e"}, height=6)
        wrap.pack(fill="both", expand=True)
        for cid, _ in cols:
            self.tv.heading(cid, command=lambda c=cid: self._sort_by(c))
        self.tv.bind("<<TreeviewSelect>>", self._show_link_detail)
        self.tv.bind("<Double-1>", lambda e: self._copy_selected())
        self._write(self.detail, [("Select a link to see why it was flagged. Double-click copies its URL.", "")])

    def _build_map_tab(self) -> None:
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  Map  ")
        top = ttk.Frame(tab)
        top.pack(fill="x", pady=(8, 6))
        ttk.Label(top, text="Layout", style="Muted.TLabel").pack(side="left", padx=(0, 6))
        self.map_layout = tk.StringVar(value="Radial")
        lc = ttk.Combobox(top, textvariable=self.map_layout, values=["Radial", "Tree"], width=8, state="readonly")
        lc.pack(side="left", padx=(0, 12))
        lc.bind("<<ComboboxSelected>>", lambda e: self._map_fit())
        self.map_ext, self.map_files = tk.BooleanVar(value=True), tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="External hosts", variable=self.map_ext, command=self._map_fit).pack(side="left", padx=(0, 8))
        ttk.Checkbutton(top, text="Files", variable=self.map_files, command=self._map_fit).pack(side="left", padx=(0, 12))
        ttk.Button(top, text="Fit", style="Small.TButton", command=self._map_fit).pack(side="left", padx=(0, 8))
        self.expand_btn = ttk.Button(top, text="Expand map", style="Small.TButton", command=self._toggle_expand)
        self.expand_btn.pack(side="left")
        self.map_lbl = ttk.Label(top, text="", style="Muted.TLabel")
        self.map_lbl.pack(side="right")
        legend = tk.Frame(tab, bg=C["bg"])
        legend.pack(side="bottom", fill="x")
        for color, text in ((C["page"], "crawled page"), (C["found"], "found, not crawled"), (C["ext"], "external host"), (C["file"], "file"), (C["bad"], "broken / high risk")):
            tk.Label(legend, text="●", fg=color, bg=C["bg"], font=("Segoe UI", 11)).pack(side="left", padx=(10, 2))
            tk.Label(legend, text=text, fg=C["mut"], bg=C["bg"], font=("Segoe UI", 9)).pack(side="left")
        tk.Label(legend, text="drag to pan · wheel to zoom · click a node", fg=C["mut"], bg=C["bg"], font=("Segoe UI", 9)).pack(side="right", padx=10)
        self.map_info = self._detail_box(tab, height=3)
        self.map_info.pack(side="bottom", fill="x", pady=(4, 2))
        self._write(self.map_info, [("Start a crawl and the site map builds here as pages are found.", "")])
        self.canvas = tk.Canvas(tab, bg=C["bg"], highlightthickness=1, highlightbackground=C["line"], cursor="fleur")
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Configure>", lambda e: self._map_fit())
        self.canvas.bind("<ButtonPress-1>", self._map_press)
        self.canvas.bind("<B1-Motion>", self._map_drag)
        self.canvas.bind("<ButtonRelease-1>", self._map_release)
        self.canvas.bind("<MouseWheel>", self._map_wheel)
        self.canvas.bind("<Button-4>", lambda e: self._map_zoom(1.15, e.x, e.y))
        self.canvas.bind("<Button-5>", lambda e: self._map_zoom(1 / 1.15, e.x, e.y))

    def _build_findings_tab(self) -> None:
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  Findings  ")
        top = ttk.Frame(tab)
        top.pack(fill="x", pady=(8, 6))
        ttk.Label(top, text="Every risky link, broken page and header problem, worst first. Right-click one to accept it (it stops counting as a problem).", style="Muted.TLabel").pack(side="left")
        ttk.Checkbutton(top, text="Show accepted", variable=self.show_accepted, command=lambda: self._refresh_findings(force=True)).pack(side="right")
        cols = (("sev", "Severity"), ("title", "Finding"), ("link", "Where"))
        wrap, self.ftv = self._tree(tab, cols, (90, 380, 640), height=14)
        wrap.pack(fill="both", expand=True)
        self.ftv.tag_configure("accepted", foreground=C["mut"])
        self.ftv.bind("<Button-3>", self._findings_menu)
        self.fmenu = tk.Menu(self, tearoff=0)

    def _build_security_tab(self) -> None:
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  Page security  ")
        ttk.Label(tab, text="Response-header audit for each page that was loaded.", style="Muted.TLabel").pack(anchor="w", pady=(8, 6))
        cols = (("page", "Page"), ("status", "Status"), ("h", "High"), ("m", "Medium"), ("l", "Low"))
        self.sec_detail = self._detail_box(tab, height=9)
        self.sec_detail.pack(side="bottom", fill="x", pady=(6, 4))
        wrap, self.stv = self._tree(tab, cols, (600, 70, 60, 80, 60), {"status": "center", "h": "center", "m": "center", "l": "center"}, height=4)
        wrap.pack(fill="both", expand=True)
        self.stv.bind("<<TreeviewSelect>>", self._show_sec_detail)

    def _build_log_tab(self) -> None:
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  Log  ")
        self.log = tk.Text(tab, bg=C["panel"], fg=C["mut"], relief="flat", font=MONO, state="disabled", wrap="word", padx=10, pady=8, highlightthickness=0)
        self.log.pack(fill="both", expand=True, pady=(8, 4))

    # ------------------------------------------------------------------ settings
    def _log(self, msg: str, status: bool = True) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", f"{datetime.now():%H:%M:%S}  {msg}\n")
        self.log.see("end")
        self.log.configure(state="disabled")
        if status:
            self.status_var.set(msg)

    def _pick_skin(self, sid: str, send: bool = True) -> None:
        self.settings.skin = sid
        for k, b in self.skin_buttons.items():
            b.configure(highlightbackground=C["acc"] if k == sid else C["panel"], fg=C["text"] if k == sid else C["mut"])
        if send and self.running:
            self.engine.send("skin", skin=sid)

    def _send_mode(self) -> None:
        self.settings.mode = MODES[self.mode_var.get()]
        if self.running:
            self.engine.send("mode", mode=self.settings.mode)

    def _toggle_summon(self) -> None:
        self.settings.summoned = not self.settings.summoned
        self.summon_btn.configure(text="Dismiss crawler" if self.settings.summoned else "Summon crawler",
                                  style="Stop.TButton" if self.settings.summoned else "Go.TButton")
        if self.running:
            self.engine.send("summon", on=self.settings.summoned)

    def _speed_changed(self) -> None:
        v = int(self.speed_var.get() // 50 * 50)
        self.speed_lbl.configure(text=f"{v} px/s")
        self.opts.scroll_speed = v
        if self.running:
            self.engine.send("speed", speed=v)

    def _preset_changed(self) -> None:
        name = self.preset_var.get()
        if name in fr.PRESETS:
            for k, v in fr.PRESETS[name].items():
                setattr(self.opts, k, v)
            self.speed_var.set(self.opts.scroll_speed)
            self.speed_lbl.configure(text=f"{self.opts.scroll_speed} px/s")
        self._refresh_opts_label()

    def _advanced(self) -> None:
        self._sync_opts()
        host = urlparse(self._normalized_url() or "").hostname or ""
        dlg = AdvancedDialog(self, self.opts, self.headless, self.auth, host)
        self.wait_window(dlg)
        if dlg.result:
            new, self.headless, self.auth = dlg.result
            for k, v in new.items():
                setattr(self.opts, k, v)
            self.preset_var.set("custom")
            self._refresh_opts_label()
            if not self.auth.empty:
                self._log("Login set (" + self.auth.describe() + "). It is used only for the site being crawled and is never saved.")

    def _refresh_opts_label(self) -> None:
        o = self.opts
        pause = f"{o.delay_min:g}s" if o.delay_min == o.delay_max else f"{o.delay_min:g}-{o.delay_max:g}s"
        extra = ", ".join(x for x in (f"{o.scope} scope", f"{o.concurrency} parallel", "ignores robots.txt" if o.ignore_robots else "") if x)
        self.opts_lbl.configure(text=f"pause {pause} · {extra}")

    def _sync_opts(self) -> fr.CrawlOptions:
        def num(var, default):
            try:
                return int(var.get())
            except (tk.TclError, ValueError):
                return default
        self.opts.depth, self.opts.max_pages = num(self.depth_var, 2), num(self.pages_var, 50)
        self.opts.scroll_speed = int(self.speed_var.get() // 50 * 50)
        return self.opts.clamped()

    def _normalized_url(self) -> str | None:
        raw = self.url_var.get().strip()
        if not raw:
            return ""
        try:
            return wc.normalize_target(raw)
        except ValueError as e:
            messagebox.showerror("WebCrawler", str(e))
            return None

    # ------------------------------------------------------------------ starting and stopping
    def _launch(self) -> None:
        url = self._normalized_url()
        if url is None:
            return
        if self.running:
            if url:
                self.engine.send("goto", url=url)
            return
        if self.headless:
            messagebox.showinfo("WebCrawler", "Headless mode has no window to scroll, so start it with Start crawl instead.")
            return
        self.pill.configure(text="● Starting browser…", foreground=C["medium"])
        self.launch_btn.configure(state="disabled")
        self.engine.send("start", settings=self._settings_for(url, False))

    def _settings_for(self, url: str, auto: bool, resume: dict | None = None) -> Settings:
        return Settings(url=url, browser=self.browser_var.get(), headless=self.headless, skin=self.settings.skin, mode=self.settings.mode,
                        summoned=self.settings.summoned or auto, auto=auto, opts=self._sync_opts(), auth=self.auth, resume=resume)

    def _resume_for(self, url: str) -> dict | None:
        """The paused crawl, if the link in the box is the site it belongs to."""
        r = self.resume_state
        return r if r and url and fr.normalize(url) == r.get("root") else None

    def _toggle_auto(self) -> None:
        if self.auto_on:
            if self.scanner is not None and self.scanner.is_alive():
                self.scanner.stop()
            else:
                self.engine.send("auto", on=False)
            return
        opts = self._sync_opts()
        if CRAWL_MODES[self.crawl_mode_var.get()] == "quick":
            self._start_quick(opts)
            return
        url = self._normalized_url()
        resume = self._resume_for(url or "")
        self._kind = "browser"
        if not self.running:
            if not url:
                messagebox.showinfo("WebCrawler", "Enter a link first.")
                return
            self.pill.configure(text="● Starting browser…", foreground=C["medium"])
            self.launch_btn.configure(state="disabled")
            self.engine.send("start", settings=self._settings_for(url, True, resume))
            self.resume_state = None
            return
        self.engine.send("auto", on=True, opts=opts, resume=resume, auth=self.auth)
        self.resume_state = None

    def _start_quick(self, opts: fr.CrawlOptions) -> None:
        url = self._normalized_url()
        if not url:
            messagebox.showinfo("WebCrawler", "Enter a link first.")
            return
        if urlparse(url).scheme not in ("http", "https"):
            messagebox.showinfo("WebCrawler", "A quick scan fetches pages over HTTP, so it needs an http(s) link. Use the browser mode for local files.")
            return
        resume = self._resume_for(url)
        if resume is None:
            self._clear(quiet=True)
        self._kind = "quick"
        self.resume_state = None
        self.scanner = httpscan.QuickScanner(url, opts, self.engine.store, self.graph, self.engine.events, self.engine.security, self.info, self.auth, resume)
        self.pill.configure(text="● Quick scan running", foreground=C["ok"])
        self.scanner.start()

    def _start_over(self) -> None:
        self.resume_state = None
        self.auto_btn.configure(text="▶  Start crawl")
        self._log("The paused crawl was discarded; the next crawl starts from the beginning.")

    def _clear(self, quiet: bool = False) -> None:
        if self.running:
            self.engine.send("reset")
        self.engine.store.clear()
        self.graph.clear()
        self.engine.security.clear()
        self.info.clear()
        self.resume_state = None
        self.auto_btn.configure(text="▶  Start crawl")
        self.rows.clear()
        self.broken.clear()
        self.sec.clear()
        for tv in (self.tv, self.ftv, self.stv):
            tv.delete(*tv.get_children())
        self._write(self.detail, [("Cleared.", "")])
        self._map_sel = None
        self._map_redraw(force=True)
        self._update_stats()
        if not quiet:
            self._log("Cleared captured links.")

    def _on_tab(self, index: int) -> bool:
        return str(self.nb.select()) == str(self.nb.tabs()[index])

    # ------------------------------------------------------------------ events from the engines
    def _poll(self) -> None:
        try:
            for _ in range(400):
                ev = self.engine.events.get_nowait()
                try:
                    self._handle(ev)
                except Exception as e:      # one bad event must not stop the window listening to the crawl
                    self._log(f"Could not show an event ({ev[0]}): {e}", status=False)
        except queue.Empty:
            pass
        if self.info.version != self._info_ver:
            self._info_ver = self.info.version
            self._dirty_findings = True
            if self._on_tab(3):
                self._refill_site()
            elif self._on_tab(4):
                self._refill_inputs()
        if self._dirty_findings and str(self.nb.select()) == str(self.nb.tabs()[2]):
            self._refresh_findings()
        if str(self.nb.select()) == str(self.nb.tabs()[1]) and self.graph.version != self._map_ver and time.monotonic() - self._map_drawn > self._map_gap:
            self._map_redraw()
        self._poll_id = self.after(100, self._poll)

    def _handle(self, ev: tuple) -> None:
        kind = ev[0]
        if kind == "link":
            _, link, findings = ev
            score = analysis.risk_score(findings)
            self.rows.append((link, findings, score))
            if self._passes(link, findings, score):
                self._insert_row(link, findings, score)
            self._dirty_findings = True
            self._update_stats()
        elif kind == "security":
            self.sec[ev[1].url] = ev[1]
            self._refill_security()
            self._dirty_findings = True
            self._update_stats()
        elif kind == "broken":
            self.broken.append(ev[1:])
            self._dirty_findings = True
            self._update_stats()
        elif kind == "progress":
            p = ev[1]
            el = int(p["elapsed"])
            self.status_var.set(f"{p['pages']} pages · {p['queued']} queued · {p['errors']} problems · {p['rps']:.1f}/s · {el // 60}:{el % 60:02d}")
        elif kind == "status":
            self._log(ev[1])
        elif kind == "page":
            self._log(f"Page {ev[2]}/{ev[3]}: {ev[1]}", status=False)
        elif kind == "cookies":
            host = urlparse(self._normalized_url() or "").hostname or ""
            mine = [{"name": c["name"], "value": c["value"], "domain": c.get("domain", ""), "path": c.get("path", "/"), "secure": bool(c.get("secure")),
                     "httpOnly": bool(c.get("httpOnly"))} for c in ev[1] if authmod._host_match(c.get("domain", ""), host)]
            self.auth = authmod.AuthConfig(mine, dict(self.auth.headers))
            self._log(f"Copied {len(mine)} cookie(s) for {host or 'the site'} from the browser. Quick scans will now use that login (it is not saved).")
        elif kind == "scan_done":
            s = ev[1]
            src = self.scanner if self._kind == "quick" else self.engine
            self.resume_state = src.resume_state if (s.get("resumable") and src is not None) else None
            why = "stopped" if s.get("stopped") else (f"{s['limit']} reached" if s.get("limit") else "finished")
            self._log(f"Crawl {why}: {s['pages']} page(s), {s['links']} links, {s['errors']} problem(s) in {s['seconds']:.1f}s.")
            skipped = s.get("skipped") or {}
            if skipped:
                self._log("Skipped: " + ", ".join(f"{v} {k}" for k, v in skipped.items()), status=False)
            self._map_redraw(force=True)
        elif kind == "auto":
            self.auto_on = ev[1]
            self.auto_btn.configure(text="■  Stop crawl" if ev[1] else ("▶  Resume crawl" if self.resume_state else "▶  Start crawl"),
                                    style="Stop.TButton" if ev[1] else "Accent.TButton")
            if not ev[1] and not self.running:
                self.pill.configure(text="● Idle", foreground=C["mut"])
        elif kind == "browser":
            state, msg = ev[1], ev[2]
            self.running = state == "running"
            self.launch_btn.configure(state="normal", text="Go" if self.running else "Launch")
            self.close_btn.configure(state="normal" if self.running else "disabled")
            self.pill.configure(text="● Browser running" if self.running else "● Idle", foreground=C["ok"] if self.running else C["mut"])
            if state == "error":
                messagebox.showerror("WebCrawler", msg)
            if msg:
                self._log(msg.splitlines()[0])

    # ------------------------------------------------------------------ links table
    def _passes(self, link, findings, score) -> bool:
        kind = self.kind_var.get()
        if kind != "all types" and link.kind != kind:
            return False
        if self.risky_var.get() and score < 8:
            return False
        q = self.q_var.get().strip().lower()
        return not q or q in link.href.lower() or q in link.text.lower()

    def _insert_row(self, link, findings, score) -> None:
        rating = analysis.rating(score)
        values = (link.n, rating if rating != "none" else "", link.kind, link.href, link.text or "", link.page)
        if self.tv.exists(str(link.n)):                      # already shown (a refill and a new event can meet): update it, do not fail
            self.tv.item(str(link.n), values=values, tags=(rating,) if rating != "none" else ())
            return
        self.tv.insert("", "end", iid=str(link.n), values=values, tags=(rating,) if rating != "none" else ())

    def _refill(self) -> None:
        self.tv.delete(*self.tv.get_children())
        shown = 0
        for link, findings, score in self.rows:
            if self._passes(link, findings, score):
                self._insert_row(link, findings, score)
                shown += 1
        self.shown_lbl.configure(text=f"{shown} of {len(self.rows)} shown")
        self._sort_by(self._sort[0], keep=True)

    def _sort_by(self, col: str, keep: bool = False) -> None:
        rev = self._sort[1] if keep else (not self._sort[1] if self._sort[0] == col else False)
        self._sort = (col, rev)
        order = {"high": 0, "medium": 1, "low": 2, "": 3}

        def key(iid):
            v = self.tv.set(iid, col)
            if col == "n":
                return int(v)
            if col == "risk":
                return order.get(v, 3)
            return v.lower()
        for i, iid in enumerate(sorted(self.tv.get_children(), key=key, reverse=rev)):
            self.tv.move(iid, "", i)

    def _link_for(self, iid: str):
        n = int(iid)
        return next((r for r in self.rows if r[0].n == n), None)

    def _show_link_detail(self, _e=None) -> None:
        sel = self.tv.selection()
        row = self._link_for(sel[0]) if sel else None
        if not row:
            return
        link, findings, score = row
        parts = [(link.href + "\n", "h"), (f"{link.kind}  ·  seen {link.count}×  ·  found on {link.page}\n", "info")]
        if findings:
            for f in sorted(findings, key=lambda f: analysis.SEVERITIES.index(f.severity)):
                parts.append((f"[{f.severity.upper()}] ", f.severity))
                parts.append((f.title + (f": {f.detail}" if f.detail else "") + "\n", ""))
        else:
            parts.append(("No findings for this link.", ""))
        self._write(self.detail, parts)

    def _copy_selected(self) -> None:
        sel = self.tv.selection()
        if sel:
            self.clipboard_clear()
            self.clipboard_append(self.tv.set(sel[0], "url"))
            self._log("Copied URL to the clipboard.")

    # ------------------------------------------------------------------ findings / security tabs
    def _all_findings(self) -> list[tuple]:
        """[(Finding, place shown, place used for matching)] for everything the crawl has found so far."""
        flat = []
        for link, findings, score in self.rows:
            for f in findings:
                if f.severity != "info":
                    flat.append((f, link.href, link.href))
        for p in self.sec.values():
            for f in p.findings:
                if f.severity != "info":
                    flat.append((f, p.url, p.url))
        for f, where in list(self.info.findings):
            if f.severity != "info":
                flat.append((f, where, where))
        for url, status, ref, reason in self.broken:
            internal = not ref or wc.classify(url, ref) != "external"
            flat.append((analysis.Finding("broken", "medium" if internal else "low", f"Broken link: {reason}", ref), url + (f"   (linked from {ref})" if ref else ""), url))
        return flat

    def _refresh_findings(self, force: bool = False) -> None:
        if not force and str(self.nb.select()) != str(self.nb.tabs()[2]) and not self._dirty_findings:
            return
        self._dirty_findings = False
        self.ftv.delete(*self.ftv.get_children())
        self._flat.clear()
        flat = sorted(self._all_findings(), key=lambda t: analysis.SEVERITIES.index(t[0].severity))
        shown = 0
        for accepted_pass in (False, True):
            if accepted_pass and not self.show_accepted.get():
                break
            for f, where, key in flat:
                if bool(self.accepted.match(f.code, key)) != accepted_pass or shown >= 3000:
                    continue
                shown += 1
                iid = self.ftv.insert("", "end", values=("ACCEPTED" if accepted_pass else f.severity.upper(), ("✓ " if accepted_pass else "") + f.title, where),
                                      tags=("accepted",) if accepted_pass else (f.severity,))
                self._flat[iid] = (f.code, key, f.title, accepted_pass)

    # ------------------------------------------------------------------ accepting findings
    def _findings_menu(self, event) -> None:
        iid = self.ftv.identify_row(event.y)
        if not iid or iid not in self._flat:
            return
        self.ftv.selection_set(iid)
        code, key, title, is_accepted = self._flat[iid]
        self.fmenu.delete(0, "end")
        if is_accepted:
            self.fmenu.add_command(label="Stop accepting this finding", command=lambda: self._unaccept(code, key))
        else:
            self.fmenu.add_command(label="Accept this finding…", command=lambda: self._accept(code, key, title))
        self.fmenu.tk_popup(event.x_root, event.y_root)

    def _accept(self, code: str, key: str, title: str) -> None:
        dlg = AcceptDialog(self, code, title, key)
        self.wait_window(dlg)
        if not dlg.result:
            return
        self.accepted.add(*dlg.result)
        self._log(f"Accepted {code} @ {dlg.result[1]}" + (f" until {dlg.result[3]}" if dlg.result[3] else ""))
        self._persist_accepted()
        self._refresh_findings(force=True)

    def _unaccept(self, code: str, key: str) -> None:
        e = self.accepted.match(code, key)
        if e:
            self.accepted.remove(e["code"], e["where"])
            self._log(f"No longer accepting {e['code']} @ {e['where']}")
            self._persist_accepted()
            self._refresh_findings(force=True)

    def _persist_accepted(self) -> None:
        """Keep the accepted findings in a file so they survive the app (asked for once, the first time)."""
        if not self.accepted_path:
            path = filedialog.asksaveasfilename(title="Where should the accepted findings be kept?", defaultextension=".json", initialfile="accepted.json",
                                                filetypes=[("Accepted findings", "*.json")])
            if not path:
                self._log("Accepted findings are only kept until you close the app (no file chosen).")
                return
            self.accepted_path = path
        try:
            self.accepted.save(self.accepted_path)
        except OSError as e:
            messagebox.showerror("WebCrawler", f"Could not save {self.accepted_path}: {e}")

    def _open_accepted(self) -> None:
        path = filedialog.askopenfilename(title="Accepted findings", filetypes=[("Accepted findings", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            self.accepted = accepted_mod.Accepted.load(path)
        except (ValueError, OSError) as e:
            messagebox.showerror("WebCrawler", str(e))
            return
        self.accepted_path = path
        self._log(f"Loaded {len(self.accepted)} accepted finding(s) from {path}")
        self._refresh_findings(force=True)

    def _save_accepted_as(self) -> None:
        path = filedialog.asksaveasfilename(title="Save accepted findings", defaultextension=".json", initialfile="accepted.json", filetypes=[("Accepted findings", "*.json")])
        if path:
            self.accepted_path = path
            self._persist_accepted()

    # ------------------------------------------------------------------ the trend over time
    def _trend(self, add: bool) -> None:
        if add and not self._have_data():
            messagebox.showinfo("WebCrawler", "Run or open a crawl first.")
            return
        path = (filedialog.asksaveasfilename(title="History file (it is created if it does not exist)", defaultextension=".json", initialfile="history.json",
                                              filetypes=[("History", "*.json")], confirmoverwrite=False)
                if add else filedialog.askopenfilename(title="History file", filetypes=[("History", "*.json")]))
        if not path:
            return
        try:
            h = history_mod.History.load(path)
            if add:
                start = self.url_var.get().strip() or self.graph.root
                h.add(history_mod.summarize(self._current_session(), self.accepted or None, self.diff), start)
                h.save(path)
                self._log(f"Added this crawl to {path} ({len(h.runs)} crawl(s))")
            page = Path(path).with_name(Path(path).stem + "-trend.html")
            page.write_text(history_mod.trend_html(h), encoding="utf-8", newline="")
        except (ValueError, OSError) as e:
            messagebox.showerror("WebCrawler", str(e))
            return
        webbrowser.open(page.resolve().as_uri())

    def _refill_security(self) -> None:
        sel = self.stv.selection()
        self.stv.delete(*self.stv.get_children())
        for i, (url, p) in enumerate(self.sec.items()):
            c = {s: sum(1 for f in p.findings if f.severity == s) for s in ("high", "medium", "low")}
            worst = "high" if c["high"] else "medium" if c["medium"] else "low" if c["low"] else "info"
            self.stv.insert("", "end", iid=str(i), values=(url, p.status, c["high"], c["medium"], c["low"]), tags=(worst,))
        kids = self.stv.get_children()
        if sel and self.stv.exists(sel[0]):
            self.stv.selection_set(sel[0])
        elif kids:
            self.stv.selection_set(kids[0])  # show the first page's findings straight away

    def _show_sec_detail(self, _e=None) -> None:
        sel = self.stv.selection()
        if not sel:
            return
        p = list(self.sec.values())[int(sel[0])]
        parts = [(p.url + "\n", "h")]
        for f in sorted(p.findings, key=lambda f: analysis.SEVERITIES.index(f.severity)):
            parts.append((f"[{f.severity.upper()}] ", f.severity))
            parts.append((f.title + (f": {f.detail}" if f.detail else "") + "\n", ""))
        if not p.findings:
            parts.append(("No header problems found.\n", ""))
        parts.append(("\nSecurity headers present:\n", "h"))
        parts.append(("\n".join(f"  {k}: {v[:110]}" for k, v in p.headers.items()) or "  (none)", ""))
        self._write(self.sec_detail, parts)

    def _update_stats(self) -> None:
        links = self.engine.store.all()
        st = self.graph.stats()
        self.stat["links"].configure(text=str(len(links)))
        self.stat["external"].configure(text=str(sum(1 for l in links if l.kind == "external")))
        self.stat["risky"].configure(text=str(sum(1 for r in self.rows if r[2] >= 8)))
        self.stat["pages"].configure(text=str(max(st["pages"], len(self.sec))))
        self.stat["broken"].configure(text=str(len(self.broken)))
        self.shown_lbl.configure(text=f"{len(self.tv.get_children())} of {len(self.rows)} shown")

    # ------------------------------------------------------------------ the map
    def _map_data(self):
        key = (self.graph.version, self.map_layout.get(), self.map_ext.get(), self.map_files.get())
        if self._map_cache and self._map_cache[0] == key:
            return self._map_cache[1:]
        nodes, edges = self.graph.view(externals=self.map_ext.get(), files=self.map_files.get(), cluster_at=800)
        lay = gr.radial_layout if self.map_layout.get() == "Radial" else gr.tree_layout
        pos = lay(nodes, edges, self.graph.root)
        self._map_cache = (key, nodes, edges, pos)
        return nodes, edges, pos

    def _map_fit(self) -> None:
        w, h = max(self.canvas.winfo_width(), 200), max(self.canvas.winfo_height(), 150)
        if self.map_layout.get() == "Radial":
            k = min(w, h) * 0.43
            self.mv.update(kx=k, ky=k, ox=w / 2, oy=h / 2)
        else:
            self.mv.update(kx=w * 0.46, ky=max(h - 90, 80), ox=w / 2, oy=40)
        self.mv["fitted"] = True
        self._map_redraw(force=True)

    def _toggle_expand(self) -> None:
        """Hide the controls above the tabs so the map gets the whole window, or bring them back."""
        hidden = not self._top[0].winfo_ismapped()
        if hidden:
            for f in self._top:
                f.pack(fill="x", pady=4, padx=16, before=self.nb)
        else:
            for f in self._top:
                f.pack_forget()
        self.expand_btn.configure(text="Show controls" if not hidden else "Expand map")
        self.after(80, self._map_fit)

    def _node_color(self, n: gr.Node) -> str:
        if n.kind == "cluster":
            return C["found"]
        if n.risk >= 40 or (n.visited and n.status is not None and (n.status == 0 or (n.status >= 400 and n.status not in (401, 403)))):
            return C["bad"]
        return {"external": C["ext"], "file": C["file"]}.get(n.kind, C["page"] if n.visited else C["found"])

    def _map_redraw(self, force: bool = False) -> None:
        if not hasattr(self, "canvas") or (not force and self.graph.version == self._map_ver):
            return
        if not force and str(self.nb.select()) != str(self.nb.tabs()[1]):
            return
        c = self.canvas
        c.delete("all")
        self._map_ver = self.graph.version
        self._map_drawn = time.monotonic()
        nodes, edges, pos = self._map_data()
        w, h = c.winfo_width(), c.winfo_height()
        self._map_screen = {}
        if not pos:
            c.create_text(w / 2, h / 2, text="The map appears here as soon as a crawl finds its first page.", fill=C["mut"], font=("Segoe UI", 12))
            self.map_lbl.configure(text="")
            return
        mv = self.mv
        sp = {u: (mv["ox"] + x * mv["kx"], mv["oy"] + y * mv["ky"]) for u, (x, y) in pos.items()}
        self._map_screen = sp
        sel = self._map_sel
        for (a, b), _count in edges:
            if a in sp and b in sp:
                hot = sel in (a, b)
                c.create_line(*sp[a], *sp[b], fill="#5fb8ff" if hot else "#26335a", width=2 if hot else 1)
        radial = self.map_layout.get() == "Radial"
        rings: dict = {}
        for x, y in pos.values():
            key = round(math.hypot(x, y), 2) if radial else round(y, 2)
            rings[key] = rings.get(key, 0) + 1
        spacing = (2 * math.pi * mv["kx"] if radial else 2 * mv["kx"]) / max(rings.values())   # pixels between neighbours on the busiest ring
        zoomed = spacing > px(70)   # label everything only when the labels will not pile on top of each other
        for n in nodes:
            if n.url not in sp:
                continue
            x, y = sp[n.url]
            r = px(4 + min(9, math.sqrt(max(n.count, 1)) * 1.6) + (2 if n.kind == "page" else 0))
            c.create_oval(x - r, y - r, x + r, y + r, fill=self._node_color(n), outline="#ffffff" if n.url == sel else C["bg"], width=2 if n.url == sel else 1)
            if n.risk >= 8:
                c.create_oval(x - r - px(3), y - r - px(3), x + r + px(3), y + r + px(3), outline=C["low"], dash=(2, 3))
            if zoomed or n.url == sel or n.depth == 0 or n.kind == "cluster" or (n.visited and len(nodes) <= 40):
                c.create_text(x + r + 4, y, text=(n.label or n.url)[:26], anchor="w", fill=C["text"], font=("Segoe UI", 8))
        st = self.graph.stats()
        grouped = sum(1 for n in nodes if n.kind == "cluster")
        self.map_lbl.configure(text=f"{st['pages']} pages · {len(nodes)} nodes · {len(edges)} links" + (f" · {st['broken']} broken" if st["broken"] else "")
                               + (f" · {grouped} groups of similar pages" if grouped else ""))
        self._map_gap = max(0.7, 6 * (time.monotonic() - self._map_drawn))        # a heavy map is redrawn less often, so a busy crawl is never slowed by it

    def _map_hit(self, x: float, y: float):
        best, bd = None, 14.0
        for u, (px, py) in self._map_screen.items():
            d = math.hypot(px - x, py - y)
            if d < bd:
                best, bd = u, d
        return best

    def _map_press(self, e) -> None:
        self._drag = (e.x, e.y, self.mv["ox"], self.mv["oy"], False)

    def _map_drag(self, e) -> None:
        if not self._drag:
            return
        x0, y0, ox, oy, moved = self._drag
        dx, dy = e.x - x0, e.y - y0
        if abs(dx) + abs(dy) > 3 or moved:
            self.canvas.move("all", (ox + dx) - self.mv["ox"], (oy + dy) - self.mv["oy"])
            self.mv["ox"], self.mv["oy"] = ox + dx, oy + dy
            self._drag = (x0, y0, ox, oy, True)

    def _map_release(self, e) -> None:
        d, self._drag = self._drag, None
        if d and not d[4]:
            self._map_sel = self._map_hit(e.x, e.y)
            self._map_show(self._map_sel)
            self._map_redraw(force=True)
        elif d:
            self._map_redraw(force=True)

    def _map_wheel(self, e) -> None:
        self._map_zoom(1.15 if e.delta > 0 else 1 / 1.15, e.x, e.y)

    def _map_zoom(self, f: float, x: float, y: float) -> None:
        mv = self.mv
        mv["ox"], mv["oy"] = x - (x - mv["ox"]) * f, y - (y - mv["oy"]) * f
        mv["kx"] *= f
        mv["ky"] *= f
        self._map_redraw(force=True)

    def _map_show(self, url: str | None) -> None:
        if not url:
            self._write(self.map_info, [("Click a node to see its details.", "")])
            return
        nodes, edges, _ = self._map_data()
        n = next((x for x in nodes if x.url == url), None)
        if not n:
            return
        out = sum(1 for (a, _b), _ in edges if a == url)
        inc = sum(1 for (_a, b), _ in edges if b == url)
        if n.kind == "cluster":
            more = f"\n... and {n.count - len(n.members)} more" if n.count > len(n.members) else ""
            self._write(self.map_info, [(n.title + "\n", "h"), ("A group of similar pages, drawn as one to keep the map readable. All of them are in the Links tab.\n" + "\n".join(n.members[:8]) + more, "info")])
            return
        parts = [(n.url + "\n", "h")]
        bits = [n.kind + (f" ({n.count} URLs)" if n.count > 1 else ""), f"status {n.status}" if n.status is not None else "", f"depth {n.depth}" if n.depth is not None else "",
                f"risk {n.risk}" if n.risk else "", f"links to {out}", f"linked from {inc}"]
        parts.append(("  ·  ".join(b for b in bits if b) + (f"\n{n.title}" if n.title else ""), "info"))
        self._write(self.map_info, parts)

    # ------------------------------------------------------------------ the Site tab
    def _refill_site(self) -> None:
        if not hasattr(self, "site_tv") or not self._on_tab(3):
            return
        tv = self.site_tv
        tv.delete(*tv.get_children())
        d = self.info.to_dict()
        rank = {"high": 0, "medium": 1, "low": 2, "info": 3}

        def add(cat, item, detail, sev="info"):
            tv.insert("", "end", values=(cat, item, detail, sev.upper() if sev != "info" else ""), tags=(sev,))
        for host, t in d["tls"].items():
            fs = checks.tls_findings(t)
            sev = min((f.severity for f in fs), key=lambda s: rank[s], default="info")
            if t.get("ok") or t.get("verify_error"):
                bits = [t.get("protocol", ""), f"issuer {t['issuer']}" if t.get("issuer") else "", f"expires {t['not_after']} ({t['days_left']} days)" if t.get("days_left") is not None else "",
                        "" if t.get("verified") else ("NOT trusted: " + t["verify_error"] if t.get("verify_error") else t.get("unverified", "not verified"))]
                add("TLS", host, "  ·  ".join(b for b in bits if b), sev)
            else:
                add("TLS", host, t.get("error", "no answer"))
        for t in d["tech"]:
            sev = min((f.severity for f in checks.tech_findings([checks.Tech(t["name"], t.get("version", ""))])), key=lambda s: rank[s], default="info")
            add("Technology", f"{t['name']} {t.get('version', '')}".strip(), f"{t.get('category', '')}  ·  seen from {t.get('evidence', '')}", sev)
        for f in d["files"]:
            bad = f["exposed"] and f["severity"] != "info"
            add("File", f["path"], ("EXPOSED: " if bad else "found: " if f["exposed"] else "not found: ") + f["title"], f["severity"] if bad else "info")
        seeds = d["seeds"]
        if seeds:
            add("Sitemap", f"{len(seeds.get('sitemaps', []))} sitemap(s)", f"{seeds.get('pages', 0)} page(s) listed", "info")
            r = seeds.get("robots", {})
            if r:
                add("robots.txt", f"{len(r.get('disallow', []))} Disallow entries", ", ".join(r.get("disallow", [])[:6]), "info")
            for e in seeds.get("errors", [])[:3]:
                add("Sitemap", "problem", e, "low")
        dns = d.get("dns") or {}
        if dns:
            dom = dns.get("domain", "")
            add("DNS", dom, f"name servers: {', '.join(dns.get('ns', [])) or 'none found'}")
            add("DNS", "mail servers (MX)", ", ".join(dns.get("mx", [])) or "none")
            add("DNS", "SPF", dns.get("spf") or "none" + (f"  ·  needs {dns['spf_lookups']} lookups" if dns.get("spf_lookups") else ""))
            add("DNS", "DMARC", dns.get("dmarc") or "none")
            add("DNS", "DKIM keys found", ", ".join(dns.get("dkim", [])) or "none at the common selector names")
            add("DNS", "MTA-STS / TLS-RPT", f"{'yes' if dns.get('mta_sts') else 'no'} / {'yes' if dns.get('tls_rpt') else 'no'}")
            add("DNS", "CAA", "; ".join(dns.get("caa", [])) or "none")
            add("DNS", "DNSSEC", "enabled" if dns.get("dnssec") else "not enabled")
            for e in dns.get("errors", [])[:2]:
                add("DNS", "problem", e, "low")
        for f in d["findings"]:
            if f["severity"] != "info":
                add("Finding", f["title"], f.get("where", ""), f["severity"])
        if not tv.get_children():
            add("", "Nothing yet", "Start a crawl: the certificate, technologies, sitemap and (if enabled) well-known files appear here.")

    def _refill_inputs(self) -> None:
        if not hasattr(self, "inputs_tv") or not self._on_tab(4):
            return
        tv = self.inputs_tv
        tv.delete(*tv.get_children())
        d = self.info.to_dict()

        def add(kind, where, detail, notes="", warn=False):
            tv.insert("", "end", values=(kind, where, detail, notes), tags=("warn",) if warn else ())
        forms = sorted(d.get("forms", []), key=lambda f: (not f.get("password"), f.get("action", "")))
        for f in forms:
            names = ", ".join(x["name"] or f"({x['type']})" for x in f.get("fields", [])[:10])
            notes = [n for n, on in (("password", f.get("password")), ("file upload", f.get("upload")), ("no CSRF token", f.get("method") == "post" and not f.get("csrf") and not f.get("search")
                                                                                                          and any(x["type"] not in ("hidden", "submit", "button") for x in f.get("fields", []))),
                                     ("sends to another site", f.get("cross_origin")), ("search", f.get("search"))) if on]
            add("Form", f"{f.get('method', 'get').upper()} {f.get('action', '')}", f"{names or 'no fields'}  ·  on {f.get('page', '')}", ", ".join(notes), warn=bool(notes) and not f.get("search"))
        for name, e in sorted(d.get("params", {}).items(), key=lambda kv: -kv[1]["count"]):
            add("Parameter", "?" + name, f"{e['count']} URL(s), e.g. {e['examples'][0] if e.get('examples') else ''}")
        for host, e in sorted(d.get("hosts", {}).items()):
            addrs = e.get("addresses")
            add("Host", host, ("does not resolve" if addrs == [] else ", ".join(addrs[:3]) if addrs else "not looked up") + f"  ·  seen in: {', '.join(e.get('sources', []))}",
                "stale name?" if addrs == [] else "", warn=addrs == [])
        if not tv.get_children():
            add("", "Nothing yet", "Crawl a site: its forms, URL parameters and subdomains appear here.")

    # ------------------------------------------------------------------ sessions: save, open, compare
    def _current_session(self) -> dict:
        start = self.url_var.get().strip() or self.graph.root
        return snapshot.build(start, self._sync_opts(), self.engine.store, self.graph, self.engine.security, self.broken, self.info, self.resume_state)

    def _have_data(self) -> bool:
        return bool(self.engine.store.all() or self.graph.nodes)

    def _save_session(self) -> None:
        if not self._have_data():
            messagebox.showinfo("WebCrawler", "Nothing to save yet.")
            return
        host = urlparse(self.url_var.get().strip() if "//" in self.url_var.get() else "//" + self.url_var.get().strip()).hostname or "crawl"
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("WebCrawler session", "*.json")], title="Save session",
                                            initialfile=f"session-{host}-{datetime.now():%Y%m%d-%H%M}.json")
        if not path:
            return
        try:
            snapshot.save(path, self._current_session())
        except OSError as e:
            messagebox.showerror("WebCrawler", f"Could not save: {e}")
            return
        self._log(f"Session saved to {path}" + (" (the paused crawl can be resumed from it)" if self.resume_state else ""))

    def _open_session(self) -> None:
        if self.auto_on:
            messagebox.showinfo("WebCrawler", "Stop the running crawl first.")
            return
        path = filedialog.askopenfilename(title="Open session", filetypes=[("WebCrawler session", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            data = snapshot.load(path)
        except (ValueError, OSError) as e:
            messagebox.showerror("WebCrawler", str(e))
            return
        self._load_session(data)

    def _load_session(self, data: dict) -> None:
        self._clear(quiet=True)
        broken, resume = snapshot.restore(data, self.engine.store, self.graph, self.engine.security, self.info)
        self.broken = list(broken)
        self.sec = dict(self.engine.security)
        self.rows = []
        for l in self.engine.store.all():
            f = analysis.assess_link(l.href, l.kind, l.page)
            self.rows.append((l, f, analysis.risk_score(f)))
        self.url_var.set(data.get("start", ""))
        saved = snapshot.options_from(data)
        for k in fr.CrawlOptions.__dataclass_fields__:
            setattr(self.opts, k, getattr(saved, k))
        self.depth_var.set(self.opts.depth)
        self.pages_var.set(self.opts.max_pages)
        self.preset_var.set("custom")
        self._refresh_opts_label()
        self.resume_state = resume
        self.auto_btn.configure(text="▶  Resume crawl" if resume else "▶  Start crawl")
        self._refill()
        self._refill_security()
        self._dirty_findings = True
        self._info_ver = -1
        self._map_cache = None
        self._map_fit()
        self._update_stats()
        self._log(f"Opened a session from {data.get('created', '?')}: {len(self.rows)} links, {self.graph.stats()['pages']} pages"
                  + (f". It was paused with {len(resume.get('queue', []))} page(s) waiting: press Resume crawl." if resume else "."))

    def _compare_with(self) -> None:
        if not self._have_data():
            messagebox.showinfo("WebCrawler", "Run or open a crawl first, then compare it with an earlier one.")
            return
        path = filedialog.askopenfilename(title="Compare this crawl with which earlier session?", filetypes=[("WebCrawler session", "*.json")])
        if not path:
            return
        try:
            old = snapshot.load(path)
        except (ValueError, OSError) as e:
            messagebox.showerror("WebCrawler", str(e))
            return
        self._show_diff(snapshot.diff(old, self._current_session(), self.accepted or None))

    def _compare_two(self) -> None:
        paths = []
        for title in ("Older session", "Newer session"):
            p = filedialog.askopenfilename(title=title, filetypes=[("WebCrawler session", "*.json")])
            if not p:
                return
            paths.append(p)
        try:
            self._show_diff(snapshot.diff(snapshot.load(paths[0]), snapshot.load(paths[1]), self.accepted or None))
        except (ValueError, OSError) as e:
            messagebox.showerror("WebCrawler", str(e))

    def _show_diff(self, d) -> None:
        self.diff = d
        tv = self.ctv
        tv.delete(*tv.get_children())
        good = {"risk-resolved", "header-improved", "site-resolved"}
        titles = dict(snapshot.SECTIONS)
        sec = d.by_section()
        for key, _ in snapshot.SECTIONS:
            for c in sec.get(key, []):
                tv.insert("", "end", values=(c.severity.upper() if c.severity != "info" else "", titles[key], c.subject, c.detail), tags=("good",) if key in good else (c.severity,))
        reg = len(d.regressions())
        self.diff_lbl.configure(text=f"{d.old.get('created', '?')}  →  {d.new.get('created', '?')}:  {d.summary()}", foreground=C["high"] if reg else C["ok"])
        if not d.changes:
            tv.insert("", "end", values=("", "No differences", "", ""))
        self.nb.select(self.nb.tabs()[6])
        self._log("Comparison: " + d.summary())

    def _export_changes(self) -> None:
        if self.diff is None:
            messagebox.showinfo("WebCrawler", "Compare two crawls first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML report", "*.html")], initialfile=f"changes-{datetime.now():%Y%m%d-%H%M}.html")
        if not path:
            return
        Path(path).write_text(report.build_diff_html(self.diff), encoding="utf-8", newline="")
        self._log(f"Saved {path}")
        if messagebox.askyesno("WebCrawler", "Open it in your browser now?"):
            webbrowser.open(Path(path).resolve().as_uri())

    # ------------------------------------------------------------------ logins
    def _copy_login(self) -> None:
        if not self.running:
            messagebox.showinfo("WebCrawler", "Open a browser with Launch, sign in to the site there, then use this to reuse that login in a quick scan.")
            return
        self.engine.send("export_cookies")

    def _forget_login(self) -> None:
        self.auth = authmod.AuthConfig()
        self._log("The login was forgotten.")

    # ------------------------------------------------------------------ export
    def _export(self, fmt: str) -> None:
        links = self.engine.store.all()
        if not links and fmt != "map":
            messagebox.showinfo("WebCrawler", "Nothing captured yet.")
            return
        if fmt == "map" and not self.graph.nodes:
            messagebox.showinfo("WebCrawler", "The map is empty. Run a crawl first.")
            return
        start = self.url_var.get().strip()
        pages = list(self.sec.values())
        makers = {"csv": (".csv", [("CSV", "*.csv")], lambda: wc.to_csv(links)), "json": (".json", [("JSON", "*.json")], lambda: wc.to_json(links, start)),
                  "html": (".html", [("HTML report", "*.html")], lambda: report.build_html(start, links, pages, self.broken, self.graph.stats(), self.info.to_dict(), self.accepted or None)),
                  "map": (".html", [("Interactive map", "*.html")], lambda: gr.to_html(self.graph, "Site map: " + start))}
        ext, types, make = makers[fmt]
        name = {"html": "report", "map": "sitemap"}.get(fmt, "links")
        path = filedialog.asksaveasfilename(defaultextension=ext, filetypes=types, initialfile=f"{name}-{datetime.now():%Y%m%d-%H%M%S}{ext}", title="Export")
        if not path:
            return
        Path(path).write_text(make(), encoding="utf-8", newline="")
        self._log(f"Saved {path}")
        if fmt in ("html", "map") and messagebox.askyesno("WebCrawler", "Open it in your browser now?"):
            webbrowser.open(Path(path).resolve().as_uri())

    def _export_all(self) -> None:
        links = self.engine.store.all()
        if not links:
            messagebox.showinfo("WebCrawler", "Nothing captured yet.")
            return
        folder = filedialog.askdirectory(title="Choose a folder for the results")
        if not folder:
            return
        start = self.url_var.get().strip()
        out = Path(folder)
        files = {"links.csv": wc.to_csv(links), "links.json": wc.to_json(links, start), "links.txt": wc.to_txt(links),
                 "report.html": report.build_html(start, links, list(self.sec.values()), self.broken, self.graph.stats(), self.info.to_dict(), self.accepted or None),
                 "sitemap.html": gr.to_html(self.graph, "Site map: " + start), "graph.json": self.graph.to_json()}
        if self.diff is not None:
            files["changes.html"] = report.build_diff_html(self.diff)
        for name, text in files.items():
            (out / name).write_text(text, encoding="utf-8", newline="")
        snapshot.save(str(out / "session.json"), self._current_session())
        self._log(f"Saved {len(files) + 1} files to {out}")

    def _close(self) -> None:
        try:
            self.after_cancel(self._poll_id)
        except (AttributeError, tk.TclError):
            pass
        if self.scanner is not None and self.scanner.is_alive():
            self.scanner.stop()
            self.scanner.join(timeout=3)
        self.engine.send("quit")
        self.engine.join(timeout=4)
        self.destroy()
        # Tk variables and images that are still around are cleaned up by whichever thread happens to run the garbage collector, and a Tcl call
        # from a thread other than the main one blocks for a second ("main thread is not in main loop"): collect them here, on the main thread
        import gc
        gc.collect()


def _dpi_aware() -> None:
    """Crisp text on high-DPI Windows screens (no effect elsewhere)."""
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    _dpi_aware()
    argv = sys.argv[1:] if argv is None else argv
    try:
        app = App(argv[0] if argv else "")
        app.mainloop()
    except Exception:
        # started by double-click (pythonw) there is no console to show a traceback in: say what happened and keep the details
        import traceback
        details = traceback.format_exc()
        log = HERE / "webcrawler-gui-error.log"
        try:
            log.write_text(details, encoding="utf-8")
        except OSError:
            log = None
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("WebCrawler could not start", details.strip().splitlines()[-1] + (f"\n\nDetails were saved to {log}" if log else ""))
            root.destroy()
        except Exception:
            pass
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
