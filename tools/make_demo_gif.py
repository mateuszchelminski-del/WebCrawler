"""Record docs/demo.gif: the browser crawler, a quick scan building the map, the findings, and what changed between two crawls.

    python tools/make_demo_gif.py            # needs Pillow (pip install pillow), Playwright with Chrome/Edge/Chromium, and a display

It starts serve_demo.py (the deliberately imperfect demo site) on 127.0.0.1:8000 itself, drives the real app, grabs frames of its window
and writes an optimised GIF of about 20 seconds. The window must stay in front while it runs: leave the mouse and keyboard alone.
"""
from __future__ import annotations

import io
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = ROOT / "docs" / "demo.gif"
WIDTH = 880

try:
    from PIL import Image, ImageDraw, ImageFont, ImageGrab
except ImportError:
    sys.exit("This needs Pillow: pip install pillow")


def font(size: int):
    for name in ("segoeuib.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def caption(img: Image.Image, text: str) -> Image.Image:
    """A band at the bottom saying what is being shown."""
    img = img.convert("RGB")
    w, h = img.size
    band = int(h * 0.075)
    out = Image.new("RGB", (w, h + band), (11, 16, 32))
    out.paste(img, (0, 0))
    d = ImageDraw.Draw(out)
    f = font(max(13, band // 2))
    d.text((14, h + (band - f.size) // 2 - 1), text, fill=(63, 209, 255), font=f)
    return out


def shrink(img: Image.Image) -> Image.Image:
    h = round(img.height * WIDTH / img.width)
    return img.resize((WIDTH, h), Image.LANCZOS)


def wait_for(url: str, seconds: float = 10) -> None:
    end = time.time() + seconds
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=1).read(10)
            return
        except OSError:
            time.sleep(0.2)
    raise SystemExit(f"the demo server did not start at {url}")


SERVERS: list = []


def serve(v2: bool) -> subprocess.Popen:
    """(Re)start the demo site: the plain version, or --v2 (after a careless change)."""
    for old in SERVERS:
        old.terminate()
        old.wait(timeout=5)
    SERVERS.clear()
    time.sleep(0.5)
    p = subprocess.Popen([sys.executable, str(ROOT / "serve_demo.py")] + (["--v2"] if v2 else []), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    SERVERS.append(p)
    wait_for("http://127.0.0.1:8000/index.html")
    return p


def browser_frames(seconds: float = 3.2, every: float = 0.16) -> list:
    """The animated crawler working through a page in a real browser."""
    import webcrawler as wc
    from playwright.sync_api import sync_playwright
    frames = []
    with sync_playwright() as pw:
        _, browser, ctx = wc.launch_any(pw, "auto", True, None, Exception)
        total = [0]

        def capture(source, payload):
            import json
            total[0] += len(json.loads(payload))
            return total[0]
        ctx.expose_binding("__wc_capture", capture)
        ctx.add_init_script(wc.overlay_script("sentinel", "view", True))
        page = ctx.new_page()
        page.set_viewport_size({"width": 1180, "height": 640})
        page.goto("http://127.0.0.1:8000/index.html")
        t0 = time.time()
        step = 0
        while time.time() - t0 < seconds:
            frames.append(caption(shrink(Image.open(io.BytesIO(page.screenshot()))), "Browser crawl: the crawler captures links as the page scrolls"))
            step += 1
            if step % 3 == 0:
                page.mouse.wheel(0, 140)
            time.sleep(every)
        (browser or ctx).close()
    return frames


def window_frame(app, text: str) -> Image.Image:
    app.update()
    x, y, w, h = app.winfo_rootx(), app.winfo_rooty(), app.winfo_width(), app.winfo_height()
    return caption(shrink(ImageGrab.grab(bbox=(x, y, x + w, y + h))), text)


def pump(app, seconds: float) -> None:
    end = time.time() + seconds
    while time.time() < end:
        app.update()
        time.sleep(0.02)


def gui_frames() -> list:
    import webcrawler_gui as g
    app = g.App("http://127.0.0.1:8000/index.html")
    app.attributes("-topmost", True)
    frames: list = []          # (image, seconds to show it)

    def scan(text_during: str, grab_every: float, tab: int) -> None:
        app.crawl_mode_var.set("Quick scan (no browser)")
        app.depth_var.set(3)
        app.opts.probe_files = True
        app.opts.delay_min = app.opts.delay_max = 0.25
        app.nb.select(tab)
        app._toggle_auto()
        last = 0.0
        while app.auto_on or (app.scanner and app.scanner.is_alive()):
            app.update()
            time.sleep(0.02)
            if time.time() - last >= grab_every:
                last = time.time()
                frames.append((window_frame(app, text_during), grab_every))
        pump(app, 0.6)
    try:
        app.update()
        time.sleep(0.5)
        app.nb.select(0)
        pump(app, 0.4)
        scan("Quick scan: pages are fetched over HTTP, the site map builds live", 0.3, 1)
        app._map_fit()
        frames.append((window_frame(app, "The site map: click a node, pan, zoom"), 1.1))
        yesterday = app._current_session()
        for tab, text, hold in ((2, "Findings, worst first: headers, links, cookies, TLS, exposed files", 1.4), (3, "Site-wide checks: certificate, technologies, sitemap, well-known files", 1.2),
                                (4, "Every form, parameter and subdomain the site exposes", 0.9)):
            app.nb.select(tab)
            pump(app, 0.5)
            frames.append((window_frame(app, text), hold))
        # the same site after a careless change
        app._clear(quiet=True)
        serve(True)
        scan("Crawl again later: the same site after a change", 1.2, 1)
        app._show_diff(g.snapshot.diff(yesterday, app._current_session()))
        pump(app, 0.5)
        frames.append((window_frame(app, "Compare crawls: new problems, weaker headers, what was fixed"), 2.6))
    finally:
        app._close()
    return frames


def main() -> int:
    try:                    # window coordinates and screen grabs must use the same pixels
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    OUT.parent.mkdir(parents=True, exist_ok=True)
    serve(False)
    try:
        part_a = [(f, 0.16) for f in browser_frames()]
        part_b = gui_frames()
    finally:
        for p in SERVERS:
            p.terminate()
    frames = part_a + part_b
    images = [f for f, _ in frames]
    durations = [int(d * 1000) for _, d in frames]
    # one shared palette keeps the colours steady between frames and the file small
    pal = images[len(images) // 2].convert("P", palette=Image.ADAPTIVE, colors=128)
    quant = [im.quantize(palette=pal, dither=Image.NONE) for im in images]
    quant[0].save(OUT, save_all=True, append_images=quant[1:], duration=durations, loop=0, optimize=True, disposal=1)
    print(f"Wrote {OUT}: {len(images)} frames, {sum(durations) / 1000:.1f} s, {OUT.stat().st_size / 1024 / 1024:.1f} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
