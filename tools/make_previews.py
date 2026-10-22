"""Render the crawler skins to PNG thumbnails for the GUI (assets/skins/*.png) and the app icon.
Uses the same SVG art as the website, so the two always match.  Run from the WebCrawler folder:  python tools/make_previews.py
"""
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent.parent
ART = HERE.parent.parent / "SentinelPortfolioV2" / "WebProjects" / "crawler-art.js"
IDS = ["sentinel", "hacker", "spider", "packet", "lock", "drone", "radar", "bot"]


def main() -> None:
    if not ART.exists():
        raise SystemExit(f"The skin artwork lives in the author's portfolio site (expected at {ART}); this tool only regenerates assets/ from it.")
    art = ART.read_text(encoding="utf-8")
    out = HERE / "assets" / "skins"
    out.mkdir(parents=True, exist_ok=True)
    html = f"<style>html,body{{margin:0;background:transparent}}svg{{display:block}}</style><script>{art}</script><div id=s></div>"
    with sync_playwright() as pw:
        try:
            b = pw.chromium.launch(channel="chrome")
        except Exception:
            b = pw.chromium.launch()
        for size, folder, ids in ((56, out, IDS), (128, HERE / "assets", ["sentinel"])):
            page = b.new_page(viewport={"width": size, "height": size})
            page.set_content(html)
            for i in ids:
                page.evaluate("(id) => { document.getElementById('s').innerHTML = CrawlerArt.svg(id); const v = document.querySelector('svg'); v.setAttribute('width', %d); v.setAttribute('height', %d); }" % (size, size), i)
                name = "icon.png" if folder.name == "assets" else f"{i}.png"
                page.screenshot(path=str(folder / name), omit_background=True)
                print("wrote", folder / name)
        b.close()


if __name__ == "__main__":
    main()
