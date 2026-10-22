"""history.py: how a site's problems change from crawl to crawl.

Every monitored crawl appends one line of numbers to a history file (open problems by severity, pages, links, what changed since the
previous crawl). `trend_html` draws them as a chart you can open in a browser or keep as a build artifact: no scripts, no external files.

    h = History.load("history.json")
    h.add(summarize(session, accepted, diff))
    h.save("history.json")
    Path("trend.html").write_text(trend_html(h))
"""
from __future__ import annotations

import html
import json
import os
import tempfile
from pathlib import Path

import snapshot

FORMAT = "webcrawler-history"
VERSION = 1
MAX_RUNS = 1000


def summarize(session: dict, accepted=None, diff=None) -> dict:
    """One crawl as a row of numbers. `accepted` findings are counted apart; `diff` (against the previous crawl) adds what changed."""
    findings = snapshot.all_findings(session)
    if accepted:
        open_, done = accepted.split(findings)
    else:
        open_, done = findings, []
    sev = {s: sum(1 for f in open_ if f["severity"] == s) for s in ("high", "medium", "low")}
    row = {"created": session.get("created", ""), "pages": len(session.get("pages", [])) or sum(1 for n in session.get("graph", {}).get("nodes", []) if n.get("visited")),
           "links": len(session.get("links", [])), "broken": len(session.get("broken", [])), **sev, "accepted": len(done)}
    if diff is not None:
        c = diff.counts()
        row.update({"regressions": len(diff.regressions()), "new_pages": c.get("page-added", 0), "removed_pages": c.get("page-removed", 0),
                    "changed_pages": c.get("page-changed", 0), "fixed": c.get("risk-resolved", 0) + c.get("site-resolved", 0) + c.get("header-improved", 0)})
    return row


class History:
    def __init__(self, start: str = "", runs: list | None = None) -> None:
        self.start = start
        self.runs: list[dict] = list(runs or [])

    @classmethod
    def load(cls, path: str | os.PathLike) -> "History":
        p = Path(path).expanduser()
        if not p.exists():
            return cls()
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"{p} is not valid JSON: {e}")
        if not isinstance(data, dict) or data.get("format") != FORMAT:
            raise ValueError(f"{p} is not a WebCrawler history file")
        return cls(str(data.get("start", "")), [r for r in data.get("runs", []) if isinstance(r, dict)][-MAX_RUNS:])

    def add(self, row: dict, start: str = "") -> None:
        if start and not self.start:
            self.start = start
        self.runs.append(row)
        self.runs = self.runs[-MAX_RUNS:]

    def save(self, path: str | os.PathLike) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=p.name + ".", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                json.dump({"format": FORMAT, "version": VERSION, "start": self.start, "runs": self.runs}, f, indent=1)
                f.write("\n")
            os.replace(tmp, p)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def direction(self) -> str:
        """'better', 'worse' or 'steady': is the weighted count of open problems lower or higher than in the previous crawl?"""
        if len(self.runs) < 2:
            return "steady"
        score = lambda r: 9 * r.get("high", 0) + 3 * r.get("medium", 0) + r.get("low", 0)
        a, b = score(self.runs[-2]), score(self.runs[-1])
        return "worse" if b > a else "better" if b < a else "steady"

    def to_text(self, last: int = 10) -> str:
        lines = [f"{'crawl':<22} {'pages':>5} {'high':>5} {'med':>4} {'low':>4} {'accepted':>8}  changes"]
        for r in self.runs[-last:]:
            ch = f"{r['regressions']} regression(s), {r.get('fixed', 0)} fixed" if "regressions" in r else ""
            lines.append(f"{r.get('created', '?'):<22} {r.get('pages', 0):>5} {r.get('high', 0):>5} {r.get('medium', 0):>4} {r.get('low', 0):>4} {r.get('accepted', 0):>8}  {ch}")
        return "\n".join(lines)


def _e(x) -> str:
    return html.escape(str(x), quote=True)


def trend_html(h: History, title: str = "") -> str:
    """The history as a self-contained page: a chart of open problems per crawl, and the numbers under it."""
    import report
    runs = h.runs[-120:]
    W, H, L, R, T, B = 900, 280, 46, 16, 16, 34
    top = max([r.get(k, 0) for r in runs for k in ("high", "medium", "low")] + [1])
    top = top + (-top % 5 if top > 5 else 0)
    n = len(runs)
    x = lambda i: L + (W - L - R) * (i / (n - 1) if n > 1 else 0.5)
    y = lambda v: T + (H - T - B) * (1 - v / top)
    svg = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="Open problems per crawl" style="width:100%;height:auto;background:var(--card);border:1px solid var(--line);border-radius:12px">']
    for k in range(0, 6):
        v = top * k / 5
        svg.append(f'<line x1="{L}" x2="{W - R}" y1="{y(v):.1f}" y2="{y(v):.1f}" stroke="var(--line)" stroke-width="1"/>'
                   f'<text x="{L - 6}" y="{y(v) + 4:.1f}" text-anchor="end" fill="var(--mut)" font-size="11">{v:g}</text>')
    for key, color in (("low", "var(--lo)"), ("medium", "var(--md)"), ("high", "var(--hi)")):
        pts = " ".join(f"{x(i):.1f},{y(r.get(key, 0)):.1f}" for i, r in enumerate(runs))
        if n > 1:
            svg.append(f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="2.2" stroke-linejoin="round"/>')
        for i, r in enumerate(runs):
            svg.append(f'<circle cx="{x(i):.1f}" cy="{y(r.get(key, 0)):.1f}" r="3.4" fill="{color}"><title>{_e(r.get("created", ""))}: {r.get(key, 0)} {key}</title></circle>')
    if n:
        for i in sorted({0, n // 2, n - 1}):
            svg.append(f'<text x="{x(i):.1f}" y="{H - 12}" text-anchor="{"start" if i == 0 and n > 1 else "end" if i == n - 1 and n > 1 else "middle"}" fill="var(--mut)" font-size="11">{_e(runs[i].get("created", "")[:10])}</text>')
    svg.append("</svg>")
    legend = '<p class="note"><span class="sev high">&#9632; high</span> &nbsp; <span class="sev medium">&#9632; medium</span> &nbsp; <span class="sev low">&#9632; low</span> &nbsp; open problems per crawl; accepted findings are not counted</p>'
    word = {"better": "Fewer open problems than the crawl before.", "worse": "More open problems than the crawl before.", "steady": "Open problems are unchanged since the crawl before."}[h.direction()]
    rows = []
    for r in reversed(runs[-30:]):
        rows.append("<tr>" + "".join(f"<td>{_e(v)}</td>" for v in (r.get("created", ""), r.get("pages", 0), r.get("high", 0), r.get("medium", 0), r.get("low", 0), r.get("accepted", 0),
                                                                   r.get("regressions", ""), r.get("changed_pages", ""))) + "</tr>")
    table = ("<table><thead><tr>" + "".join(f"<th>{t}</th>" for t in ("Crawl", "Pages", "High", "Medium", "Low", "Accepted", "Regressions", "Pages changed")) + "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>")
    body = (f"<h1>Trend</h1><p class=sub>{_e(title or h.start)} &middot; {n} crawl(s)</p>" + (f"<p>{_e(word)}</p>" if n > 1 else "") + (("".join(svg) + legend + "<h2>Recent crawls</h2>" + table) if n else "<p class=note>No crawls recorded yet.</p>"))
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8><title>WebCrawler: trend</title><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<style>{report.CSS}</style></head><body><main>{body}</main></body></html>")
