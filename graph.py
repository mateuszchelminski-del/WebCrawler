"""graph.py: the site map. Pages and links become nodes and edges; layouts turn them into coordinates; the result
exports as JSON or as a self-contained interactive HTML map. No browser, no GUI toolkit: pure Python.
"""
from __future__ import annotations

import json
import math
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from urllib.parse import urlparse

import frontier
import webcrawler as wc


@dataclass
class Node:
    url: str
    kind: str = "link"            # page (crawled) | link (found, not crawled) | external | file | mail
    label: str = ""
    depth: int | None = None
    status: int | None = None     # HTTP status; 0 = no response
    title: str = ""
    visited: bool = False
    risk: int = 0
    count: int = 1                # for collapsed external hosts: how many URLs it stands for
    rendered: bool = False        # its links were found by running its JavaScript in a browser
    fp: str | None = None         # SimHash of the page's visible text (content.py); None = not measured, "" = no text
    words: int = 0
    members: list = field(default_factory=list)      # kind "cluster" only: a sample of the URLs it stands for (count says how many)


def _label(url: str) -> str:
    u = urlparse(url)
    if u.scheme in ("mailto", "tel"):
        return url
    path = u.path or "/"
    tail = path.rstrip("/").rsplit("/", 1)[-1] or u.netloc or path
    return tail + (("?" + u.query[:20]) if u.query else "")


class SiteGraph:
    def __init__(self, root: str = "") -> None:
        self.root = frontier.normalize(root) if root else ""
        self.sources: set[str] = set()          # nodes that only list pages (a sitemap), so they do not count as "linking" to them
        self.nodes: dict[str, Node] = {}
        self.edges: dict[tuple[str, str], int] = {}
        self.version = 0
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ building
    def _key(self, url: str) -> str:
        return frontier.normalize(url) if urlparse(url).scheme in ("http", "https", "file") else url

    def _node(self, url: str, kind: str | None = None) -> Node:
        n = self.nodes.get(url)
        if n is None:
            n = self.nodes[url] = Node(url, kind or "link", _label(url))
        return n

    def set_root(self, url: str) -> None:
        with self._lock:
            self.root = self._key(url)
            n = self._node(self.root, "page")
            n.depth = 0
            self.version += 1

    def visit(self, url: str, depth: int | None = None, status: int | None = None, title: str = "") -> None:
        """Record that a page was actually fetched."""
        with self._lock:
            u = self._key(url)
            n = self._node(u, "page")
            n.kind, n.visited = "page", True
            if depth is not None:
                n.depth = depth
            if status is not None:
                n.status = status
            if title:
                n.title = title[:120]
                n.label = title[:28] if len(title) > 3 else n.label
            if not self.root:
                self.root = u
            self.version += 1

    def link(self, src: str, dst: str, kind: str | None = None) -> None:
        """Record that page src links to dst (kind from the crawler's classification)."""
        with self._lock:
            s, d = self._key(src), self._key(dst)
            if s == d:
                return
            self._node(s, "page")
            node = self._node(d)
            if not node.visited:
                node.kind = {"external": "external", "file": "file", "mailto": "mail", "tel": "mail"}.get(kind or "", node.kind if node.kind != "link" else "link")
            self.edges[(s, d)] = self.edges.get((s, d), 0) + 1
            self.version += 1

    def mark_rendered(self, url: str) -> None:
        with self._lock:
            n = self.nodes.get(self._key(url))
            if n:
                n.rendered = True
                self.version += 1

    def set_content(self, url: str, fp: str, words: int) -> None:
        """Remember how a page's text reads, so a later crawl can tell whether it changed."""
        with self._lock:
            n = self.nodes.get(self._key(url))
            if n and (n.fp, n.words) != (fp, words):
                n.fp, n.words = fp, words
                self.version += 1

    def set_status(self, url: str, status: int) -> None:
        with self._lock:
            n = self.nodes.get(self._key(url))
            if n:
                n.status = status
                self.version += 1

    def set_risk(self, url: str, score: int) -> None:
        with self._lock:
            n = self.nodes.get(self._key(url))
            if n and score > n.risk:
                n.risk = score
                self.version += 1

    def clear(self) -> None:
        with self._lock:
            self.nodes.clear()
            self.edges.clear()
            self.sources.clear()
            self.version += 1

    def add_source(self, url: str, pages: list[str]) -> None:
        """A sitemap: a node that lists `pages` without being a real link to them."""
        with self._lock:
            s = self._key(url)
            self.visit(s, 0, 200, "sitemap")
            self.sources.add(s)
            for p in pages:
                self.link(s, p, "internal")

    def orphans(self) -> list[str]:
        """Pages that exist (a sitemap lists them, or they were fetched) but that no other page links to."""
        with self._lock:
            linked = {d for (s, d) in self.edges if s not in self.sources}
            listed = {d for (s, d) in self.edges if s in self.sources}
            return sorted(u for u in listed if u not in linked and u != self.root and self.nodes[u].kind in ("page", "link"))

    # ------------------------------------------------------------------ saving and loading
    def to_state(self) -> dict:
        with self._lock:
            return {"root": self.root, "sources": sorted(self.sources),
                    "nodes": [{"url": n.url, "kind": n.kind, "label": n.label, "depth": n.depth, "status": n.status, "title": n.title,
                               "visited": n.visited, "risk": n.risk, "count": n.count, "rendered": n.rendered,
                               **({"fp": n.fp, "words": n.words} if n.fp is not None else {})} for n in self.nodes.values()],
                    "edges": [[s, d, c] for (s, d), c in self.edges.items()]}

    def load_state(self, d: dict) -> None:
        with self._lock:
            self.root = d.get("root", "")
            self.sources = set(d.get("sources", []))
            self.nodes = {n["url"]: Node(n["url"], n.get("kind", "link"), n.get("label", ""), n.get("depth"), n.get("status"), n.get("title", ""),
                                         bool(n.get("visited")), int(n.get("risk", 0)), int(n.get("count", 1)), bool(n.get("rendered", False)),
                                         n.get("fp"), int(n.get("words", 0))) for n in d.get("nodes", [])}
            self.edges = {(s, t): int(c) for s, t, c in d.get("edges", [])}
            self.version += 1

    # ------------------------------------------------------------------ views
    @staticmethod
    def is_redirect(n: "Node") -> bool:
        return n.visited and n.status is not None and 300 <= n.status < 400

    def view(self, externals: bool = True, files: bool = True, mail: bool = False, max_nodes: int = 1500, redirects: bool = False, cluster_at: int = 0):
        """(nodes, edges) to draw. External URLs collapse into one node per host so a link-heavy page stays readable, and redirect
        hops are folded away (a link to /old that redirects to /new is drawn as a link to /new) unless redirects=True. With cluster_at, a
        graph bigger than that has its dead-end pages grouped by the page that links to them and the folder they live in ("/blog/ x 400")
        until it fits; problems (broken, restricted, risky pages) always stay as nodes of their own."""
        with self._lock:
            hop_to: dict[str, str] = {}
            if not redirects:
                hops = {u for u, n in self.nodes.items() if self.is_redirect(n)}
                nxt: dict[str, str] = {}
                for (s, d) in self.edges:
                    if s in hops and s not in nxt:
                        nxt[s] = d
                for h in hops:                      # follow a chain of hops to the page it ends at
                    t, seen = h, {h}
                    while t in hops and t in nxt and nxt[t] not in seen and len(seen) < 25:
                        t = nxt[t]
                        seen.add(t)
                    if t not in hops:               # a loop or a dead end leaves the hops visible as ordinary nodes
                        hop_to[h] = t
            def map_id(n: Node) -> str | None:
                if n.kind == "external":
                    return ("ext:" + (urlparse(n.url).netloc or n.url)) if externals else None
                if n.kind == "file":
                    return n.url if files else None
                if n.kind == "mail":
                    return n.url if mail else None
                return n.url

            out: dict[str, Node] = {}
            ids: dict[str, str] = {}
            for url, n in self.nodes.items():
                if url in hop_to and hop_to[url] != url and hop_to[url] in self.nodes:
                    continue                         # a redirect hop: edges to it are redirected to where it leads
                nid = map_id(n)
                if nid is None:
                    continue
                ids[url] = nid
                if nid.startswith("ext:"):
                    h = out.get(nid)
                    if h is None:
                        h = out[nid] = Node(nid, "external", nid[4:], None, None, "", False, 0, 0)
                    h.count += 1
                    h.risk = max(h.risk, n.risk)
                else:
                    out[nid] = n
            for h, t in hop_to.items():
                if h not in ids and t in ids:
                    ids[h] = ids[t]
            edges: dict[tuple[str, str], int] = {}
            for (s, d), c in self.edges.items():
                if s in hop_to and hop_to[s] != s and hop_to[s] in self.nodes:
                    continue
                a, b = ids.get(s), ids.get(d)
                if a and b and a != b:
                    edges[(a, b)] = edges.get((a, b), 0) + c
            if cluster_at and len(out) > cluster_at:
                out, edges = self._cluster(out, edges, cluster_at)
            if len(out) > max_nodes:  # keep the pages, drop the least interesting leaves
                keep = sorted(out.values(), key=lambda n: (n.kind != "page", n.depth if n.depth is not None else 99))[:max_nodes]
                names = {n.url for n in keep}
                out = {k: v for k, v in out.items() if k in names}
                edges = {k: v for k, v in edges.items() if k[0] in names and k[1] in names}
            return list(out.values()), list(edges.items())

    MIN_CLUSTER = 6

    def _cluster(self, out: dict, edges: dict, limit: int):
        """Coarsen a map that is too big to read. First dead ends that hang off the same page are grouped by folder, then by page alone;
        if the map is still too big, everything beyond the depth that fits is grouped the same way, and as a last resort every page is grouped
        with its folder-mates (a group keeps the links of its members)."""
        parent: dict[str, str] = {}
        has_out = set()
        adj: dict[str, list[str]] = defaultdict(list)
        for (a, b) in edges:
            parent.setdefault(b, a)
            has_out.add(a)
            adj[a].append(b)

        def problem(n: Node) -> bool:
            broken = n.visited and n.status is not None and (n.status == 0 or n.status >= 400)
            return n.risk > 0 or broken or n.url == self.root or n.url.startswith(("ext:", "grp:")) or n.kind not in ("page", "link", "file")

        def folder(u: str) -> str:
            p = urlparse(u)
            return p.path.rsplit("/", 1)[0] + "/" if "/" in p.path else "/"

        dist: dict[str, int] = {}
        tree_parent: dict[str, str] = {}

        def measure() -> None:
            q = deque([self.root] if self.root in out else [])
            dist.update({self.root: 0} if q else {})
            while q:
                u = q.popleft()
                for v in adj.get(u, ()):
                    if v not in dist and v in out:
                        dist[v] = dist[u] + 1
                        tree_parent[v] = u
                        q.append(v)

        for mode in ("folder", "parent", "deep", "any"):
            if len(out) <= limit:
                break
            if mode == "any":
                measure()
                eligible = lambda n: not problem(n) and n.url in tree_parent
                par = tree_parent
            elif mode == "deep":
                measure()
                counts = defaultdict(int)
                for n in out.values():
                    counts[dist.get(n.url, 1)] += 1
                cutoff, running = 0, 0
                for d in sorted(counts):
                    running += counts[d]
                    if running > limit * 0.7:
                        break
                    cutoff = d
                eligible = lambda n: not problem(n) and dist.get(n.url, 1) > max(cutoff, 1) and n.url in tree_parent
                par = tree_parent
            else:
                eligible = lambda n: not problem(n) and n.url not in has_out and n.url in parent
                par = parent
            groups: dict[tuple, list[str]] = defaultdict(list)
            for n in out.values():
                if eligible(n):
                    groups[(par[n.url], folder(n.url) if mode != "parent" else "")].append(n.url)
            remap: dict[str, str] = {}
            remaining = len(out)
            for (pa, fold), urls in sorted(groups.items(), key=lambda kv: -len(kv[1])):         # the biggest groups first, and only as many as it takes
                if len(urls) < self.MIN_CLUSTER or remaining <= limit:
                    continue
                remaining -= len(urls) - 1
                cid = f"grp:{pa}|{fold}"
                shown = fold if fold else (urlparse(pa).path or "/")
                depth = out[pa].depth + 1 if pa in out and out[pa].depth is not None else None
                members = sorted(urls)[:40]
                total = sum(out[u].count for u in urls if u in out)
                if cid in out:                           # a group formed in an earlier pass: absorb it
                    members, total = sorted(set(out[cid].members) | set(members))[:40], total + out[cid].count
                out[cid] = Node(cid, "cluster", f"{shown.rstrip('/') or '/'} x{total}", depth, None,
                                f"{total} pages in {shown}" if fold else f"{total} pages linked from {pa}", False, 0, total, False, None, 0, members)
                for u in urls:
                    remap[u] = cid
            if remap:
                for u in remap:
                    out.pop(u, None)
                merged: dict[tuple[str, str], int] = {}
                for (a, b), c in edges.items():
                    a, b = remap.get(a, a), remap.get(b, b)
                    if a != b:
                        merged[(a, b)] = merged.get((a, b), 0) + c
                edges = merged
                parent, has_out = {}, set()
                adj = defaultdict(list)
                for (a, b) in edges:
                    parent.setdefault(b, a)
                    has_out.add(a)
                    adj[a].append(b)
        return out, edges

    def stats(self) -> dict:
        """Counts for display. Redirect hops are counted separately, so "pages" is what a visitor would call pages."""
        with self._lock:
            visited = [n for n in self.nodes.values() if n.visited]
            pages = [n for n in visited if not self.is_redirect(n)]
            return {"nodes": len(self.nodes), "edges": len(self.edges), "pages": len(pages), "redirects": len(visited) - len(pages),
                    "broken": sum(1 for n in pages if n.status is not None and (n.status == 0 or (n.status >= 400 and n.status not in (401, 403)))),
                    "restricted": sum(1 for n in pages if n.status in (401, 403)),
                    "external_hosts": len({urlparse(n.url).netloc for n in self.nodes.values() if n.kind == "external"})}

    # ------------------------------------------------------------------ export
    def to_json(self) -> str:
        nodes, edges = self.view(max_nodes=100000, mail=True)
        idx = {n.url: i for i, n in enumerate(nodes)}
        return json.dumps({"root": self.root, "stats": self.stats(),
                           "nodes": [{"id": n.url, "kind": n.kind, "label": n.label, "title": n.title, "depth": n.depth, "status": n.status,
                                      "visited": n.visited, "risk": n.risk, "count": n.count, "rendered": n.rendered} for n in nodes],
                           "edges": [{"from": idx[a], "to": idx[b], "count": c} for (a, b), c in edges if a in idx and b in idx]}, indent=2)


# ---------------------------------------------------------------------- layouts

def _tree(nodes: list[Node], edges: list, root: str):
    """Breadth-first spanning tree. Returns (children, depth, roots); unreachable nodes hang under the main root."""
    adj: dict[str, list[str]] = defaultdict(list)
    for (a, b), _ in edges:
        adj[a].append(b)
    ids = [n.url for n in nodes]
    start = root if root in set(ids) else (ids[0] if ids else "")
    children: dict[str, list[str]] = defaultdict(list)
    depth: dict[str, int] = {}
    if not start:
        return children, depth, start
    seen = {start}
    depth[start] = 0
    q = deque([start])
    def bfs(q):
        while q:
            u = q.popleft()
            for v in adj.get(u, ()):
                if v not in seen:
                    seen.add(v)
                    depth[v] = depth[u] + 1
                    children[u].append(v)
                    q.append(v)
    bfs(q)
    for nid in ids:                 # anything the root cannot reach (pages opened by hand, other roots)
        if nid not in seen:
            seen.add(nid)
            depth[nid] = 1
            children[start].append(nid)
            bfs(deque([nid]))
    return children, depth, start


def radial_layout(nodes: list[Node], edges: list, root: str) -> dict[str, tuple[float, float]]:
    """Root in the middle, one ring per link-hop, each branch gets an angular wedge sized by how much hangs off it."""
    children, depth, start = _tree(nodes, edges, root)
    if not start:
        return {}
    weight: dict[str, int] = {}
    def w(u):
        weight[u] = max(1, sum(w(c) for c in children.get(u, ())))
        return weight[u]
    import sys
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(max(old, 10000))
    try:
        w(start)
    finally:
        sys.setrecursionlimit(old)
    # ring radius: at least one ring-gap beyond the previous ring, and big enough for everything on the ring to fit side by side
    per = defaultdict(int)
    for d in depth.values():
        per[d] += 1
    radius = {0: 0.0}
    for d in range(1, max(depth.values()) + 1):
        radius[d] = max(radius[d - 1] + 0.18, per[d] * 0.07 / (2 * math.pi))
    top = radius[max(depth.values())] or 1.0
    pos = {start: (0.0, 0.0)}
    stack = [(start, 0.0, 2 * math.pi)]
    while stack:
        u, a0, a1 = stack.pop()
        kids = children.get(u, ())
        total = sum(weight[c] for c in kids) or 1
        a = a0
        for c in kids:
            span = (a1 - a0) * weight[c] / total
            mid = a + span / 2
            r = radius[depth[c]] / top
            pos[c] = (r * math.cos(mid), r * math.sin(mid))
            stack.append((c, a, a + span))
            a += span
    return pos


def tree_layout(nodes: list[Node], edges: list, root: str) -> dict[str, tuple[float, float]]:
    """Top-down: depth on the vertical axis, leaves spread along the horizontal axis, parents centred over their children."""
    children, depth, start = _tree(nodes, edges, root)
    if not start:
        return {}
    x: dict[str, float] = {}
    counter = [0]
    order = []
    stack = [(start, False)]
    while stack:
        u, done = stack.pop()
        if done:
            kids = children.get(u, ())
            x[u] = (sum(x[c] for c in kids) / len(kids)) if kids else float(counter[0])
            if not kids:
                counter[0] += 1
            order.append(u)
        else:
            stack.append((u, True))
            for c in reversed(children.get(u, ())):
                stack.append((c, False))
    span = max(counter[0] - 1, 1)
    maxd = max(depth.values()) or 1
    return {u: (2 * x[u] / span - 1, depth[u] / maxd) for u in order}


# ---------------------------------------------------------------------- self-contained interactive map

HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Site map</title><style>
html,body{margin:0;height:100%;background:#0b1020;color:#e8eefc;font:14px system-ui,Segoe UI,sans-serif;overflow:hidden}
#bar{position:fixed;top:0;left:0;right:0;display:flex;gap:12px;align-items:center;padding:8px 12px;background:rgba(18,26,48,.92);border-bottom:1px solid #25304f;z-index:2;flex-wrap:wrap}
#bar b{font-size:15px}#bar label{color:#9aa8c7;display:flex;gap:5px;align-items:center}select,input[type=search]{background:#18223f;color:#e8eefc;border:1px solid #25304f;border-radius:6px;padding:4px 8px}
#info{position:fixed;right:10px;bottom:10px;max-width:420px;background:rgba(18,26,48,.94);border:1px solid #25304f;border-radius:10px;padding:10px 12px;font-size:13px;word-break:break-all;display:none}
#legend{position:fixed;left:10px;bottom:10px;background:rgba(18,26,48,.9);border:1px solid #25304f;border-radius:10px;padding:8px 12px;font-size:12px;color:#9aa8c7}
#legend i{display:inline-block;width:10px;height:10px;border-radius:50%;margin:0 4px 0 8px}canvas{display:block;margin-top:0}
</style></head><body><div id="bar"><b>Site map</b><span id="sum" style="color:#9aa8c7"></span>
<label>Layout <select id="lay"><option value="r">Radial</option><option value="t">Tree</option></select></label>
<label><input id="ext" type="checkbox" checked> External hosts</label><label><input id="fil" type="checkbox" checked> Files</label>
<label>Find <input id="q" type="search" placeholder="url or title"></label><span style="color:#9aa8c7">drag to pan, wheel to zoom, click a node</span></div>
<canvas id="c"></canvas><div id="info"></div>
<div id="legend"><i style="background:#3fd1ff"></i>crawled page<i style="background:#6f7fa8"></i>found, not crawled<i style="background:#ffb454"></i>external host<i style="background:#ff7ad9"></i>file<i style="background:#ff6b6b"></i>broken / high risk<i style="background:#6f7fa8;border-radius:2px"></i>group of pages</div>
<script>
const D=__DATA__;
const cv=document.getElementById('c'),cx=cv.getContext('2d');let W,H,k=1,ox=0,oy=0,sel=-1,hov=-1,lay='r',showExt=true,showFil=true,term='';
const col=n=>n.risk>=40||(n.visited&&(n.status===0||n.status>=400))?'#ff6b6b':n.kind==='external'?'#ffb454':n.kind==='file'?'#ff7ad9':n.visited?'#3fd1ff':'#6f7fa8';
function vis(n){return !(n.kind==='external'&&!showExt)&&!(n.kind==='file'&&!showFil)}
function fit(){W=cv.width=innerWidth;H=cv.height=innerHeight;k=Math.min(W,H)*0.42;ox=W/2;oy=lay==='r'?H/2+20:70;if(lay==='t'){k=Math.min(W*0.46,H*0.8);ox=W/2}draw()}
function P(n){const p=lay==='r'?n.r:n.t;return[ox+p[0]*k,oy+p[1]*k*(lay==='t'?1:1)]}
function rad(n){return 4+Math.min(10,Math.sqrt(n.count||1)*1.6)+(n.kind==='page'?2:0)}
function draw(){cx.clearRect(0,0,W,H);cx.lineWidth=1;
 for(const [a,b,c] of D.edges){const A=D.nodes[a],B=D.nodes[b];if(!vis(A)||!vis(B))continue;const pa=P(A),pb=P(B);cx.strokeStyle=(sel===a||sel===b)?'rgba(63,209,255,.9)':'rgba(120,140,190,.22)';cx.beginPath();cx.moveTo(pa[0],pa[1]);cx.lineTo(pb[0],pb[1]);cx.stroke()}
 D.nodes.forEach((n,i)=>{if(!vis(n))return;const p=P(n),r=rad(n);cx.fillStyle=col(n);cx.globalAlpha=term&&!(n.id+' '+n.title).toLowerCase().includes(term)?.18:1;cx.beginPath();cx.arc(p[0],p[1],r,0,7);cx.fill();
  if(i===sel||i===hov){cx.strokeStyle='#fff';cx.lineWidth=2;cx.stroke();cx.lineWidth=1}
  if(n.risk>=8){cx.strokeStyle='#ffe082';cx.setLineDash([3,3]);cx.beginPath();cx.arc(p[0],p[1],r+4,0,7);cx.stroke();cx.setLineDash([])}
  if(k>Math.max(150,D.nodes.length*14)||i===sel||i===hov||n.depth===0){cx.fillStyle='#e8eefc';cx.font='11px system-ui';cx.fillText(n.label.slice(0,26),p[0]+r+3,p[1]+4)}cx.globalAlpha=1})}
function hit(x,y){let best=-1,bd=1e9;D.nodes.forEach((n,i)=>{if(!vis(n))return;const p=P(n),d=Math.hypot(p[0]-x,p[1]-y);if(d<rad(n)+4&&d<bd){bd=d;best=i}});return best}
let drag=null;cv.onmousedown=e=>{drag=[e.clientX,e.clientY,ox,oy,false]};
onmouseup=e=>{if(drag&&!drag[4]){sel=hit(e.clientX,e.clientY);show()}drag=null;draw()};
onmousemove=e=>{if(drag){const dx=e.clientX-drag[0],dy=e.clientY-drag[1];if(Math.abs(dx)+Math.abs(dy)>3)drag[4]=true;ox=drag[2]+dx;oy=drag[3]+dy;draw()}else{const h=hit(e.clientX,e.clientY);if(h!==hov){hov=h;draw()}}};
cv.onwheel=e=>{e.preventDefault();const f=e.deltaY<0?1.15:1/1.15;ox=e.clientX-(e.clientX-ox)*f;oy=e.clientY-(e.clientY-oy)*f;k*=f;draw()};
function show(){const el=document.getElementById('info');if(sel<0){el.style.display='none';return}const n=D.nodes[sel];el.style.display='block';el.textContent='';
 const rows=[['URL',n.id],['Title',n.title],['Type',n.kind+(n.count>1?' ('+n.count+' URLs)':'')],['Status',n.status==null?'':n.status],['Depth',n.depth==null?'':n.depth],['Risk',n.risk],['Includes',n.m?n.m.join(', ')+(n.count>n.m.length?' ... and '+(n.count-n.m.length)+' more':''):'']];
 for(const [a,b] of rows){if(b===''||b==null)continue;const d=document.createElement('div');const s=document.createElement('b');s.textContent=a+': ';d.append(s,document.createTextNode(String(b)));el.appendChild(d)}}
document.getElementById('lay').onchange=e=>{lay=e.target.value;fit()};
document.getElementById('ext').onchange=e=>{showExt=e.target.checked;draw()};document.getElementById('fil').onchange=e=>{showFil=e.target.checked;draw()};
document.getElementById('q').oninput=e=>{term=e.target.value.toLowerCase();draw()};
document.getElementById('sum').textContent=D.stats.pages+' pages, '+D.stats.nodes+' nodes, '+D.stats.edges+' links'+(D.stats.broken?', '+D.stats.broken+' broken':'');
onresize=fit;fit();
</script></body></html>"""


def to_html(graph: SiteGraph, title: str = "") -> str:
    nodes, edges = graph.view(max_nodes=4000, cluster_at=1200)
    r, t = radial_layout(nodes, edges, graph.root), tree_layout(nodes, edges, graph.root)
    idx = {n.url: i for i, n in enumerate(nodes)}
    data = {"stats": graph.stats(), "root": graph.root,
            "nodes": [{"id": n.url, "kind": n.kind, "label": n.label or n.url, "title": n.title, "depth": n.depth, "status": n.status,
                       "visited": n.visited, "risk": n.risk, "count": n.count, "r": list(r.get(n.url, (0, 0))), "t": list(t.get(n.url, (0, 0))),
                       **({"m": n.members} if n.members else {})} for n in nodes],
            "edges": [[idx[a], idx[b], c] for (a, b), c in edges if a in idx and b in idx]}
    blob = json.dumps(data).replace("</", "<\\/").replace("<!--", "<\\!--")
    out = HTML.replace("__DATA__", blob)
    return out.replace("<title>Site map</title>", "<title>" + (title or "Site map").replace("<", "&lt;") + "</title>") if title else out
