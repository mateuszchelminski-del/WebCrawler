import json
import math
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import graph as gr  # noqa: E402

ROOT = "https://example.com/"


def sample():
    g = gr.SiteGraph()
    g.set_root(ROOT)
    g.visit(ROOT, 0, 200, "Home")
    for p in ("about", "blog", "docs"):
        g.link(ROOT, f"https://example.com/{p}", "internal")
        g.visit(f"https://example.com/{p}", 1, 200, p.title())
    for i in range(3):
        g.link("https://example.com/blog", f"https://example.com/blog/post-{i}", "internal")
    g.link("https://example.com/docs", "https://example.com/docs/guide", "internal")
    g.link(ROOT, "https://ext-a.org/x", "external")
    g.link("https://example.com/about", "https://ext-a.org/y", "external")
    g.link("https://example.com/about", "https://ext-b.org/", "external")
    g.link(ROOT, "https://example.com/files/r.pdf", "file")
    g.link(ROOT, "mailto:me@example.com", "mailto")
    g.visit("https://example.com/missing", 1, 404)
    g.link(ROOT, "https://example.com/missing", "internal")
    return g


class Building(unittest.TestCase):
    def test_nodes_edges_and_kinds(self):
        g = sample()
        kinds = {n.url: n.kind for n in g.nodes.values()}
        self.assertEqual(kinds["https://example.com/about"], "page")
        self.assertEqual(kinds["https://example.com/blog/post-0"], "link")
        self.assertEqual(kinds["https://ext-a.org/x"], "external")
        self.assertEqual(kinds["https://example.com/files/r.pdf"], "file")
        self.assertEqual(kinds["mailto:me@example.com"], "mail")
        self.assertIn((ROOT, "https://example.com/about"), g.edges)

    def test_duplicate_edges_count_and_self_links_ignored(self):
        g = sample()
        g.link(ROOT, "https://example.com/about#team", "internal")  # same page after normalising
        self.assertEqual(g.edges[(ROOT, "https://example.com/about")], 2)
        v = g.version
        g.link(ROOT, ROOT)
        self.assertEqual(g.version, v)

    def test_stats_count_broken_pages(self):
        s = sample().stats()
        self.assertEqual((s["pages"], s["broken"], s["external_hosts"]), (5, 1, 2))

    def test_version_bumps_on_change(self):
        g = gr.SiteGraph()
        v = g.version
        g.visit(ROOT, 0, 200)
        self.assertGreater(g.version, v)


class Views(unittest.TestCase):
    def test_externals_collapse_to_hosts(self):
        nodes, edges = sample().view()
        ext = {n.url: n for n in nodes if n.kind == "external"}
        self.assertEqual(set(ext), {"ext:ext-a.org", "ext:ext-b.org"})
        self.assertEqual(ext["ext:ext-a.org"].count, 2)
        self.assertIn(((ROOT, "ext:ext-a.org"), 1), edges)

    def test_filters(self):
        g = sample()
        urls = {n.url for n in g.view(externals=False, files=False)[0]}
        self.assertFalse(any(u.startswith("ext:") or u.endswith(".pdf") or u.startswith("mailto") for u in urls))
        self.assertIn("mailto:me@example.com", {n.url for n in g.view(mail=True)[0]})

    def test_max_nodes_keeps_pages(self):
        g = sample()
        nodes, _ = g.view(max_nodes=6)
        self.assertEqual(len(nodes), 6)
        self.assertTrue(all(n.kind == "page" for n in nodes if n.visited))


class Redirects(unittest.TestCase):
    def build(self):
        g = gr.SiteGraph(ROOT)
        g.visit(ROOT, 0, 200, "Home")
        g.link(ROOT, "https://example.com/old", "internal")
        g.visit("https://example.com/old", 1, 301)
        g.link("https://example.com/old", "https://example.com/mid", "internal")
        g.visit("https://example.com/mid", 1, 308)
        g.link("https://example.com/mid", "https://example.com/new", "internal")
        g.visit("https://example.com/new", 1, 200, "New")
        g.link(ROOT, "https://example.com/new", "internal")
        return g

    def test_hops_are_not_pages_in_the_counts(self):
        s = self.build().stats()
        self.assertEqual((s["pages"], s["redirects"]), (2, 2))

    def test_hops_are_folded_out_of_the_map(self):
        nodes, edges = self.build().view()
        self.assertEqual({n.url for n in nodes}, {ROOT, "https://example.com/new"})
        self.assertEqual(dict(edges), {(ROOT, "https://example.com/new"): 2})     # the direct link and the one through two hops
        nodes, edges = self.build().view(redirects=True)
        self.assertEqual(len(nodes), 4)

    def test_a_redirect_loop_or_dead_end_stays_visible(self):
        g = gr.SiteGraph(ROOT)
        g.visit(ROOT, 0, 200)
        g.link(ROOT, "https://example.com/a", "internal")
        g.visit("https://example.com/a", 1, 302)
        g.link("https://example.com/a", "https://example.com/b", "internal")
        g.visit("https://example.com/b", 1, 302)
        g.link("https://example.com/b", "https://example.com/a", "internal")
        g.link(ROOT, "https://example.com/dead", "internal")
        g.visit("https://example.com/dead", 1, 301)                                # never followed
        nodes, _ = g.view()
        self.assertTrue({"https://example.com/a", "https://example.com/b", "https://example.com/dead"} <= {n.url for n in nodes})

    def test_layouts_and_json_work_on_the_folded_view(self):
        g = self.build()
        nodes, edges = g.view()
        self.assertEqual(set(gr.radial_layout(nodes, edges, ROOT)), {ROOT, "https://example.com/new"})
        d = json.loads(g.to_json())
        self.assertEqual(d["stats"]["redirects"], 2)
        self.assertEqual(len(d["nodes"]), 2)

    def test_the_diff_ignores_hops(self):
        import snapshot as sn
        data = {"graph": self.build().to_state()}
        self.assertEqual(set(sn._pages(data)), {ROOT, "https://example.com/new"})


class Layouts(unittest.TestCase):
    def setUp(self):
        self.g = sample()
        self.nodes, self.edges = self.g.view()

    def test_radial_rings_follow_depth(self):
        pos = gr.radial_layout(self.nodes, self.edges, ROOT)
        self.assertEqual(pos[ROOT], (0.0, 0.0))
        r = lambda u: math.hypot(*pos[u])
        self.assertLess(r("https://example.com/about"), r("https://example.com/blog/post-0"))
        self.assertAlmostEqual(r("https://example.com/blog/post-0"), 1.0, places=6)
        self.assertEqual(set(pos), {n.url for n in self.nodes})

    def test_no_two_nodes_share_a_spot(self):
        for lay in (gr.radial_layout, gr.tree_layout):
            pos = lay(self.nodes, self.edges, ROOT)
            pts = {(round(x, 4), round(y, 4)) for x, y in pos.values()}
            self.assertEqual(len(pts), len(pos), lay.__name__)

    def test_tree_layout_depth_on_y_parent_over_children(self):
        pos = gr.tree_layout(self.nodes, self.edges, ROOT)
        self.assertEqual(pos[ROOT][1], 0.0)
        self.assertGreater(pos["https://example.com/blog/post-0"][1], pos["https://example.com/blog"][1])
        kids = [pos[f"https://example.com/blog/post-{i}"][0] for i in range(3)]
        self.assertAlmostEqual(pos["https://example.com/blog"][0], sum(kids) / 3)

    def test_unreachable_nodes_still_get_positions(self):
        g = sample()
        g.visit("https://example.com/opened-by-hand", None, 200)
        g.link("https://example.com/opened-by-hand", "https://example.com/child", "internal")
        nodes, edges = g.view()
        pos = gr.radial_layout(nodes, edges, ROOT)
        self.assertIn("https://example.com/child", pos)

    def test_empty_graph(self):
        self.assertEqual(gr.radial_layout([], [], ""), {})
        self.assertEqual(gr.tree_layout([], [], ""), {})

    def test_large_graph_is_fast(self):
        import time
        g = gr.SiteGraph(ROOT)
        g.visit(ROOT, 0, 200)
        for i in range(60):
            g.link(ROOT, f"https://example.com/s{i}", "internal")
            for j in range(30):
                g.link(f"https://example.com/s{i}", f"https://example.com/s{i}/p{j}", "internal")
        nodes, edges = g.view(max_nodes=5000)
        t = time.time()
        gr.radial_layout(nodes, edges, ROOT)
        gr.tree_layout(nodes, edges, ROOT)
        self.assertLess(time.time() - t, 2.0)


class Exports(unittest.TestCase):
    def test_json(self):
        d = json.loads(sample().to_json())
        self.assertEqual(d["stats"]["pages"], 5)
        ids = [n["id"] for n in d["nodes"]]
        self.assertIn(ROOT, ids)
        e = d["edges"][0]
        self.assertTrue(0 <= e["from"] < len(ids) and 0 <= e["to"] < len(ids))

    def test_html_is_self_contained_and_escaped(self):
        g = sample()
        g.visit("https://example.com/x", 1, 200, "</script><img src=x onerror=alert(1)>")
        g.link(ROOT, "https://example.com/x", "internal")
        h = gr.to_html(g, title="<b>t</b>")
        self.assertNotIn("</script><img", h)
        self.assertEqual(len(re.findall(r"<script", h)), 1)  # only our own script, nothing injected through data
        self.assertNotRegex(h, r"""(src|href)=["']https?://""")  # no external resources
        self.assertIn("&lt;b>t&lt;/b>", h)
        blob = re.search(r"const D=(\{.*?\});\n", h, re.S).group(1)
        self.assertEqual(json.loads(blob.replace("<\\/", "</"))["stats"]["pages"], 6)


def shop(dirs=3, per=60, crawled_every=0, star=False):
    """A shop-like site: a home page, one category page per folder, and `per` product pages in each (every `crawled_every`th crawled, with links on)."""
    g = gr.SiteGraph()
    g.set_root(ROOT)
    g.visit(ROOT, 0, 200, "Home")
    leaves = []
    for d in range(dirs):
        hub = f"{ROOT}cat{d}/"
        g.visit(hub, 1, 200, f"Category {d}")
        g.link(ROOT, hub, "internal")
        for i in range(per):
            u = f"{hub}item-{i}.html"
            g.link(ROOT if star else hub, u, "internal")
            if crawled_every and i % crawled_every == 0:
                g.visit(u, 2, 200, f"Item {d}-{i}")
                g.link(u, ROOT, "internal")
            leaves.append(u)
    return g, leaves


class Clusters(unittest.TestCase):
    def test_a_map_that_fits_is_left_alone(self):
        g, _ = shop(2, 10)
        nodes, edges = g.view(cluster_at=100)
        self.assertEqual(len(nodes), len(g.nodes))
        self.assertFalse([n for n in nodes if n.kind == "cluster"])

    def test_dead_ends_under_one_page_become_one_group_each(self):
        g, leaves = shop(3, 60)
        nodes, edges = g.view(cluster_at=30)
        groups = [n for n in nodes if n.kind == "cluster"]
        self.assertEqual(len(groups), 3)
        self.assertEqual(sorted(n.count for n in groups), [60, 60, 60])
        self.assertLessEqual(len(nodes), 30)
        grp = groups[0]
        self.assertTrue(set(grp.members) <= set(leaves))
        self.assertEqual(len(grp.members), 40)                     # a sample, not all 60 (count says how many)
        self.assertRegex(grp.label, r"^/cat\d x60$")
        ids = {n.url for n in nodes}
        self.assertTrue(all(a in ids and b in ids for (a, b), _ in edges))                       # no edge points at a node that was folded away
        hubs = {a for (a, b), _ in edges if b == grp.url}
        self.assertEqual(len(hubs), 1)
        self.assertEqual(sum(c for (a, b), c in edges if b == grp.url), 60)                      # the 60 links are still counted

    def test_problems_stay_visible(self):
        g, leaves = shop(2, 40)
        g.visit(leaves[3], 2, 404)
        g.set_risk(leaves[5], 60)
        nodes, _ = g.view(cluster_at=20)
        ids = {n.url for n in nodes}
        self.assertIn(fr_normalize(leaves[3]), ids)
        self.assertIn(fr_normalize(leaves[5]), ids)
        self.assertIn(fr_normalize(ROOT), ids)
        self.assertTrue([n for n in nodes if n.kind == "cluster"])

    def test_small_groups_are_not_worth_grouping(self):
        g, _ = shop(4, gr.SiteGraph.MIN_CLUSTER - 1)
        nodes, _ = g.view(cluster_at=5)
        self.assertFalse([n for n in nodes if n.kind == "cluster"])

    def test_crawled_pages_with_links_are_grouped_when_that_is_the_only_way(self):
        g, _ = shop(4, 100, crawled_every=2, star=True)                 # every other product page was crawled and links back home; the home page lists them all
        before = len(g.view()[0])
        nodes, edges = g.view(cluster_at=60)
        self.assertGreater(before, 400)
        self.assertLessEqual(len(nodes), 60)
        represented = sum(n.count if n.kind == "cluster" else 1 for n in nodes)
        self.assertEqual(represented, before)                             # grouped, not lost

    def test_only_as_much_is_grouped_as_it_takes(self):
        g, _ = shop(6, 50)
        nodes, _ = g.view(cluster_at=len(g.nodes) - 100)           # 100 nodes too many: two groups of 50 would do it... or three of 49 saved each
        groups = [n for n in nodes if n.kind == "cluster"]
        self.assertLess(len(groups), 6)
        self.assertGreaterEqual(len(groups), 2)
        self.assertLessEqual(len(nodes), len(g.nodes) - 100)

    def test_the_layout_and_export_cope(self):
        g, _ = shop(3, 80)
        nodes, edges = g.view(cluster_at=30)
        pos = gr.radial_layout(nodes, edges, g.root)
        self.assertEqual(set(pos), {n.url for n in nodes})
        html = gr.to_html(g)
        data = embedded(html)
        self.assertEqual(len(data["nodes"]), len(g.nodes))               # under the export's own limit: nothing grouped
        big, _ = shop(14, 100)
        data = embedded(gr.to_html(big))
        self.assertLessEqual(len(data["nodes"]), 1200)
        self.assertTrue([n for n in data["nodes"] if n["kind"] == "cluster" and n["m"]])

    def test_it_is_fast(self):
        import time
        g, _ = shop(30, 500, crawled_every=5, star=True)
        t = time.perf_counter()
        nodes, edges = g.view(cluster_at=800)
        self.assertLess(time.perf_counter() - t, 2.0)
        self.assertLessEqual(len(nodes), 800)


def embedded(html):
    """The data an exported map carries."""
    blob = re.search(r"const D=(\{.*?\});\n", html, re.S).group(1)
    return json.loads(blob.replace("<\\/", "</"))


def fr_normalize(u):
    import frontier
    return frontier.normalize(u)


if __name__ == "__main__":
    unittest.main()
