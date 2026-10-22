"""Content-change detection (text fingerprints), new third-party scripts, and their place in the comparison between two crawls."""
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import analysis as an  # noqa: E402
import checks as ck  # noqa: E402
import content  # noqa: E402
import frontier as fr  # noqa: E402
import graph as gr  # noqa: E402
import snapshot as sn  # noqa: E402
import test_httpscan_checks as ths  # noqa: E402
import webcrawler as wc  # noqa: E402

VOCAB = ("security network packet router switch firewall gateway certificate encryption protocol session cookie header request response server client "
         "payload endpoint tunnel proxy cache latency bandwidth handshake signature token policy audit access control identity privilege").split()


def article(n=420, seed=7):
    rnd = random.Random(seed)
    return " ".join(rnd.choice(VOCAB) + (str(rnd.randint(0, 9)) if rnd.random() < 0.1 else "") for _ in range(n))


def page(text, extra=""):
    return f"<html><head><title>T</title><style>p{{color:red}}</style><script>var x = 'not text';</script></head><body><h1>Title</h1><p>{text}</p>{extra}</body></html>"


class Fingerprints(unittest.TestCase):
    def test_only_visible_words_count(self):
        w = content.words("<html><head><title>Hidden</title><script>alert('x')</script><style>a{b:c}</style></head><body><noscript>no js</noscript><p>Hello,   World!</p><svg><text>icon</text></svg></body></html>")
        self.assertEqual(w, ["hello", "world"])
        self.assertEqual(content.words("<p>Café über 日本語</p>"), ["café", "über", "日本語"])
        self.assertEqual(content.words(""), [])
        self.assertEqual(content.words("<p>unclosed <b>bold <i>x"), ["unclosed", "bold", "x"])

    def test_noise_is_flattened(self):
        a = content.words("<p>Updated 12 March 2026 at 10:41. Token a8f3c9d2e1b04f67aa91c3 views: 1,204</p>")
        b = content.words("<p>Updated 19 March 2027 at 22:07. Token 77d0e5a1b2c3d4e5f6a7b8 views: 9,871</p>")
        self.assertEqual(a, b)

    def test_the_same_page_has_the_same_fingerprint(self):
        text = article()
        fp1, n1 = content.fingerprint(page(text))
        fp2, n2 = content.fingerprint(page(text, "<script src='/x.js'></script><style>b{}</style>"))
        self.assertEqual((fp1, n1), (fp2, n2))
        self.assertEqual(len(fp1), 16)
        self.assertEqual(content.fingerprint("<script>only code</script>"), ("", 0))

    def test_a_small_edit_is_noise_a_real_edit_is_not(self):
        base = article()
        words = base.split()
        fp0, n0 = content.fingerprint(page(base))
        one = list(words)
        one[100] = "different"
        fp1, n1 = content.fingerprint(page(" ".join(one)))
        self.assertLessEqual(content.distance(fp0, fp1), content.SAME)
        self.assertEqual(content.compare(fp0, n0, fp1, n1), "")
        spam = base + " " + " ".join(["buy cheap pills online casino bonus click here now"] * 8)
        fp2, n2 = content.fingerprint(page(spam))
        self.assertGreater(content.distance(fp0, fp2), content.SAME)
        self.assertIn("text changed", content.compare(fp0, n0, fp2, n2))
        self.assertIn("words", content.compare(fp0, n0, fp2, n2))

    def test_unrelated_pages_read_as_largely_different(self):
        fp0, n0 = content.fingerprint(page(article(420, seed=1)))
        fp1, n1 = content.fingerprint(page(article(420, seed=2)))
        self.assertGreaterEqual(content.distance(fp0, fp1), content.REPLACED - 4)
        msg = content.compare(fp0, n0, "00ff00ff00ff00ff", 400)
        self.assertTrue(msg.startswith("text largely different"), msg)

    def test_short_and_empty_pages(self):
        a, b = content.fingerprint("<p>Welcome to the site</p>"), content.fingerprint("<p>Welcome to the sites</p>")
        self.assertEqual(content.compare(*a, *a), "")
        self.assertIn("short page changed", content.compare(*a, *b))
        self.assertEqual(content.compare("", 0, "", 0), "")
        self.assertIn("appeared", content.compare("", 0, *content.fingerprint(page(article()))))
        self.assertIn("disappeared", content.compare(*content.fingerprint(page(article())), "", 0))

    def test_it_is_fast_on_big_pages(self):
        import time
        big = page(article(60000)) * 3
        t = time.perf_counter()
        content.fingerprint(big)
        self.assertLess(time.perf_counter() - t, 3.0)


class Scripts(unittest.TestCase):
    PAGE = "https://www.example.com/shop/"

    def hosts(self, html):
        return content.script_hosts(self.PAGE, html)

    def test_third_party_scripts_only(self):
        html = ("<script src='/static/app.js'></script><script src='https://cdn.example.com/lib.js'></script><script src='https://static.other.net/a.js'></script>"
                "<script src='//ads.tracker.io/t.js'></script><script src='https://static.other.net/b.js'></script><script>inline()</script>"
                "<script src='data:text/javascript,1'></script><script src='relative/x.js'></script>")
        self.assertEqual(self.hosts(html), ["static.other.net", "ads.tracker.io"])

    def test_a_base_tag_moves_relative_scripts(self):
        self.assertEqual(self.hosts("<base href='https://elsewhere.net/'><script src='app.js'></script>"), ["elsewhere.net"])

    def test_broken_markup_does_not_raise(self):
        self.assertEqual(self.hosts("<script src=<<>"), [])
        self.assertEqual(self.hosts(""), [])


class Storage(unittest.TestCase):
    def test_the_graph_remembers_fingerprints_and_old_sessions_still_load(self):
        g = gr.SiteGraph("https://e.com/")
        g.visit("https://e.com/", 0, 200, "Home")
        g.visit("https://e.com/empty", 1, 200, "E")
        g.set_content("https://e.com/", "00ff00ff00ff00ff", 120)
        g.set_content("https://e.com/empty", "", 0)
        again = gr.SiteGraph()
        again.load_state(g.to_state())
        n = again.nodes[fr.normalize("https://e.com/")]
        self.assertEqual((n.fp, n.words), ("00ff00ff00ff00ff", 120))
        self.assertEqual(again.nodes[fr.normalize("https://e.com/empty")].fp, "")
        state = g.to_state()
        for node in state["nodes"]:
            node.pop("fp", None), node.pop("words", None)
        legacy = gr.SiteGraph()
        legacy.load_state(state)
        self.assertIsNone(legacy.nodes[fr.normalize("https://e.com/")].fp)                  # "not measured", which is not the same as "no text"

    def test_site_info_keeps_scripts(self):
        import json
        si = ck.SiteInfo()
        si.add_scripts("https://e.com/a", ["cdn.x.net", "ads.y.io"])
        si.add_scripts("https://e.com/b", ["cdn.x.net"])
        self.assertEqual(si.scripts["cdn.x.net"], {"count": 2, "pages": ["https://e.com/a", "https://e.com/b"]})
        v = si.version
        si.add_scripts("https://e.com/b", [])
        self.assertEqual(si.version, v)
        self.assertEqual(ck.SiteInfo.from_dict(json.loads(json.dumps(si.to_dict()))).scripts, si.scripts)
        si.clear()
        self.assertEqual(si.scripts, {})


def session(pages, scripts=None, start="https://e.com/"):
    """pages: {url: (fingerprint, words, rendered, status)}"""
    nodes = [{"url": u, "kind": "page", "visited": True, "status": st, "fp": fp, "words": w, "rendered": r} for u, (fp, w, r, st) in pages.items()]
    for n in nodes:
        if n["fp"] is None:
            del n["fp"], n["words"]
    site = {} if scripts is None else {"scripts": scripts}
    return {"created": "2026-10-01T00:00:00Z", "start": start, "links": [], "pages": [], "broken": [], "site": site, "graph": {"nodes": nodes, "edges": [], "sources": []}}


class InComparisons(unittest.TestCase):
    A = content.fingerprint(page(article(420, 1)))
    B = content.fingerprint(page(article(420, 2)))

    def changes(self, old, new, section="page-changed"):
        return [c for c in sn.diff(old, new).changes if c.section == section]

    def test_changed_text_is_reported_unchanged_text_is_not(self):
        u = "https://e.com/"
        same = self.changes(session({u: (*self.A, False, 200)}), session({u: (*self.A, False, 200)}))
        self.assertEqual(same, [])
        c = self.changes(session({u: (*self.A, False, 200)}), session({u: (*self.B, False, 200)}))
        self.assertEqual((len(c), c[0].subject, c[0].severity), (1, u, "low"))
        self.assertIn("largely different", c[0].detail)

    def test_it_is_not_a_regression(self):
        u = "https://e.com/"
        d = sn.diff(session({u: (*self.A, False, 200)}), session({u: (*self.B, False, 200)}))
        self.assertEqual(d.regressions("low"), [])

    def test_what_cannot_be_compared_is_skipped(self):
        u = "https://e.com/"
        old = session({u: (*self.A, False, 200)})
        self.assertEqual(self.changes(old, session({u: (*self.B, True, 200)})), [])        # one crawl ran the page's JavaScript, the other did not
        self.assertEqual(self.changes(old, session({u: (*self.B, False, 500)})), [])       # an error page: the status change says it
        self.assertEqual(self.changes(old, session({u: (None, 0, False, 200)})), [])       # an older session never measured it
        self.assertEqual(self.changes(session({u: (None, 0, False, 200)}), old), [])

    def test_new_third_party_scripts_are_a_regression(self):
        u = "https://e.com/"
        old = session({u: (*self.A, False, 200)}, scripts={"cdn.good.net": {"count": 3, "pages": [u]}})
        new = session({u: (*self.A, False, 200)}, scripts={"cdn.good.net": {"count": 3, "pages": [u]}, "evil.example": {"count": 2, "pages": [u, u + "x"]}})
        d = sn.diff(old, new)
        c = [x for x in d.changes if x.section == "script-new"]
        self.assertEqual((len(c), c[0].subject, c[0].severity), (1, "evil.example", "medium"))
        self.assertIn("and 1 more", c[0].detail)
        self.assertEqual(len(d.regressions("medium")), 1)
        self.assertEqual([x for x in sn.diff(new, old).changes if x.section == "script-new"], [])          # a script going away is not news
        no_data = session({u: (*self.A, False, 200)})
        self.assertEqual([x for x in sn.diff(no_data, new).changes if x.section == "script-new"], [])      # the older session did not record scripts

    def test_text_of_the_change(self):
        u = "https://e.com/"
        d = sn.diff(session({u: (*self.A, False, 200)}), session({u: (*self.B, False, 200)}))
        self.assertIn("Pages whose content changed (1)", d.to_text())


class InTheScanner(unittest.TestCase):
    """Two real scans of a local page, between which the page's text and scripts change."""

    @classmethod
    def setUpClass(cls):
        cls.srv = ths.serve()
        cls.srv.other_base = cls.srv.base
        cls.base = cls.srv.base

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def scan(self):
        s, ev, store, site, info, sec = ths.run_scan(self.base + "/article", depth=0, use_sitemap=False)
        return sn.build(self.base + "/article", s.opts, store, site, sec, [], info), site, info

    def test_a_page_that_changes_between_crawls_is_noticed(self):
        self.srv.article, self.srv.extra = article(), ""
        old, site, info = self.scan()
        node = site.nodes[fr.normalize(self.base + "/article")]
        self.assertTrue(node.fp and node.words > 300, (node.fp, node.words))
        again, _, _ = self.scan()
        self.assertEqual([c for c in sn.diff(old, again).changes if c.section in ("page-changed", "script-new")], [])     # unchanged page: silence
        self.srv.article = article() + " " + " ".join(["buy cheap pills online casino bonus click here now"] * 10)
        self.srv.extra = "<script src='https://cdn.skimmer.example/pay.js'></script>"
        new, _, info2 = self.scan()
        d = sn.diff(old, new)
        sec = {c.section: c for c in d.changes}
        self.assertIn("text changed", sec["page-changed"].detail)
        self.assertEqual(sec["script-new"].subject, "cdn.skimmer.example")
        self.assertIn("cdn.skimmer.example", info2.scripts)
        self.assertNotIn("cdn.skimmer.example", info.scripts)


if __name__ == "__main__":
    unittest.main()
