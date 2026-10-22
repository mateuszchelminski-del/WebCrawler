"""Browser-crawler features: logins, markup checks, sitemap discovery, resume. Skipped if no browser is available."""
import queue
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_webcrawler import _have_browser  # noqa: E402
import test_httpscan_checks as ths  # noqa: E402

import auth  # noqa: E402
import engine as eng  # noqa: E402
import frontier as fr  # noqa: E402


def collect(e, until, timeout=60):
    seen, end = [], time.time() + timeout
    while time.time() < end and not until(seen):
        try:
            seen.append(e.events.get(timeout=0.3))
        except queue.Empty:
            pass
    return seen


def finished(events):
    return ("auto", False) in [x[:2] for x in events]


@unittest.skipUnless(_have_browser(), "Playwright with a browser is not available")
class BrowserChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.other = ths.serve(), ths.serve()
        cls.srv.other_base = cls.other.base
        cls.base = cls.srv.base

    @classmethod
    def tearDownClass(cls):
        for s in (cls.srv, cls.other):
            s.shutdown()
            s.server_close()

    def setUp(self):
        self.srv.hits.clear()
        self.srv.seen.clear()
        self.other.seen.clear()

    def start(self, url, auth_cfg=None, resume=None, **opts):
        o = dict(delay_min=0, delay_max=0, scroll_speed=1500, depth=3)
        o.update(opts)
        e = eng.Engine()
        e.start()
        self.addCleanup(lambda: (e.send("quit"), e.join(timeout=15)))
        e.send("start", settings=eng.Settings(url=url, headless=True, auto=True, opts=fr.CrawlOptions(**o), auth=auth_cfg or auth.AuthConfig(), resume=resume))
        return e

    def test_login_reaches_protected_pages_and_skips_logout(self):
        cfg = auth.AuthConfig.build(cookie="sid=ok", headers=["X-Token: t"], domain="127.0.0.1")
        e = self.start(self.base + "/members", cfg, use_sitemap=False)
        ev = collect(e, finished)
        pages = {x[1].replace(self.base, "") for x in ev if x[0] == "page"}
        self.assertEqual(pages, {"/members", "/account"})
        self.assertNotIn("/logout", self.srv.hits)
        self.assertEqual(e.graph.nodes[fr.normalize(self.base + "/members")].status, 200)
        sent = [h for p, h in self.srv.seen if p == "/members"][0]
        self.assertEqual(sent.get("x-token"), "t")
        self.assertIn("sid=ok", sent.get("cookie", ""))
        self.assertFalse(any("sid=ok" in str(x) or "Bearer" in str(x) for x in ev if x[0] == "status"))   # the login is never echoed

    def test_login_headers_go_to_page_loads_and_script_calls_but_not_to_images_scripts_and_styles(self):
        cfg = auth.AuthConfig.build(cookie="sid=ok", headers=["X-Token: t"], domain="127.0.0.1")
        e = self.start(self.base + "/with-assets", cfg, use_sitemap=False, depth=0)
        collect(e, finished)
        deadline = time.time() + 8
        while "/api/data" not in self.srv.hits and time.time() < deadline:      # the page's own script calls the API after it loads
            time.sleep(0.1)

        def sent(path):
            return [h for p, h in self.srv.seen if p == path]
        for path in ("/with-assets", "/api/data"):
            self.assertTrue(sent(path), path)
            self.assertTrue(all(h.get("x-token") == "t" for h in sent(path)), path)             # a page load and a fetch() carry the header
        for path in ("/app.js", "/pic.png", "/site.css"):
            self.assertTrue(sent(path), path)
            self.assertTrue(all("x-token" not in h for h in sent(path)), path)                  # sub-resources do not need it and are not rewritten
            self.assertTrue(all("sid=ok" in h.get("cookie", "") for h in sent(path)), path)     # the cookie still goes along, as the browser's own

    def test_without_a_login_the_pages_are_denied(self):
        e = self.start(self.base + "/members", use_sitemap=False, depth=1)
        ev = collect(e, finished)
        self.assertTrue(any(x[0] == "broken" and x[2] == 403 for x in ev))

    def test_extra_headers_are_not_sent_to_other_hosts(self):
        cfg = auth.AuthConfig.build(headers=["X-Token: t"])
        e = self.start(self.base + "/leak", cfg, use_sitemap=False, depth=0)
        collect(e, finished)
        self.assertEqual([h.get("x-token") for p, h in self.srv.seen if p == "/leak"], ["t"])
        hops = [h for p, h in self.other.seen if p == "/echo"]
        self.assertTrue(hops)
        self.assertTrue(all("x-token" not in h for h in hops))

    def test_markup_findings_and_technologies(self):
        e = self.start(self.base + "/page-html", depth=0, use_sitemap=False)
        ev = collect(e, finished)
        sec = [x[1] for x in ev if x[0] == "security" and x[1].url.endswith("/page-html")]
        codes = {f.code for s in sec for f in s.findings}
        self.assertTrue({"no-sri-script", "password-in-url"} <= codes, codes)
        self.assertTrue({("jQuery", "3.4.1"), ("WordPress", "6.2")} <= set(e.info.tech))

    def test_forms_and_parameters_are_inventoried(self):
        e = self.start(self.base + "/inputs", depth=0, use_sitemap=False)
        collect(e, finished)
        forms = {(f["method"], f["action"].replace(self.base, "")): f for f in e.info.forms.values()}
        self.assertEqual(set(forms), {("post", "/login"), ("get", "/search")})
        self.assertTrue(forms[("post", "/login")]["password"])
        self.assertTrue(forms[("get", "/search")]["search"])
        self.assertTrue({"q", "page", "id"} <= set(e.info.params))

    def test_sitemap_pages_are_visited_and_orphans_reported(self):
        e = self.start(self.base + "/", depth=2)
        collect(e, finished)
        visited = {u.replace(self.base, "") for u in e.graph.nodes if e.graph.nodes[u].visited}
        self.assertIn("/hidden", visited)
        self.assertNotIn("/admin/", visited)
        self.assertIn(("orphan-page", fr.normalize(self.base + "/hidden")), {(f.code, w) for f, w in e.info.findings})

    def test_stop_then_resume_does_not_refetch(self):
        e = self.start(self.base + "/chain/0", use_sitemap=False, depth=10, delay_min=0.4, delay_max=0.4)
        collect(e, lambda s: sum(1 for x in s if x[0] == "page") >= 2)
        e.send("auto", on=False)
        ev = collect(e, finished, timeout=20)
        summary = [x[1] for x in ev if x[0] == "scan_done"][0]
        self.assertTrue(summary["resumable"])
        state = e.resume_state
        self.assertTrue(state["visited"] and state["queue"])
        done = len(state["visited"])
        e2 = self.start(self.base + "/chain/0", resume=state, use_sitemap=False, depth=10)
        e2.store, e2.graph = e.store, e.graph
        collect(e2, finished, timeout=60)
        self.assertGreater(len(e2.resume_state["visited"]), done)
        self.assertFalse(e2.last_summary["resumable"])
        chain = {p: n for p, n in self.srv.hits.items() if p.startswith("/chain/")}
        self.assertLessEqual(sum(chain.values()), len(chain) + 1, chain)   # at most one page is repeated: the one the stop interrupted
        self.assertTrue(all(n <= 2 for n in chain.values()), chain)

    def test_export_cookies_command(self):
        cfg = auth.AuthConfig.build(cookie="sid=ok", domain="127.0.0.1")
        e = self.start(self.base + "/a", cfg, depth=0, use_sitemap=False)
        collect(e, finished)
        e.send("export_cookies")
        ev = collect(e, lambda s: any(x[0] == "cookies" for x in s), timeout=10)
        cookies = [x[1] for x in ev if x[0] == "cookies"]
        self.assertTrue(cookies and any(c["name"] == "sid" for c in cookies[0]))


if __name__ == "__main__":
    unittest.main()
