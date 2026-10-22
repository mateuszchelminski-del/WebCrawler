"""GUI tests: build the real window, feed it engine events, check the tables and the exports. Skipped without a display."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import tkinter as tk
    _r = tk.Tk()
    _r.destroy()
    HAVE_DISPLAY = True
except Exception:
    HAVE_DISPLAY = False

if HAVE_DISPLAY:
    import analysis as an
    import frontier as fr
    import webcrawler_gui as g
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import test_httpscan as ths
    import test_httpscan_checks as thc
    import auth as authmod

PAGE = "https://example.com/"


@unittest.skipUnless(HAVE_DISPLAY, "no display available for Tk")
class Gui(unittest.TestCase):
    def setUp(self):
        self.app = g.App("https://example.com")
        self.addCleanup(self.app._close)
        for href, text in (("/about", "About"), ("https://bit.ly/x", "Short"), ("https://paypal.com@evil.test/a", "Pay"), ("mailto:a@b.co", "Mail")):
            link = self.app.engine.store.add({"href": href, "text": text, "page": PAGE})[1]
            self.app._handle(("link", link, an.assess_link(link.href, link.kind, link.page)))
        self.app.update()

    def test_rows_and_stats(self):
        self.assertEqual(len(self.app.tv.get_children()), 4)
        self.assertEqual(self.app.stat["links"].cget("text"), "4")
        self.assertEqual(self.app.stat["risky"].cget("text"), "2")

    def test_filters(self):
        self.app.risky_var.set(True)
        self.app._refill()
        self.assertEqual(len(self.app.tv.get_children()), 2)
        self.app.risky_var.set(False)
        self.app.kind_var.set("mailto")
        self.app._refill()
        self.assertEqual(len(self.app.tv.get_children()), 1)
        self.app.kind_var.set("all types")
        self.app.q_var.set("bit.ly")
        self.app.update()
        self.assertEqual(len(self.app.tv.get_children()), 1)

    def test_detail_and_findings_tab(self):
        iid = next(i for i in self.app.tv.get_children() if "paypal" in self.app.tv.set(i, "url"))
        self.app.tv.selection_set(iid)
        self.app.update()
        self.assertIn("user@host", self.app.detail.get("1.0", "end"))
        self.app._dirty_findings = True
        self.app._refresh_findings()
        sev = [self.app.ftv.set(i, "sev") for i in self.app.ftv.get_children()]
        self.assertEqual(sev[0], "HIGH")

    def test_security_event_fills_tab(self):
        sec = an.PageSecurity(PAGE, 200, an.check_headers(PAGE, [])[0], {"server": "x"})
        self.app._handle(("security", sec))
        self.assertEqual(len(self.app.stv.get_children()), 1)
        self.app.stv.selection_set(self.app.stv.get_children()[0])
        self.app.update()
        self.assertIn("No Content-Security-Policy", self.app.sec_detail.get("1.0", "end"))

    def test_exports_write_files(self):
        with tempfile.TemporaryDirectory() as d:
            for fmt, name in (("csv", "a.csv"), ("json", "a.json"), ("html", "a.html")):
                path = str(Path(d) / name)
                with mock.patch.object(g.filedialog, "asksaveasfilename", return_value=path), mock.patch.object(g.messagebox, "askyesno", return_value=False):
                    self.app._export(fmt)
                self.assertTrue(Path(path).read_text(encoding="utf-8").strip(), fmt)
            with mock.patch.object(g.filedialog, "askdirectory", return_value=d):
                self.app._export_all()
            self.assertTrue((Path(d) / "report.html").exists())
            self.assertIn("risk", (Path(d) / "links.csv").read_text(encoding="utf-8").splitlines()[0])

    def findings_rows(self):
        self.app._dirty_findings = True
        self.app._refresh_findings(force=True)
        return {i: self.app.ftv.item(i, "values") for i in self.app.ftv.get_children()}

    def test_accepting_a_finding_takes_it_off_the_list_and_remembers_it(self):
        import accepted as accepted_mod

        class Stub:
            def __init__(self, parent, code, title, where):
                self.result = (code, where, "marketing links", "2027-01-01")
        rows = self.findings_rows()
        iid = next(i for i, v in rows.items() if "bit.ly" in v[2])
        code, key, title, was = self.app._flat[iid]
        self.assertEqual((code, was), ("shortener", False))
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "accepted.json"
            with mock.patch.object(g, "AcceptDialog", Stub), mock.patch.object(self.app, "wait_window"), mock.patch.object(g.filedialog, "asksaveasfilename", return_value=str(path)):
                self.app._accept(code, key, title)
            saved = accepted_mod.Accepted.load(path)
            self.assertEqual([(e["code"], e["where"], e["reason"], e["expires"]) for e in saved.entries], [("shortener", key, "marketing links", "2027-01-01")])
            after = self.findings_rows()
            self.assertEqual(len(after), len(rows) - 1)
            self.assertFalse(any("bit.ly" in v[2] for v in after.values()))
            self.app.show_accepted.set(True)
            shown = self.findings_rows()
            row = next(v for v in shown.values() if "bit.ly" in v[2])
            self.assertEqual(row[0], "ACCEPTED")
            self.assertTrue(row[1].startswith("✓ "))
            iid = next(i for i, v in shown.items() if "bit.ly" in v[2])
            self.assertTrue(self.app._flat[iid][3])
            self.app._unaccept(self.app._flat[iid][0], self.app._flat[iid][1])
            self.assertEqual(len(accepted_mod.Accepted.load(path)), 0)
            self.assertTrue(all(v[0] != "ACCEPTED" for v in self.findings_rows().values()))

    def test_the_accept_dialog_checks_the_date(self):
        dlg = g.AcceptDialog(self.app, "no-csp", "No CSP", "https://example.com/a")
        dlg.expires.set("next week")
        with mock.patch.object(g.messagebox, "showerror") as err:
            dlg._ok()
        err.assert_called_once()
        self.assertIsNone(dlg.result)
        dlg.expires.set("2027-02-03")
        dlg.reason.set("static site")
        dlg.scope.set("all")
        dlg._ok()
        self.assertEqual(dlg.result, ("no-csp", "*", "static site", "2027-02-03"))

    def test_accepted_findings_are_not_counted_in_comparisons(self):
        import snapshot
        old = self.app._current_session()
        link = self.app.engine.store.add({"href": "https://t.co/new", "text": "n", "page": PAGE})[1]
        self.app._handle(("link", link, an.assess_link(link.href, link.kind, link.page)))
        new = self.app._current_session()
        self.assertEqual(len(snapshot.diff(old, new).regressions()), 1)
        self.app.accepted.add("shortener", "https://t.co/*", "ok")
        with mock.patch.object(g.filedialog, "askopenfilename", return_value=self._save(old)):
            self.app._compare_with()
        self.assertEqual(self.app.diff.regressions(), [])
        self.assertEqual(self.app.diff.suppressed, 1)

    def _save(self, session):
        d = tempfile.mkdtemp()
        path = str(Path(d) / "old.json")
        g.snapshot.save(path, session)
        return path

    def test_adding_a_crawl_to_a_history_shows_the_trend(self):
        import history
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "history.json")
            with mock.patch.object(g.filedialog, "asksaveasfilename", return_value=path), mock.patch.object(g.webbrowser, "open") as opened:
                self.app._trend(add=True)
                self.app._trend(add=True)
            self.assertEqual(len(history.History.load(path).runs), 2)
            self.assertEqual(opened.call_count, 2)
            page = Path(d) / "history-trend.html"
            self.assertIn("<svg", page.read_text(encoding="utf-8"))

    def test_a_huge_site_is_drawn_as_groups_you_can_inspect(self):
        import test_graph
        g, _ = test_graph.shop(12, 150, crawled_every=3, star=True)
        self.app.graph.load_state(g.to_state())
        self.app.nb.select(1)
        for _ in range(5):
            self.app.update()
        nodes, edges, pos = self.app._map_data()
        self.assertLessEqual(len(nodes), 800)
        groups = [n for n in nodes if n.kind == "cluster"]
        self.assertTrue(groups)
        self.app._map_fit()
        self.assertIn("groups of similar pages", self.app.map_lbl.cget("text"))
        self.app._map_sel = groups[0].url
        self.app._map_show(groups[0].url)
        shown = self.app.map_info.get("1.0", "end")
        self.assertIn("group of similar pages", shown)
        self.assertIn("/cat", shown)
        self.assertGreaterEqual(self.app._map_gap, 0.7)

    def test_clear(self):
        self.app._clear()
        self.assertEqual((len(self.app.rows), len(self.app.tv.get_children()), len(self.app.engine.store)), (0, 0, 0))

    def test_skin_and_summon_state_before_launch(self):
        self.app._pick_skin("hacker")
        self.assertEqual(self.app.settings.skin, "hacker")
        self.app._toggle_summon()
        self.assertFalse(self.app.settings.summoned)
        self.assertEqual(self.app._settings_for("http://x/", False).skin, "hacker")

    def test_bad_url_is_rejected(self):
        self.app.url_var.set("ftp://example.com")
        with mock.patch.object(g.messagebox, "showerror") as err:
            self.assertIsNone(self.app._normalized_url())
            err.assert_called_once()


@unittest.skipUnless(HAVE_DISPLAY, "no display available for Tk")
class GuiCrawling(unittest.TestCase):
    """The parts added for crawling: presets, settings dialog, the map, and a real quick scan driven from the window."""

    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base = ths.serve()
        cls.srv.ext_base = cls.base

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.app = g.App()
        self.addCleanup(self.app._close)

    def test_preset_changes_pacing(self):
        self.app.preset_var.set("stealth")
        self.app._preset_changed()
        self.assertEqual((self.app.opts.delay_min, self.app.opts.concurrency), (5.0, 1))
        self.assertIn("5-15s", self.app.opts_lbl.cget("text"))
        self.app.preset_var.set("blitz")
        self.app._preset_changed()
        self.assertEqual(self.app.opts.delay_max, 0.0)

    def test_settings_dialog_parses_and_rejects(self):
        dlg = g.AdvancedDialog(self.app, self.app.opts, False)
        dlg.v["delay_min"].set("2")
        dlg.v["delay_max"].set("4.5")
        dlg.v["max_duration"].set("3")
        dlg.v["scope"].set("subdomains")
        dlg.inc.insert("1.0", "/docs")
        dlg.exc.insert("1.0", "/logout")
        new = dlg.parse()
        self.assertEqual((new["delay_min"], new["delay_max"], new["max_duration"], new["scope"]), (2.0, 4.5, 180.0, "subdomains"))
        self.assertEqual((new["include"], new["exclude"]), (["/docs"], ["/logout"]))
        dlg.exc.insert("1.0", "([bad")
        with self.assertRaises(g.re.error):
            dlg.parse()
        dlg.destroy()

    def test_map_draws_hits_and_zooms(self):
        gph = self.app.graph
        gph.set_root("https://example.com/")
        gph.visit("https://example.com/", 0, 200, "Home")
        for p in ("a", "b", "c"):
            gph.link("https://example.com/", f"https://example.com/{p}", "internal")
        gph.link("https://example.com/", "https://other.org/x", "external")
        self.app.nb.select(1)
        self.app.update()
        self.app._map_fit()
        self.app.update()
        self.assertEqual(len(self.app._map_screen), 5)  # 4 pages + 1 collapsed external host
        x, y = self.app._map_screen["https://example.com/a"]
        self.assertEqual(self.app._map_hit(x + 2, y + 2), "https://example.com/a")
        k = self.app.mv["kx"]
        self.app._map_zoom(2.0, 100, 100)
        self.assertAlmostEqual(self.app.mv["kx"], k * 2)
        self.app.map_ext.set(False)
        self.app._map_fit()
        self.assertEqual(len(self.app._map_screen), 4)
        self.app._map_sel = "https://example.com/a"
        self.app._map_show("https://example.com/a")
        self.assertIn("linked from 1", self.app.map_info.get("1.0", "end"))

    def test_quick_scan_from_the_window(self):
        import time
        self.app.url_var.set(self.base + "/index.html")
        self.app.crawl_mode_var.set("Quick scan (no browser)")
        self.app.preset_var.set("blitz")
        self.app._preset_changed()
        self.app.depth_var.set(3)
        self.app._toggle_auto()
        end = time.time() + 60
        while time.time() < end:
            self.app.update()
            time.sleep(0.05)
            if self.app.scanner and not self.app.scanner.is_alive() and not self.app.auto_on:
                break
        for _ in range(10):
            self.app.update()
        self.assertGreater(len(self.app.rows), 10)
        self.assertGreaterEqual(self.app.graph.stats()["pages"], 5)
        self.assertTrue(any(b[0].endswith("/nope.html") for b in self.app.broken))
        self.assertEqual(self.app.stat["broken"].cget("text"), str(len(self.app.broken)))
        self.assertGreater(len(self.app.sec), 3)
        self.app._dirty_findings = True
        self.app._refresh_findings()
        self.assertTrue(any("Broken link" in self.app.ftv.set(i, "title") for i in self.app.ftv.get_children()))
        self.app.nb.select(1)
        self.app.update()
        self.assertGreater(len(self.app._map_screen), 8)
        self.assertEqual(self.app.auto_btn.cget("text"), "▶  Start crawl")


@unittest.skipUnless(HAVE_DISPLAY, "no display available for Tk")
class GuiMonitoring(unittest.TestCase):
    """Sessions, resume, comparing, logins and the Site tab, driven through the real window with quick scans."""

    @classmethod
    def setUpClass(cls):
        cls.srv = thc.serve()
        cls.srv.other_base = cls.srv.base
        cls.base = cls.srv.base

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.srv.hits.clear()
        self.srv.extra = ""
        self.app = g.App()
        self.addCleanup(self.app._close)
        self.tmp = Path(tempfile.mkdtemp())
        self.app.crawl_mode_var.set("Quick scan (no browser)")
        self.app.preset_var.set("blitz")
        self.app._preset_changed()
        self.app.opts.check_tls = False

    def scan(self, start="/", depth=3, **opts):
        import time
        for k, v in opts.items():
            setattr(self.app.opts, k, v)
        self.app.url_var.set(self.base + start)
        self.app.depth_var.set(depth)
        self.app._toggle_auto()
        end = time.time() + 60
        while time.time() < end:
            self.app.update()
            time.sleep(0.03)
            if self.app.scanner and not self.app.scanner.is_alive() and not self.app.auto_on:
                break
        for _ in range(10):
            self.app.update()

    def test_save_clear_open_restores_the_whole_session(self):
        self.scan()
        rows, pages, sec = len(self.app.rows), self.app.graph.stats()["pages"], len(self.app.sec)
        self.assertGreater(rows, 1)
        path = str(self.tmp / "s.json")
        with mock.patch.object(g.filedialog, "asksaveasfilename", return_value=path):
            self.app._save_session()
        self.app._clear()
        self.assertEqual((len(self.app.rows), self.app.graph.stats()["pages"]), (0, 0))
        with mock.patch.object(g.filedialog, "askopenfilename", return_value=path):
            self.app._open_session()
        self.assertEqual((len(self.app.rows), self.app.graph.stats()["pages"], len(self.app.sec)), (rows, pages, sec))
        self.assertEqual(len(self.app.tv.get_children()), rows)
        self.assertEqual(self.app.url_var.get(), self.base + "/")
        self.assertTrue(self.app.info.seeds)                              # the sitemap result came back too

    def test_opening_a_bad_file_shows_an_error_and_changes_nothing(self):
        self.scan()
        rows = len(self.app.rows)
        bad = self.tmp / "bad.json"
        bad.write_text("nope", encoding="utf-8")
        with mock.patch.object(g.filedialog, "askopenfilename", return_value=str(bad)), mock.patch.object(g.messagebox, "showerror") as err:
            self.app._open_session()
            err.assert_called_once()
        self.assertEqual(len(self.app.rows), rows)

    def test_stop_then_resume_from_the_window(self):
        import time
        self.app.preset_var.set("custom")
        self.app.opts.delay_min = self.app.opts.delay_max = 0.2
        self.app.opts.concurrency = 1
        self.app.url_var.set(self.base + "/chain/0")
        self.app.depth_var.set(10)
        self.app.opts.use_sitemap = False
        self.app._toggle_auto()
        t0 = time.time()
        while time.time() - t0 < 1.0:
            self.app.update()
            time.sleep(0.03)
        self.app._toggle_auto()                                           # Stop
        end = time.time() + 30
        while time.time() < end and (self.app.auto_on or (self.app.scanner and self.app.scanner.is_alive())):
            self.app.update()
            time.sleep(0.03)
        for _ in range(10):
            self.app.update()
        self.assertIsNotNone(self.app.resume_state)
        self.assertEqual(self.app.auto_btn.cget("text"), "▶  Resume crawl")
        done = len(self.app.resume_state["visited"])
        self.app.opts.delay_min = self.app.opts.delay_max = 0
        self.app._toggle_auto()                                           # Resume
        end = time.time() + 60
        while time.time() < end:
            self.app.update()
            time.sleep(0.03)
            if self.app.scanner and not self.app.scanner.is_alive() and not self.app.auto_on:
                break
        for _ in range(10):
            self.app.update()
        self.assertIsNone(self.app.resume_state)
        self.assertEqual(self.app.auto_btn.cget("text"), "▶  Start crawl")
        chain = {p: n for p, n in self.srv.hits.items() if p.startswith("/chain/")}
        self.assertEqual(len(chain), 8)
        self.assertTrue(all(n == 1 for n in chain.values()), chain)
        self.assertGreater(len(chain), done)

    def test_changing_the_url_does_not_resume_the_old_crawl(self):
        self.app.resume_state = {"root": "https://other.example/", "queue": [["https://other.example/a", 1, None]], "visited": []}
        self.assertIsNone(self.app._resume_for("https://something-else.example/"))
        self.assertIsNotNone(self.app._resume_for("https://other.example"))   # the same site, however it is typed

    def test_compare_with_an_earlier_session_shows_what_changed(self):
        self.scan()
        old = str(self.tmp / "old.json")
        with mock.patch.object(g.filedialog, "asksaveasfilename", return_value=old):
            self.app._save_session()
        self.srv.extra = "<a href='https://paypal.com@evil.test/login'>login</a>"
        self.scan()
        with mock.patch.object(g.filedialog, "askopenfilename", return_value=old):
            self.app._compare_with()
        rows = [self.app.ctv.item(i, "values") for i in self.app.ctv.get_children()]
        self.assertTrue(any("evil.test" in r[2] and r[0] == "HIGH" for r in rows), rows)
        self.assertIn("regression", self.app.diff_lbl.cget("text"))
        self.assertEqual(self.app.nb.select(), self.app.nb.tabs()[6])
        out = str(self.tmp / "changes.html")
        with mock.patch.object(g.filedialog, "asksaveasfilename", return_value=out), mock.patch.object(g.messagebox, "askyesno", return_value=False):
            self.app._export_changes()
        self.assertIn("evil.test", Path(out).read_text(encoding="utf-8"))

    def test_compare_two_saved_sessions(self):
        self.scan()
        a = str(self.tmp / "a.json")
        with mock.patch.object(g.filedialog, "asksaveasfilename", return_value=a):
            self.app._save_session()
        self.srv.extra = "<a href='https://bit.ly/x'>s</a>"
        self.scan()
        b = str(self.tmp / "b.json")
        with mock.patch.object(g.filedialog, "asksaveasfilename", return_value=b):
            self.app._save_session()
        with mock.patch.object(g.filedialog, "askopenfilename", side_effect=[a, b]):
            self.app._compare_two()
        self.assertTrue(any("bit.ly" in self.app.ctv.item(i, "values")[2] for i in self.app.ctv.get_children()))

    def test_export_all_includes_session_and_changes(self):
        self.scan()
        self.app.diff = g.snapshot.diff(self.app._current_session(), self.app._current_session())
        d = str(self.tmp / "all")
        os.makedirs(d)
        with mock.patch.object(g.filedialog, "askdirectory", return_value=d):
            self.app._export_all()
        self.assertTrue({"session.json", "changes.html", "report.html", "sitemap.html"} <= {p.name for p in Path(d).iterdir()})
        self.assertIn("Site-wide checks", (Path(d) / "report.html").read_text(encoding="utf-8"))

    def test_site_tab_lists_probes_sitemap_and_findings(self):
        self.scan(probe_files=True)
        self.app.nb.select(3)
        for _ in range(10):
            self.app.update()
        rows = [self.app.site_tv.item(i, "values") for i in self.app.site_tv.get_children()]
        kinds = {r[0] for r in rows}
        self.assertTrue({"File", "Sitemap", "robots.txt", "Finding"} <= kinds, kinds)
        self.assertTrue(any(r[0] == "File" and r[1] == "/.git/HEAD" and r[2].startswith("EXPOSED") and r[3] == "HIGH" for r in rows))
        self.app._dirty_findings = True
        self.app._refresh_findings()
        titles = [self.app.ftv.set(i, "title") for i in self.app.ftv.get_children()]
        self.assertTrue(any("Git repository" in t for t in titles))      # site-wide findings reach the Findings tab too

    def test_inputs_tab_lists_forms_parameters_and_hosts(self):
        self.scan("/inputs", depth=0, use_sitemap=False)
        self.app.info.add_host("old.example.com", "link", "example.com")
        self.app.info.hosts["old.example.com"]["addresses"] = []
        self.app.nb.select(4)
        for _ in range(10):
            self.app.update()
        rows = [self.app.inputs_tv.item(i, "values") for i in self.app.inputs_tv.get_children()]
        self.assertTrue(any(r[0] == "Form" and r[1].startswith("POST") and r[1].endswith("/login") and "password" in r[3] for r in rows), rows)
        self.assertTrue(any(r[0] == "Form" and r[1].startswith("GET") and "search" in r[3] for r in rows))
        self.assertTrue({"?q", "?id"} <= {r[1] for r in rows if r[0] == "Parameter"})
        self.assertTrue(any(r[0] == "Host" and r[1] == "old.example.com" and r[3] == "stale name?" for r in rows))

    def test_dns_records_appear_on_the_site_tab(self):
        import dnscheck
        rep = dnscheck.DnsReport("example.com", ns=["ns1.example.net"], spf="v=spf1 -all", dmarc="", queries=7)
        rep.findings.append(g.analysis.Finding("email-no-dmarc", "medium", "No DMARC record", "x"))
        self.app.info.add_dns(rep)
        self.app.nb.select(3)
        for _ in range(10):
            self.app.update()
        rows = [self.app.site_tv.item(i, "values") for i in self.app.site_tv.get_children()]
        self.assertTrue(any(r[0] == "DNS" and r[1] == "SPF" and "v=spf1 -all" in r[2] for r in rows), rows)
        self.assertTrue(any(r[0] == "DNS" and r[1] == "DMARC" and r[2] == "none" for r in rows))
        self.assertTrue(any(r[0] == "Finding" and r[1] == "No DMARC record" and r[3] == "MEDIUM" for r in rows))

    def test_a_login_is_used_by_the_quick_scan(self):
        self.app.auth = authmod.AuthConfig.build(cookie="sid=ok", headers=["X-Token: t"], domain="127.0.0.1")
        self.scan("/members", depth=2, use_sitemap=False)
        self.assertIn("/account", self.srv.hits)
        self.assertNotIn("/logout", self.srv.hits)
        self.app._forget_login()
        self.assertTrue(self.app.auth.empty)

    def test_cookies_copied_from_the_browser_are_filtered_to_the_site(self):
        self.app.url_var.set("https://app.example.com/")
        self.app._handle(("cookies", [{"name": "sid", "value": "1", "domain": ".example.com", "path": "/"}, {"name": "track", "value": "2", "domain": ".ads.net", "path": "/"}]))
        self.assertEqual([c["name"] for c in self.app.auth.cookies], ["sid"])

    def test_settings_dialog_login_and_discovery_options(self):
        dlg = g.AdvancedDialog(self.app, self.app.opts, False, authmod.AuthConfig(), "app.example.com")
        dlg.cookie_var.set("sid=abc; theme=dark")
        dlg.hdr.insert("1.0", "Authorization: Bearer tok\nX-Api-Key: k1")
        dlg.v["probe_files"].set(True)
        dlg.v["use_sitemap"].set(False)
        dlg.v["check_tls"].set(False)
        self.assertFalse(dlg.parse()["check_dns"])                          # reading DNS names the domain to a third party: off unless chosen
        dlg.v["check_dns"].set(True)
        new, login = dlg.parse(), dlg.build_login()
        self.assertEqual((new["probe_files"], new["use_sitemap"], new["check_tls"], new["check_dns"]), (True, False, False, True))
        self.assertEqual(([c["name"] for c in login.cookies], login.headers), (["sid", "theme"], {"Authorization": "Bearer tok", "X-Api-Key": "k1"}))
        self.assertEqual(login.cookies[0]["domain"], "app.example.com")
        dlg.hdr.insert("end", "\nbad header line")
        with self.assertRaises(ValueError):
            dlg.build_login()
        dlg._clear_login()
        self.assertTrue(dlg.build_login().empty)
        dlg.destroy()


if __name__ == "__main__":
    unittest.main()
