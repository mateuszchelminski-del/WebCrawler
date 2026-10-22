import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import analysis as an  # noqa: E402
import checks as ck  # noqa: E402
import frontier as fr  # noqa: E402
import graph as gr  # noqa: E402
import snapshot as sn  # noqa: E402
import webcrawler as wc  # noqa: E402

ROOT = "https://example.com/"


def crawl(extra_links=(), status=None, headers=None, findings=None, tech=(), site_findings=(), tls=None, resume=None):
    """A small finished crawl, as live objects, then built into session data."""
    store, g, site = wc.LinkStore(), gr.SiteGraph(), ck.SiteInfo()
    g.set_root(ROOT)
    g.visit(ROOT, 0, 200, "Home")
    for path in ("about", "blog"):
        g.link(ROOT, ROOT + path, "internal")
        g.visit(ROOT + path, 1, (status or {}).get(path, 200), path)
        store.add({"href": "/" + path, "text": path, "page": ROOT})
    for href in extra_links:
        store.add({"href": href, "text": "x", "page": ROOT})
    sec = {ROOT: an.PageSecurity(ROOT, 200, list(findings or []), dict(headers or {"strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'"}))}
    for t in tech:
        site.add_tech([t], ROOT)
    for f, w in site_findings:
        site.add_finding(f, w)
    if tls:
        site.add_tls(tls)
    return sn.build(ROOT, fr.CrawlOptions(depth=2), store, g, sec, [], site, resume), (store, g, sec, site)


def sections(d):
    out = {}
    for c in d.changes:
        out.setdefault(c.section, []).append(c)
    return out


class SaveLoad(unittest.TestCase):
    def test_round_trip_through_a_file_restores_everything(self):
        data, (store, g, sec, site) = crawl(["https://bit.ly/x", "https://paypal.com@evil.test/"], findings=[an.Finding("no-csp", "medium", "No CSP")],
                                            tech=[ck.Tech("PHP", "5.6", "X-Powered-By header", "language")], resume={"queue": [[ROOT + "next", 1, ROOT]], "visited": [ROOT]})
        path = str(Path(tempfile.mkdtemp()) / "s.json")
        sn.save(path, data)
        back = sn.load(path)
        s2, g2, sec2, site2 = wc.LinkStore(), gr.SiteGraph(), {}, ck.SiteInfo()
        broken, resume = sn.restore(back, s2, g2, sec2, site2)
        self.assertEqual([(l.n, l.href, l.kind) for l in s2.all()], [(l.n, l.href, l.kind) for l in store.all()])
        self.assertEqual(g2.stats(), g.stats())
        self.assertEqual(set(g2.edges), set(g.edges))
        self.assertEqual(sec2[ROOT].findings, sec[ROOT].findings)
        self.assertEqual(set(site2.tech), set(site.tech))
        self.assertEqual(resume["queue"], [[ROOT + "next", 1, ROOT]])
        self.assertEqual(broken, [])
        self.assertEqual(sn.options_from(back).depth, 2)

    def test_new_links_keep_numbering_after_restore(self):
        data, _ = crawl()
        s = wc.LinkStore()
        sn.restore(data, s, gr.SiteGraph(), {}, None)
        self.assertEqual(s.add({"href": "/new", "page": ROOT})[1].n, 3)  # the two restored links were #1 and #2

    def test_save_is_atomic_and_leaves_no_temp_files(self):
        d = Path(tempfile.mkdtemp())
        data, _ = crawl()
        sn.save(str(d / "a.json"), data)
        self.assertEqual([p.name for p in d.iterdir()], ["a.json"])

        class Boom:
            def __init__(self):  # not JSON-serialisable: the write fails half way
                pass
        bad = dict(data, x=Boom())
        with self.assertRaises(TypeError):
            sn.save(str(d / "a.json"), bad)
        self.assertEqual([p.name for p in d.iterdir()], ["a.json"])           # no stray temp file
        self.assertEqual(sn.load(str(d / "a.json"))["start"], ROOT)            # the old file is untouched

    def test_load_rejects_what_is_not_a_session(self):
        d = Path(tempfile.mkdtemp())
        for name, text in (("a.json", "not json"), ("b.json", '{"format": "other"}'), ("c.json", "[]"), ("d.json", json.dumps({"format": sn.FORMAT, "version": 99}))):
            (d / name).write_text(text, encoding="utf-8")
            with self.assertRaises(ValueError, msg=name):
                sn.load(str(d / name))

    def test_credentials_are_never_in_a_session(self):
        data, _ = crawl()
        blob = json.dumps(data).lower()
        for word in ("authorization", "cookie", "bearer", "password"):
            self.assertNotIn(word, blob)

    def test_unknown_options_are_ignored(self):
        data, _ = crawl()
        data["options"]["from_the_future"] = 1
        self.assertEqual(sn.options_from(data).depth, 2)


class Diffs(unittest.TestCase):
    def test_identical_crawls_have_no_changes(self):
        a, _ = crawl()
        d = sn.diff(a, copy.deepcopy(a))
        self.assertEqual(d.changes, [])
        self.assertIn("No differences", d.to_text())
        self.assertEqual(d.regressions(), [])

    def test_pages_and_status(self):
        old, _ = crawl()
        new, (_, g, _, _) = crawl(status={"blog": 500})
        g.visit(ROOT + "pricing", 1, 200, "Pricing")
        g.link(ROOT, ROOT + "pricing", "internal")
        new["graph"] = g.to_state()
        s = sections(sn.diff(old, new))
        self.assertEqual([c.subject for c in s["page-added"]], [ROOT + "pricing"])
        self.assertEqual((s["status-changed"][0].detail, s["status-changed"][0].severity), ("200 -> 500", "medium"))
        gone = copy.deepcopy(old)
        gone["graph"]["nodes"] = [n for n in gone["graph"]["nodes"] if not n["url"].endswith("/about")]
        self.assertEqual([c.subject for c in sections(sn.diff(old, gone))["page-removed"]], [ROOT + "about"])

    def test_recovery_is_not_a_regression(self):
        broken, _ = crawl(status={"blog": 404})
        fixed, _ = crawl()
        d = sn.diff(broken, fixed)
        self.assertEqual((sections(d)["status-changed"][0].severity, d.regressions()), ("info", []))

    def test_new_risky_link_is_a_regression(self):
        old, _ = crawl()
        new, _ = crawl(["https://paypal.com@evil.test/login", "https://example.org/fine"])
        d = sn.diff(old, new)
        s = sections(d)
        self.assertEqual(len(s["link-added"]), 2)
        self.assertEqual([c.subject for c in s["risk-new"]], ["https://paypal.com@evil.test/login"])
        self.assertEqual(s["risk-new"][0].severity, "high")
        self.assertEqual(len(d.regressions()), 1)

    def test_removed_link_is_not_called_fixed(self):
        old, _ = crawl(["https://bit.ly/x"])
        new, _ = crawl()
        s = sections(sn.diff(old, new))
        self.assertEqual([c.subject for c in s["link-removed"]], ["https://bit.ly/x"])
        self.assertNotIn("risk-resolved", s)

    def test_weaker_headers(self):
        old, _ = crawl()
        weak = {"strict-transport-security": "max-age=300"}
        new, _ = crawl(headers=weak, findings=[an.Finding("no-csp", "medium", "No Content-Security-Policy header")])
        s = sections(sn.diff(old, new))
        details = {c.detail for c in s["header-weaker"]}
        self.assertIn("No Content-Security-Policy header", details)
        self.assertNotIn("content-security-policy was removed", details)        # already said by the finding: not reported twice
        self.assertTrue(any("HSTS max-age lowered" in x for x in details))
        self.assertTrue(len(sn.diff(old, new).regressions("low")) >= 2)

    def test_a_removed_header_without_its_own_finding_is_still_reported(self):
        old, _ = crawl(headers={"strict-transport-security": "max-age=31536000", "referrer-policy": "no-referrer"})
        new, _ = crawl(headers={"strict-transport-security": "max-age=31536000"})
        self.assertEqual([c.detail for c in sections(sn.diff(old, new))["header-weaker"]], ["referrer-policy was removed"])

    def test_improved_headers_and_resolved_findings(self):
        bad, _ = crawl(findings=[an.Finding("no-csp", "medium", "No CSP"), an.Finding("no-sri-script", "medium", "Third-party script without SRI", "cdn.x/a.js")])
        good, _ = crawl()
        s = sections(sn.diff(bad, good))
        self.assertEqual([c.detail for c in s["header-improved"]], ["No CSP"])
        self.assertEqual([c.detail for c in s["risk-resolved"]], ["Third-party script without SRI"])
        self.assertEqual(sn.diff(bad, good).regressions(), [])

    def test_markup_finding_on_a_new_page_is_a_new_problem_not_weaker_headers(self):
        old, _ = crawl()
        new, _ = crawl(findings=[an.Finding("no-csp", "medium", "No CSP")])
        new["pages"].append({"url": ROOT + "new", "status": 200, "findings": [{"code": "no-csp", "severity": "medium", "title": "No CSP", "detail": ""}], "headers": {}})
        s = sections(sn.diff(old, new))
        self.assertEqual([c.subject for c in s.get("risk-new", [])], [ROOT + "new"])   # a brand-new page: its problems are new problems
        self.assertEqual([c.subject for c in s["header-weaker"]], [ROOT])               # the existing page got weaker

    def test_technology_changes(self):
        old, _ = crawl(tech=[ck.Tech("jQuery", "3.7.1"), ck.Tech("Gone", "1")])
        new, _ = crawl(tech=[ck.Tech("jQuery", "3.4.1"), ck.Tech("Newlib", "2.0")])
        s = {c.subject: c for c in sections(sn.diff(old, new))["tech-changed"]}
        self.assertEqual(s["jQuery 3.4.1"].severity, "medium")
        self.assertIn("version changed", s["jQuery 3.4.1"].detail)
        self.assertEqual(s["Gone 1"].detail, "no longer detected")
        self.assertEqual(s["Newlib 2.0"].detail, "appeared")

    def test_site_wide_findings_and_tls(self):
        tls = {"host": "example.com", "ok": True, "verified": True, "protocol": "TLSv1.3", "issuer": "Old CA", "days_left": 3, "not_after": "2026-10-24", "verify_error": "", "error": ""}
        old, _ = crawl(tls=tls)
        new, _ = crawl(tls={**tls, "issuer": "New CA", "days_left": 89, "not_after": "2027-01-20"}, site_findings=[(an.Finding("exposed-file", "high", ".env file is publicly readable", "/.env"), ROOT + ".env")])
        s = sections(sn.diff(old, new))
        self.assertEqual((s["site-new"][0].severity, s["site-new"][0].subject), ("high", ROOT + ".env"))
        self.assertEqual([c.subject for c in s["site-resolved"]], ["example.com"])   # the expiring-certificate finding went away
        det = " | ".join(c.detail for c in s["tls-changed"])
        self.assertIn("issuer Old CA -> New CA", det)
        self.assertIn("certificate renewed", det)

    def test_text_and_dict_output(self):
        old, _ = crawl()
        new, _ = crawl(["https://bit.ly/x"])
        d = sn.diff(old, new)
        t = d.to_text()
        self.assertIn("New problems (1)", t)
        self.assertIn("[MEDIUM]", t)
        self.assertEqual(json.loads(json.dumps(d.to_dict()))["summary"], d.summary())
        self.assertLess(t.index("New problems"), t.index("New links"))  # worst news first

    def test_regression_levels(self):
        old, _ = crawl()
        new, _ = crawl(["https://203.0.113.9/x"], site_findings=[(an.Finding("old-nginx", "low", "old"), ROOT)])
        d = sn.diff(old, new)
        self.assertEqual(len(d.regressions("medium")), 1)      # the raw-IP link (medium); the low site finding is below the line
        self.assertEqual(len(d.regressions("low")), 2)


class InputAndDnsDiffs(unittest.TestCase):
    def form(self, action, method="post", names=("user",), **kw):
        return {"page": ROOT, "action": ROOT + action, "method": method, "enctype": "", "fields": [{"name": n, "type": "text", "required": False} for n in names],
                "password": False, "upload": False, "csrf": True, "search": False, "cross_origin": False, "id": "", **kw}

    def pair(self, old_site, new_site):
        old, _ = crawl()
        new, _ = crawl()
        old["site"].update(old_site)
        new["site"].update(new_site)
        return sections(sn.diff(old, new)), sn.diff(old, new)

    def test_new_and_removed_forms_and_parameters(self):
        s, d = self.pair({"forms": [self.form("login"), self.form("old")], "params": {"id": {"count": 3, "examples": []}, "gone": {"count": 1, "examples": []}}},
                         {"forms": [self.form("login"), self.form("upload", upload=True, password=False), self.form("pay", cross_origin=True)],
                          "params": {"id": {"count": 5, "examples": []}, "q": {"count": 2, "examples": []}}})
        new = {c.subject: c for c in s["input-new"]}
        self.assertEqual(set(new), {"POST " + ROOT + "upload", "POST " + ROOT + "pay", "?q"})
        self.assertEqual(new["POST " + ROOT + "upload"].severity, "low")
        self.assertIn("file upload", new["POST " + ROOT + "upload"].detail)
        self.assertEqual({c.subject for c in s["input-removed"]}, {"POST " + ROOT + "old", "?gone"})
        self.assertEqual(d.regressions("low"), [])                 # a new form is news, not a failure

    def test_a_reordered_form_is_the_same_form(self):
        s, _ = self.pair({"forms": [self.form("a", names=("x", "y"))], "params": {}}, {"forms": [self.form("a", names=("y", "x"))], "params": {}})
        self.assertNotIn("input-new", s)

    def test_sessions_from_before_inputs_were_collected_are_not_compared(self):
        old, _ = crawl()
        for k in ("forms", "params", "hosts", "dns"):
            old["site"].pop(k, None)
        new, _ = crawl()
        new["site"]["forms"] = [self.form("login")]
        new["site"]["params"] = {"id": {"count": 1, "examples": []}}
        new["site"]["hosts"] = {"api.example.com": {"sources": ["link"], "addresses": None}}
        s = sections(sn.diff(old, new))
        self.assertTrue({"input-new", "host-changed"}.isdisjoint(s))

    def test_subdomains(self):
        s, _ = self.pair({"hosts": {"old.example.com": {"sources": ["link"], "addresses": []}, "www.example.com": {"sources": ["link"], "addresses": None}}},
                         {"hosts": {"api.example.com": {"sources": ["csp"], "addresses": None}, "www.example.com": {"sources": ["link"], "addresses": None}}})
        self.assertEqual({(c.subject, c.detail) for c in s["host-changed"]}, {("api.example.com", "new subdomain referenced"), ("old.example.com", "no longer referenced")})

    def test_dns_record_changes(self):
        base = {"domain": "example.com", "ns": ["a.ns.net"], "mx": ["mx.example.com"], "spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject", "dnssec": True, "mta_sts": True, "caa": ["0 issue \"x\""]}
        s, d = self.pair({"dns": base}, {"dns": {**base, "ns": ["evil.ns.net"], "mx": ["mx.evil.net"], "spf": "v=spf1 +all", "dnssec": False, "mta_sts": False, "caa": []}})
        det = " | ".join(c.detail for c in s["dns-changed"])
        for needle in ("name servers: a.ns.net -> evil.ns.net", "mail servers: mx.example.com -> mx.evil.net", "SPF changed", "DNSSEC was turned off", "MTA-STS policy is gone", "CAA records changed"):
            self.assertIn(needle, det)
        self.assertEqual(len(d.regressions("medium")), 3)           # name servers, mail servers, DNSSEC
        same, _ = self.pair({"dns": base}, {"dns": dict(base)})
        self.assertNotIn("dns-changed", same)
        other, _ = self.pair({"dns": base}, {"dns": {**base, "domain": "other.org", "ns": []}})
        self.assertNotIn("dns-changed", other)                       # different domains are not compared


if __name__ == "__main__":
    unittest.main()
