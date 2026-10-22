import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import analysis as an  # noqa: E402
import report  # noqa: E402
import webcrawler as wc  # noqa: E402

PAGE = "https://example.com/"


class Report(unittest.TestCase):
    def build(self):
        s = wc.LinkStore()
        s.add({"href": "https://paypal.com@evil.test/x", "text": "<script>alert(1)</script>", "page": PAGE})
        s.add({"href": "/about", "text": "About", "page": PAGE})
        sec = an.PageSecurity(PAGE, 200, an.check_headers(PAGE, [("Content-Type", "text/html")])[0], {})
        return report.build_html(PAGE, s.all(), [sec])

    def test_sections_and_counts(self):
        h = self.build()
        for needle in ("WebCrawler report", "Risky links", "Page security headers", "All links", "user@host in the URL", "No Content-Security-Policy header"):
            self.assertIn(needle, h)

    def test_untrusted_text_is_escaped(self):
        h = self.build()
        self.assertNotIn("<script>alert(1)</script>", h)
        self.assertIn("&lt;script&gt;", h)

    def test_self_contained(self):
        h = self.build()
        self.assertNotRegex(h, r"<script|src=|href=")  # no scripts, no external files

    def test_empty_crawl(self):
        h = report.build_html(PAGE, [], [])
        self.assertIn("No link scored above informational", h)


class SiteAndDiffReports(unittest.TestCase):
    def site(self):
        import checks as ck
        si = ck.SiteInfo()
        si.add_tls({"host": "e.com", "ok": True, "verified": False, "verify_error": "self-signed <b>certificate</b>", "protocol": "TLSv1.3", "issuer": "Evil <i>CA</i>",
                    "days_left": 5, "not_after": "2026-10-26", "error": ""})
        si.add_tech([ck.Tech("PHP", "5.6", "X-Powered-By header", "language")], PAGE)
        si.add_probes([ck.ProbeResult("/.env", PAGE + ".env", ".env file is publicly readable", "high", True, 200)])
        si.set_seeds(ck.Seeds(["https://e.com/a"], ["https://e.com/sitemap.xml"], {"disallow": ["/admin/"]}, []), PAGE)
        return si.to_dict()

    def test_site_section_is_in_the_report_and_escaped(self):
        h = report.build_html(PAGE, [], [], None, None, self.site())
        for needle in ("Site-wide checks", "Technologies", "Well-known files", "PHP", "exposed", "Certificate expires in 5 day"):
            self.assertIn(needle, h)
        self.assertNotIn("<b>certificate</b>", h)
        self.assertNotIn("<i>CA</i>", h)
        self.assertNotRegex(h, r"<script|src=|href=")

    def test_inputs_and_dns_sections(self):
        import checks as ck
        import dnscheck
        si = ck.SiteInfo()
        si.add_forms(ck.extract_forms(PAGE, "<form method='post' action='/login'><input name='user'><input type='password' name='<b>pw</b>'></form><form action='/s'><input name='q'></form>"))
        si.add_params(PAGE + "p?id=1&<i>x</i>=2")
        si.add_host("api.e.com", "link", "e.com")
        rep = dnscheck.DnsReport("e.com", "https://doh.example/<b>", spf="v=spf1 +all <script>", dmarc="", queries=9)
        rep.findings.append(an.Finding("email-no-dmarc", "medium", "No DMARC record", "x"))
        si.add_dns(rep)
        h = report.build_html(PAGE, [], [], None, None, si.to_dict())
        for needle in ("Where the site accepts input", "Forms", "/login", "password", "Query parameters", "?id", "Subdomains the site refers to", "api.e.com",
                       "DNS and e-mail security: e.com", "No DMARC record", "Nothing was submitted"):
            self.assertIn(needle, h)
        self.assertNotIn("<b>pw</b>", h)
        self.assertNotIn("<script>", h)
        self.assertNotIn("<i>x</i>", h)
        self.assertNotIn("Where the site accepts input", report.build_html(PAGE, [], []))

    def test_report_without_site_data_still_builds(self):
        self.assertIn("No site-wide checks", report.build_html(PAGE, [], []))

    def test_diff_report(self):
        import snapshot as sn
        old = {"created": "2026-10-01T00:00:00Z", "start": PAGE, "links": [], "pages": [], "graph": {"nodes": [], "edges": []}, "site": {}}
        new = {"created": "2026-10-21T00:00:00Z", "start": PAGE, "links": [{"href": "https://bit.ly/<script>x</script>", "kind": "external", "page": PAGE, "text": "", "n": 1, "host": "bit.ly", "count": 1, "nofollow": False}],
               "pages": [], "graph": {"nodes": [], "edges": []}, "site": {}}
        d = sn.diff(old, new)
        h = report.build_diff_html(d)
        self.assertIn("What changed", h)
        self.assertIn("New problems (1)", h)
        self.assertNotIn("<script>x</script>", h)
        self.assertNotRegex(h, r"<script|src=|href=")
        self.assertIn("No differences", report.build_diff_html(sn.diff(old, old)))


if __name__ == "__main__":
    unittest.main()
