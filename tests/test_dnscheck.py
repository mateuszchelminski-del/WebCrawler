"""DNS and e-mail security records, read through a fake DNS-over-HTTPS resolver on localhost (no real DNS is touched)."""
import http.server
import json
import queue
import sys
import threading
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _net  # noqa: E402,F401  (a longer listen backlog for the local test servers)
import checks as ck  # noqa: E402
import dnscheck as dn  # noqa: E402
import frontier as fr  # noqa: E402
import httpclient  # noqa: E402
import httpscan  # noqa: E402
import graph as gr  # noqa: E402
import auth as auth_mod  # noqa: E402

TXT, MX, NS, CAA, DS = 16, 15, 2, 257, 43


def txt(*values):
    return [(TXT, '"' + v + '"') for v in values]


class FakeDoh(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, zone, fail=False, garbage=False):
        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                q = parse_qs(urlparse(self.path).query)
                name, rtype = q["name"][0].lower().rstrip("."), q["type"][0]
                self.server.asked.append((name, rtype))
                if self.server.fail:
                    body, status = b"upstream failure", 502
                elif self.server.garbage:
                    body, status = b"<html>not dns</html>", 200
                else:
                    rows = self.server.zone.get((name, rtype), [])
                    d = {"Status": 0, "AD": False, "Answer": [{"name": name, "type": t, "TTL": 60, "data": data} for t, data in rows]}
                    if not rows and not any(k[0] == name for k in self.server.zone):
                        d["Status"] = 3
                    body, status = json.dumps(d).encode(), 200
                self.send_response(status)
                self.send_header("Content-Type", "application/dns-json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        super().__init__(("127.0.0.1", 0), H)
        self.zone, self.fail, self.garbage, self.asked = zone, fail, garbage, []
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}/dns-query"

    def stop(self):
        self.shutdown()
        self.server_close()


def good_zone(d="example.com"):
    return {
        (d, "NS"): [(NS, "ns1.example.net."), (NS, "ns2.example.net.")],
        (d, "MX"): [(MX, "10 mail.example.com.")],
        (d, "TXT"): txt("v=spf1 ip4:203.0.113.5 -all", "google-site-verification=abc"),
        ("_dmarc." + d, "TXT"): txt("v=DMARC1; p=reject; rua=mailto:dmarc@example.com"),
        ("google._domainkey." + d, "TXT"): txt("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN"),
        ("_mta-sts." + d, "TXT"): txt("v=STSv1; id=1"),
        ("_smtp._tls." + d, "TXT"): txt("v=TLSRPTv1; rua=mailto:t@example.com"),
        (d, "CAA"): [(CAA, '0 issue "letsencrypt.org"')],
        (d, "DS"): [(DS, "12345 13 2 ABCDEF")],
    }


def run_check(zone, domain="example.com", **kw):
    srv = FakeDoh(zone, **kw)
    try:
        client = httpclient.Client("test", 5, True, max_idle=2, use_proxy=False)
        doh = dn.Doh(srv.url, client)
        rep = dn.check_domain(domain, doh)
        client.close()
        return rep, srv
    finally:
        srv.stop()


def codes(rep):
    return {f.code: f for f in rep.findings}


class Parsing(unittest.TestCase):
    def test_txt_answers_are_unquoted_and_joined(self):
        self.assertEqual(dn.unquote_txt('"v=spf1 include:a.example "'), "v=spf1 include:a.example ")
        self.assertEqual(dn.unquote_txt('"v=DKIM1; p=AAAA" "BBBB"'), "v=DKIM1; p=AAAABBBB")
        self.assertEqual(dn.unquote_txt(r'"say \"hi\""'), 'say "hi"')
        self.assertEqual(dn.unquote_txt("bare"), "bare")

    def test_spf_terms(self):
        p = dn.parse_spf("v=spf1 ip4:1.2.3.4 a mx include:_spf.google.com include:sendgrid.net exists:%{i}.x.org ptr -all")
        self.assertEqual(p["all"], "-all")
        self.assertEqual(p["includes"], ["_spf.google.com", "sendgrid.net"])
        self.assertEqual(len(p["lookups"]), 6)                     # a, mx, 2 includes, exists, ptr (ip4 costs nothing)
        self.assertTrue(p["ptr"])
        self.assertEqual(dn.parse_spf("v=spf1 redirect=_spf.example.com")["redirect"], "_spf.example.com")
        self.assertEqual(dn.parse_spf("v=spf1 +all")["all"], "+all")
        self.assertEqual(dn.parse_spf("v=spf1 ?all")["all"], "?all")

    def test_dmarc_tags(self):
        t = dn.parse_dmarc("v=DMARC1; p=quarantine; pct=50 ;rua=mailto:a@b.co; sp=none")
        self.assertEqual((t["p"], t["pct"], t["sp"], t["rua"]), ("quarantine", "50", "none", "mailto:a@b.co"))


class Checks(unittest.TestCase):
    def test_a_well_configured_domain_has_nothing_to_report(self):
        rep, srv = run_check(good_zone())
        self.assertEqual([f for f in rep.findings if f.severity != "info"], [])
        self.assertEqual(codes(rep), {})
        self.assertEqual((rep.spf_lookups, rep.dkim, rep.mta_sts, rep.tls_rpt, rep.dnssec), (0, ["google"], True, True, True))
        self.assertEqual(rep.ns, ["ns1.example.net", "ns2.example.net"])
        self.assertEqual(rep.mx, ["mail.example.com"])
        self.assertEqual(rep.caa, ['0 issue "letsencrypt.org"'])
        self.assertEqual(rep.errors, [])
        self.assertGreater(rep.queries, 5)

    def test_a_mail_domain_with_nothing_published(self):
        z = {("example.com", "NS"): [(NS, "ns.x.net.")], ("example.com", "MX"): [(MX, "5 mx.example.com.")]}
        rep, _ = run_check(z)
        c = codes(rep)
        self.assertEqual(c["email-no-spf"].severity, "medium")
        self.assertEqual(c["email-no-dmarc"].severity, "medium")
        self.assertIn("email-no-dkim-found", c)
        self.assertIn("email-no-mta-sts", c)
        self.assertIn("dns-no-caa", c)
        self.assertIn("dns-no-dnssec", c)

    def test_a_domain_that_handles_no_mail_is_asked_for_less(self):
        z = {("example.com", "NS"): [(NS, "ns.x.net.")], ("example.com", "MX"): [(MX, "0 .")]}
        rep, srv = run_check(z)
        c = codes(rep)
        self.assertEqual((c["email-no-spf"].severity, c["email-no-dmarc"].severity), ("low", "low"))
        self.assertNotIn("email-no-mta-sts", c)
        self.assertFalse([a for a in srv.asked if "_domainkey" in a[0]])    # no point guessing DKIM selectors for a domain without mail

    def test_spf_problems(self):
        base = {("example.com", "NS"): [(NS, "ns.x.net.")], ("example.com", "MX"): [(MX, "5 mx.example.com.")]}
        for spf, code, sev in (("v=spf1 +all", "email-spf-permissive", "high"), ("v=spf1 ip4:1.2.3.4 ?all", "email-spf-permissive", "medium"),
                               ("v=spf1 ip4:1.2.3.4", "email-spf-permissive", "medium"), ("v=spf1 ptr -all", "email-spf-ptr", "low"),
                               ("v=spf1 ip4:1.2.3.4 ~all", "email-spf-softfail", "info")):
            rep, _ = run_check({**base, ("example.com", "TXT"): txt(spf)})
            self.assertEqual(codes(rep)[code].severity, sev, spf)
        rep, _ = run_check({**base, ("example.com", "TXT"): txt("v=spf1 -all", "v=spf1 ip4:1.2.3.4 -all")})
        self.assertIn("email-spf-multiple", codes(rep))
        rep, _ = run_check({**base, ("example.com", "TXT"): txt("v=spf1 redirect=_spf.example.net")})
        self.assertNotIn("email-spf-permissive", codes(rep))                 # the policy lives at the redirect target

    def test_spf_lookup_limit_follows_includes(self):
        z = {("example.com", "NS"): [(NS, "ns.x.net.")], ("example.com", "MX"): [(MX, "5 mx.example.com.")],
             ("example.com", "TXT"): txt("v=spf1 include:a.example.net include:b.example.net a mx -all"),
             ("a.example.net", "TXT"): txt("v=spf1 include:c.example.net a a a -all"),
             ("b.example.net", "TXT"): txt("v=spf1 a:x.example.org a:y.example.org a:z.example.org mx -all"),
             ("c.example.net", "TXT"): txt("v=spf1 a mx -all")}
        rep, _ = run_check(z)
        self.assertEqual(rep.spf_lookups, 2 + 2 + 4 + 2 + 4)               # top: 2 includes + a + mx; a: include + 3 a; c: a, mx; b: 3 a: + mx
        self.assertIn("email-spf-lookups", codes(rep))
        z[("example.com", "TXT")] = txt("v=spf1 include:c.example.net -all")
        rep, _ = run_check(z)
        self.assertEqual(rep.spf_lookups, 3)
        self.assertNotIn("email-spf-lookups", codes(rep))

    def test_spf_include_loops_terminate(self):
        z = {("example.com", "NS"): [(NS, "ns.x.net.")], ("example.com", "TXT"): txt("v=spf1 include:a.example.net -all"),
             ("a.example.net", "TXT"): txt("v=spf1 include:a.example.net -all")}
        rep, srv = run_check(z)
        self.assertLess(len(srv.asked), 40)

    def test_dmarc_problems(self):
        base = good_zone()
        for record, code, sev in (("v=DMARC1; p=none; rua=mailto:a@b.co", "email-dmarc-none", "low"), ("v=DMARC1; p=bogus", "email-dmarc-invalid", "medium"),
                                  ("v=DMARC1; p=reject; pct=25; rua=mailto:a@b.co", "email-dmarc-partial", "low"),
                                  ("v=DMARC1; p=reject; sp=none; rua=mailto:a@b.co", "email-dmarc-subdomains", "low"), ("v=DMARC1; p=reject", "email-dmarc-no-rua", "info")):
            rep, _ = run_check({**base, ("_dmarc.example.com", "TXT"): txt(record)})
            self.assertEqual(codes(rep)[code].severity, sev, record)

    def test_dmarc_only_counts_records_that_say_so(self):
        rep, _ = run_check({**good_zone(), ("_dmarc.example.com", "TXT"): txt("some verification token")})
        self.assertIn("email-no-dmarc", codes(rep))

    def test_the_registrable_domain_is_what_is_checked(self):
        srv = FakeDoh(good_zone("example.co.uk"))
        client = httpclient.Client("t", 5, True, use_proxy=False)
        try:
            rep = dn.run("www.shop.example.co.uk", srv.url, client)
        finally:
            client.close()
            srv.stop()
        self.assertEqual(rep.domain, "example.co.uk")
        self.assertEqual(codes(rep), {})


class Failures(unittest.TestCase):
    def test_a_resolver_that_errors_is_reported_not_raised(self):
        rep, _ = run_check(good_zone(), fail=True)
        self.assertEqual(rep.findings, [])                              # no findings invented from silence
        self.assertTrue(rep.errors and "502" in rep.errors[0])

    def test_a_resolver_that_does_not_speak_json(self):
        rep, _ = run_check(good_zone(), garbage=True)
        self.assertEqual(rep.findings, [])
        self.assertTrue(rep.errors)

    def test_an_unreachable_resolver(self):
        client = httpclient.Client("t", 2, True, use_proxy=False)
        rep = dn.check_domain("example.com", dn.Doh("http://127.0.0.1:9/dns-query", client))
        client.close()
        self.assertEqual(rep.findings, [])
        self.assertTrue(rep.errors)

    def test_private_hosts_never_leave_the_machine(self):
        srv = FakeDoh(good_zone())
        try:
            for h in ("localhost", "127.0.0.1", "10.1.2.3", "intranet", "printer.local", "[::1]", ""):
                self.assertIsNone(dn.run(h, srv.url), h)
            self.assertEqual(srv.asked, [])
        finally:
            srv.stop()


class InTheCrawl(unittest.TestCase):
    def discover(self, start, **kw):
        srv = FakeDoh(kw.pop("zone", good_zone("example.com")))
        events = queue.Queue()
        opts = fr.CrawlOptions(check_tls=False, use_sitemap=False, check_dns=True, doh_url=srv.url, **kw).clamped()
        info = ck.SiteInfo()
        try:
            httpscan.run_discovery(start, opts, auth_mod.AuthConfig(), fr.Pacer(opts), threading.Event(), info, gr.SiteGraph(),
                                   lambda *a: events.put(a))
        finally:
            srv.stop()
        msgs = []
        while not events.empty():
            msgs.append(events.get())
        return info, srv, msgs

    def test_it_is_off_unless_asked_for(self):
        self.assertFalse(fr.CrawlOptions().check_dns)
        srv = FakeDoh(good_zone())
        try:
            opts = fr.CrawlOptions(check_tls=False, use_sitemap=False, doh_url=srv.url).clamped()
            info = ck.SiteInfo()
            httpscan.run_discovery("https://www.example.com/", opts, auth_mod.AuthConfig(), fr.Pacer(opts), threading.Event(), info, gr.SiteGraph(), lambda *a: None)
            self.assertEqual((srv.asked, info.dns), ([], {}))
        finally:
            srv.stop()

    def test_records_and_findings_land_in_site_info_and_survive_a_save(self):
        z = good_zone("example.com")
        z[("_dmarc.example.com", "TXT")] = txt("v=DMARC1; p=none")
        info, srv, _ = self.discover("https://www.example.com/", zone=z)
        self.assertEqual(info.dns["domain"], "example.com")
        self.assertIn(("email-dmarc-none", "example.com"), [(f.code, w) for f, w in info.findings])
        again = ck.SiteInfo.from_dict(json.loads(json.dumps(info.to_dict())))
        self.assertEqual(again.dns["dmarc"], "v=DMARC1; p=none")
        self.assertEqual(len(again.findings), len(info.findings))

    def test_a_local_site_asks_nothing(self):
        info, srv, msgs = self.discover("http://127.0.0.1:8000/")
        self.assertEqual((srv.asked, info.dns), ([], {}))
        self.assertTrue(any("not a public host" in str(m) for m in msgs))


class CertificateLogs(unittest.TestCase):
    ROWS = [{"name_value": "example.com\nwww.example.com"}, {"name_value": "*.example.com"}, {"name_value": "api.example.com\nstaging.example.com"},
            {"name_value": "mail.example.org"}, {"name_value": "notexample.com"}, {"name_value": "deep.sub.example.com."}, {"name_value": "bad name.example.com"}, "junk"]

    def serve(self, body, status=200):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.server.asked.append(self.path)
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        srv.asked = []
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close()))
        return srv, f"http://127.0.0.1:{srv.server_address[1]}/ct?q=%25.{{domain}}"

    def test_names_are_collected_cleaned_and_limited_to_the_domain(self):
        srv, url = self.serve(self.ROWS)
        names, err = dn.ct_subdomains("example.com", url)
        self.assertEqual(err, "")
        self.assertEqual(names, ["api.example.com", "deep.sub.example.com", "example.com", "staging.example.com", "www.example.com"])
        self.assertEqual(srv.asked, ["/ct?q=%25.example.com"])

    def test_failures_come_back_as_errors(self):
        for body, status in ((b"<html>busy</html>", 200), (b"overloaded", 503)):
            srv, url = self.serve(body, status)
            names, err = dn.ct_subdomains("example.com", url)
            self.assertEqual((names, bool(err)), ([], True))

    def test_private_names_are_never_sent(self):
        srv, url = self.serve(self.ROWS)
        self.assertEqual(dn.ct_subdomains("localhost", url), ([], ""))
        self.assertEqual(dn.ct_subdomains("intranet.local", url), ([], ""))
        self.assertEqual(srv.asked, [])

    def test_it_is_part_of_discovery_only_when_asked_and_unresolved_log_names_are_not_findings(self):
        srv, url = self.serve(self.ROWS)
        opts = fr.CrawlOptions(check_tls=False, use_sitemap=False, ct_url=url).clamped()
        info = ck.SiteInfo()
        httpscan.run_discovery("https://www.example.com/", opts, auth_mod.AuthConfig(), fr.Pacer(opts), threading.Event(), info, gr.SiteGraph(), lambda *a: None)
        self.assertEqual((srv.asked, info.hosts), ([], {}))                                    # off by default
        opts = fr.CrawlOptions(check_tls=False, use_sitemap=False, check_ct=True, ct_url=url).clamped()
        httpscan.run_discovery("https://www.example.com/", opts, auth_mod.AuthConfig(), fr.Pacer(opts), threading.Event(), info, gr.SiteGraph(), lambda *a: None)
        self.assertEqual(len(srv.asked), 1)
        self.assertEqual(set(info.hosts), {"api.example.com", "deep.sub.example.com", "example.com", "staging.example.com", "www.example.com"})
        self.assertEqual(info.hosts["api.example.com"]["sources"], ["certificate-log"])
        from unittest import mock
        with mock.patch.object(ck, "resolve_hosts", return_value={h: [] for h in info.hosts}):
            info.resolve_hosts()
        self.assertEqual([f for f, _ in info.findings if f.code == "host-unresolved"], [])
        info.add_host("api.example.com", "link", "example.com")                                # but a page that links to it makes it the site's own reference
        info.hosts["api.example.com"]["addresses"] = None
        with mock.patch.object(ck, "resolve_hosts", return_value={"api.example.com": []}):
            info.resolve_hosts()
        self.assertEqual([w for f, w in info.findings if f.code == "host-unresolved"], ["api.example.com"])


class Cli(unittest.TestCase):
    def test_flags(self):
        import webcrawler as wc
        p = wc.build_parser()
        a = p.parse_args(["https://example.com", "--dns"])
        self.assertTrue(wc.build_options(a).check_dns)
        self.assertTrue(wc.build_options(p.parse_args(["https://example.com", "--subdomains"])).check_ct)
        o = wc.build_options(p.parse_args(["https://example.com", "--ct-url", "https://ct.example.net/?q={domain}"]))
        self.assertEqual((o.check_ct, o.ct_url), (True, "https://ct.example.net/?q={domain}"))
        self.assertFalse(wc.build_options(p.parse_args(["https://example.com"])).check_ct)
        a = p.parse_args(["https://example.com", "--doh", "https://dns.example.net/dns-query"])
        o = wc.build_options(a)
        self.assertEqual((o.check_dns, o.doh_url), (True, "https://dns.example.net/dns-query"))
        self.assertFalse(wc.build_options(p.parse_args(["https://example.com"])).check_dns)


if __name__ == "__main__":
    unittest.main()
