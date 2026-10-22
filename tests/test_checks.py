import gzip
import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import checks as ck  # noqa: E402
from analysis import Finding  # noqa: E402

HTTPS = "https://example.com/page"
HTTP = "http://example.com/page"


def codes(fs):
    return {f.code for f in fs}


class HtmlAnalysis(unittest.TestCase):
    def test_third_party_scripts_need_sri(self):
        h = ('<script src="https://cdn.other.com/a.js"></script>'
             '<script src="https://cdn.other.com/b.js" integrity="sha384-x" crossorigin></script>'
             '<script src="/local.js"></script><script src="//cdn.third.com/c.js"></script>'
             '<link rel="stylesheet" href="https://fonts.other.com/s.css">')
        f = ck.analyze_html(HTTPS, h)
        det = {x.detail for x in f if x.code == "no-sri-script"}
        self.assertEqual(det, {"cdn.other.com/a.js", "cdn.third.com/c.js"})
        self.assertIn("no-sri-style", codes(f))

    def test_mixed_content_only_on_https_pages(self):
        h = '<script src="http://x.com/a.js"></script><img src="http://x.com/i.png"><iframe src="http://x.com/f"></iframe>'
        f = ck.analyze_html(HTTPS, h)
        self.assertEqual([x.severity for x in f if x.code == "mixed-active"], ["high", "high"])
        self.assertIn("mixed-passive", codes(f))
        self.assertFalse({"mixed-active", "mixed-passive"} & codes(ck.analyze_html(HTTP, h)))

    def test_forms(self):
        self.assertIn("password-over-http", codes(ck.analyze_html(HTTP, '<form method="post"><input type="password"></form>')))
        self.assertIn("password-in-url", codes(ck.analyze_html(HTTPS, '<form><input type="password"></form>')))
        self.assertIn("form-http", codes(ck.analyze_html(HTTPS, '<form method="post" action="http://example.com/login"><input type="password"></form>')))
        self.assertIn("form-http", codes(ck.analyze_html(HTTPS, '<form method="post" action="http://example.com/s"><input name="q"></form>')))
        self.assertIn("login-cross-origin", codes(ck.analyze_html(HTTPS, '<form method="post" action="https://sso.other.org/in"><input type="password"></form>')))
        self.assertEqual(codes(ck.analyze_html(HTTPS, '<form method="post" action="/login"><input type="password"><input type="submit"></form>')), {"form-no-csrf"})
        self.assertEqual(ck.analyze_html(HTTPS, '<form method="post" action="/login"><input type="hidden" name="csrf_token" value="x"><input type="password"></form>'), [])
        self.assertEqual(ck.analyze_html(HTTPS, '<meta name="csrf-token" content="abc"><form method="post" action="/s"><input name="q"></form>'), [])

    def test_secrets_are_found_and_redacted(self):
        key = "AKIA" + "ABCDEFGHIJKLMNOP"
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"
        f = ck.analyze_html(HTTPS, f"<script>var k='{key}'; var t='{jwt}';</script><!-- password = hunter2 -->")
        self.assertTrue({"exposed-secret", "comment-secret"} <= codes(f))
        self.assertTrue(all(key not in x.detail and jwt not in x.detail and "hunter2" not in x.detail for x in f))  # never echo the secret
        self.assertTrue(any(x.severity == "high" and "AWS" in x.title for x in f))

    def test_tabnabbing_is_info_and_noopener_clears_it(self):
        self.assertEqual([x.severity for x in ck.analyze_html(HTTPS, '<a href="https://o.org" target="_blank">x</a>')], ["info"])
        self.assertEqual(ck.analyze_html(HTTPS, '<a href="https://o.org" target="_blank" rel="noopener">x</a>'), [])

    def test_broken_or_empty_markup(self):
        self.assertEqual(ck.analyze_html(HTTPS, ""), [])
        ck.analyze_html(HTTPS, "<form><<<script src=><a href")  # must not raise


class Fingerprints(unittest.TestCase):
    def test_headers_and_cookies(self):
        t = ck.fingerprint([("Server", "Apache/2.4.49 (Unix)"), ("X-Powered-By", "PHP/7.4.3"), ("Set-Cookie", "PHPSESSID=abc; Path=/"), ("CF-Ray", "1")])
        names = {(x.name, x.version) for x in t}
        self.assertTrue({("Apache", "2.4.49"), ("PHP", "7.4.3"), ("PHP", ""), ("Cloudflare", "")} <= names)
        c = codes(ck.tech_findings(t))
        self.assertTrue({"apache-path-traversal", "eol-php"} <= c)

    def test_markup(self):
        html = ('<meta name="generator" content="WordPress 6.2.1"><script src="/js/jquery-3.4.1.min.js"></script>'
                '<link href="/css/bootstrap-3.3.7.css"><script src="angular.min.js?v=1.8.2"></script><link href="/wp-content/themes/x.css">')
        t = ck.fingerprint([], html)
        self.assertTrue({("WordPress", "6.2.1"), ("jQuery", "3.4.1"), ("Bootstrap", "3.3.7")} <= {(x.name, x.version) for x in t})
        c = codes(ck.tech_findings(t))
        self.assertTrue({"old-jquery", "old-bootstrap"} <= c)

    def test_modern_versions_are_not_flagged(self):
        t = ck.fingerprint([("X-Powered-By", "PHP/8.3.1"), ("Server", "nginx/1.25.3")], '<script src="jquery-3.7.1.min.js"></script><link href="bootstrap@5.3.2/x.css">')
        self.assertEqual(ck.tech_findings(t), [])

    def test_version_comparison_is_numeric(self):
        self.assertEqual(ck._ver("3.5"), ck._ver("3.5.0"))
        self.assertLess(ck._ver("3.10.0"), (3, 10, 1))
        self.assertGreater(ck._ver("3.10.0"), ck._ver("3.9.9"))
        self.assertEqual(codes(ck.tech_findings([ck.Tech("jQuery", "3.5.0")])), set())
        self.assertEqual(codes(ck.tech_findings([ck.Tech("jQuery", "3.4.9")])), {"old-jquery"})

    def test_empty(self):
        self.assertEqual(ck.fingerprint([], ""), [])


def make_cert(d):
    openssl = shutil.which("openssl")
    if not openssl:
        return None
    crt, key = os.path.join(d, "c.crt"), os.path.join(d, "c.key")
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    r = subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "3", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], capture_output=True, env=env)
    return (crt, key) if r.returncode == 0 else None


class Tls(unittest.TestCase):
    def test_findings_from_described_certificates(self):
        base = {"host": "h", "ok": True, "verified": True, "protocol": "TLSv1.3", "days_left": 200, "not_after": "2027-05-01", "verify_error": "", "error": ""}
        self.assertEqual(ck.tls_findings(base), [])
        self.assertEqual(codes(ck.tls_findings({**base, "days_left": -3})), {"tls-expired"})
        f = ck.tls_findings({**base, "days_left": 9})
        self.assertEqual((f[0].code, f[0].severity), ("tls-expiring", "high"))
        self.assertEqual(ck.tls_findings({**base, "days_left": 20})[0].severity, "medium")
        self.assertEqual(codes(ck.tls_findings({**base, "protocol": "TLSv1"})), {"tls-old-protocol"})
        f = ck.tls_findings({**base, "verified": False, "days_left": None, "verify_error": "certificate has expired"})
        self.assertEqual((f[0].code, f[0].title), ("tls-invalid", "Certificate has expired"))
        self.assertIn("self-signed", ck.tls_findings({**base, "verify_error": "self-signed certificate"})[0].title)
        self.assertIn("does not match", ck.tls_findings({**base, "verify_error": "Hostname mismatch, certificate is not valid for 'h'."})[0].title)
        self.assertEqual(ck.tls_findings({"host": "h", "ok": False, "error": "refused"})[0].severity, "info")

    def test_unreachable_host_does_not_raise(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        info = ck.tls_info("127.0.0.1", port, timeout=2)
        self.assertFalse(info["ok"])
        self.assertTrue(info["error"])

    def test_live_self_signed_server_is_reported_as_untrusted(self):
        d = tempfile.mkdtemp()
        pair = make_cert(d)
        if not pair:
            self.skipTest("openssl is not available to make a test certificate")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*pair)
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        port = srv.getsockname()[1]
        stop = threading.Event()

        def serve():
            srv.settimeout(0.3)
            while not stop.is_set():
                try:
                    c, _ = srv.accept()
                except OSError:
                    continue
                try:
                    with ctx.wrap_socket(c, server_side=True):
                        pass
                except (ssl.SSLError, OSError):
                    pass
        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            info = ck.tls_info("127.0.0.1", port, timeout=5)
        finally:
            stop.set()
            t.join(2)
            srv.close()
        self.assertTrue(info["ok"])
        self.assertFalse(info["verified"])
        self.assertTrue(info["verify_error"])
        self.assertIn(info["protocol"], ("TLSv1.2", "TLSv1.3"))
        self.assertIn("tls-invalid", codes(ck.tls_findings(info)))


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "certs"


def pem_to_der(name):
    return ssl.PEM_cert_to_DER_cert((FIXTURES / name).read_text())


class CertParsing(unittest.TestCase):
    """Public leaf certificates from badssl.com (a site that exists to test TLS clients) and ones made locally with openssl."""

    def test_expired_certificate(self):
        c = ck.parse_cert(pem_to_der("expired.badssl.com.pem"))
        self.assertEqual((c["subject"], c["issuer"], c["not_after"], c["not_before"]), ("*.badssl.com", "COMODO CA Limited", "2015-04-12", "2015-04-09"))
        self.assertLess(c["days_left"], 0)
        self.assertEqual((c["key_type"], c["key_bits"], c["sig_alg"], c["self_signed"]), ("RSA", 2048, "sha256WithRSA", False))
        self.assertIn("*.badssl.com", c["san"])
        self.assertEqual(c["valid_days"], 3)

    def test_self_signed_certificate(self):
        c = ck.parse_cert(pem_to_der("self-signed.badssl.com.pem"))
        self.assertTrue(c["self_signed"])
        self.assertEqual(c["issuer"], "BadSSL")

    def test_key_types_and_sizes(self):
        self.assertEqual(ck.parse_cert(pem_to_der("rsa8192.badssl.com.pem"))["key_bits"], 8192)
        e = ck.parse_cert(pem_to_der("ecc256.badssl.com.pem"))
        self.assertEqual((e["key_type"], e["key_bits"]), ("EC", 256))
        self.assertTrue(e["sig_alg"].startswith("ecdsa-with-SHA"))

    def test_unreadable_input_returns_nothing_instead_of_raising(self):
        der = pem_to_der("expired.badssl.com.pem")
        for bad in (b"", b"\x00", b"not a certificate", der[:50], der[:-100], der[:300] + b"\xff" * 50, bytes(range(256)) * 4):
            self.assertEqual(ck.parse_cert(bad), {}, bad[:10])

    def test_locally_made_certificates(self):
        openssl = shutil.which("openssl")
        if not openssl:
            self.skipTest("openssl is not available")
        d = tempfile.mkdtemp()
        env = dict(os.environ, MSYS_NO_PATHCONV="1")

        def make(name, *args):
            crt = os.path.join(d, name + ".crt")
            r = subprocess.run([openssl, "req", "-x509", "-nodes", "-keyout", os.path.join(d, name + ".key"), "-out", crt, "-days", "10", "-subj", "/CN=weak.test/O=Test Org",
                                *args], capture_output=True, env=env)
            if r.returncode != 0:
                return None
            with open(crt) as fh:
                return ck.parse_cert(ssl.PEM_cert_to_DER_cert(fh.read()))
        rsa1024 = make("rsa1024", "-newkey", "rsa:1024")
        if rsa1024:
            self.assertEqual((rsa1024["key_bits"], rsa1024["subject"], rsa1024["issuer"], rsa1024["self_signed"]), (1024, "weak.test", "Test Org", True))
            self.assertTrue(9 <= rsa1024["days_left"] <= 10)
            f = ck.tls_findings({"host": "weak.test", "ok": True, "key_type": "RSA", "key_bits": 1024, "days_left": 10})
            self.assertEqual([(x.code, x.severity) for x in f if x.code == "tls-weak-key"], [("tls-weak-key", "medium")])
        sha1 = make("sha1", "-newkey", "rsa:2048", "-sha1")
        if sha1:
            self.assertEqual(sha1["sig_alg"], "sha1WithRSA")
            self.assertIn("tls-weak-signature", codes(ck.tls_findings({"host": "h", "ok": True, "sig_alg": "sha1WithRSA", "days_left": 100})))
        ec = make("ec", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1")
        if ec:
            self.assertEqual((ec["key_type"], ec["key_bits"]), ("EC", 256))
        if not (rsa1024 or sha1 or ec):
            self.skipTest("this openssl could not make the test certificates")


class TlsWording(unittest.TestCase):
    base = {"host": "h", "ok": True, "verified": False, "protocol": "TLSv1.2", "days_left": 100, "not_after": "2027-01-01", "error": ""}

    def title(self, **kw):
        return {f.code: f.title for f in ck.tls_findings({**self.base, **kw})}

    def test_each_failure_has_its_own_explanation(self):
        self.assertEqual(self.title(verify_error="self signed certificate")["tls-invalid"], "Certificate is self-signed")
        self.assertEqual(self.title(verify_error="self signed certificate in certificate chain")["tls-invalid"], "Certificate chain ends in an untrusted root")
        self.assertEqual(self.title(verify_error="unable to get local issuer certificate")["tls-invalid"], "Certificate chain is incomplete or from an unknown authority")
        self.assertEqual(self.title(verify_error="Hostname mismatch, certificate is not valid for 'h'.")["tls-invalid"], "Certificate does not match the host name")
        self.assertEqual(self.title(verify_error="something odd")["tls-invalid"], "Certificate failed verification")
        f = {x.code: x for x in ck.tls_findings({**self.base, "verify_error": "unable to get local issuer certificate"})}
        self.assertIn("intermediate certificates", f["tls-invalid"].detail)

    def test_an_expired_certificate_is_reported_once_with_its_date(self):
        f = ck.tls_findings({**self.base, "verify_error": "certificate has expired", "days_left": -40, "not_after": "2026-09-11"})
        self.assertEqual([x.code for x in f], ["tls-invalid"])
        self.assertIn("40 day(s) ago, on 2026-09-11", f[0].detail)

    def test_obsolete_protocol_severity(self):
        f = {x.code: x for x in ck.tls_findings({**self.base, "legacy": ["TLSv1", "TLSv1.1"]})}
        self.assertEqual((f["tls-old-protocol"].severity, f["tls-old-protocol"].title), ("medium", "Server accepts obsolete TLSv1 and TLSv1.1"))   # TLS 1.2 is offered too
        f = {x.code: x for x in ck.tls_findings({**self.base, "protocol": "TLSv1", "legacy": ["TLSv1"]})}
        self.assertEqual(f["tls-old-protocol"].severity, "high")                                                       # nothing newer on offer
        self.assertIn("nothing newer", f["tls-old-protocol"].detail)
        self.assertEqual(ck.tls_findings({**self.base, "legacy": []}), [])

    def test_an_unreachable_port_is_only_information(self):
        f = ck.tls_findings({"host": "h", "ok": False, "error": "refused"})
        self.assertEqual([(x.code, x.severity) for x in f], [("tls-unreachable", "info")])


class LegacyServer(unittest.TestCase):
    def test_a_server_that_only_speaks_tls_1_0_is_detected(self):
        d = tempfile.mkdtemp()
        pair = make_cert(d)
        if not pair:
            self.skipTest("openssl is not available to make a test certificate")
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            ctx.load_cert_chain(*pair)
        except (ssl.SSLError, ValueError):
            self.skipTest("this machine's TLS library cannot speak TLS 1.0")
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        port = srv.getsockname()[1]
        stop = threading.Event()

        def serve():
            srv.settimeout(0.3)
            while not stop.is_set():
                try:
                    c, _ = srv.accept()
                except OSError:
                    continue
                try:
                    with ctx.wrap_socket(c, server_side=True):
                        pass
                except (ssl.SSLError, OSError):
                    pass
        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            info = ck.tls_info("127.0.0.1", port, timeout=5)
        finally:
            stop.set()
            t.join(2)
            srv.close()
        if not info["ok"]:
            self.skipTest("the local client could not complete a TLS 1.0 handshake either")
        self.assertEqual((info["protocol"], info["legacy"]), ("TLSv1", ["TLSv1"]))
        self.assertTrue(info.get("unverified") or info.get("verify_error"))     # the certificate is not trusted either way
        self.assertEqual(info["subject"], "localhost")                       # the certificate is still read
        f = [x for x in ck.tls_findings(info) if x.code == "tls-old-protocol"]
        self.assertEqual(f[0].severity, "high")


class FormsAndInputs(unittest.TestCase):
    PAGE = "https://example.com/account/"

    def test_forms_are_inventoried_with_what_they_ask_for(self):
        html = ("<form id='login' method='POST' action='/login'><input name='user' autocomplete='off'><input type='password' name='pw' required>"
                "<input type='hidden' name='authenticity_token' value='x'><input type='submit'></form>"
                "<form action='/search' role='search'><input name='q'></form>"
                "<form method='post' action='/upload' enctype='multipart/form-data'><input type='file' name='doc'><textarea name='note'></textarea><select name='kind'></select></form>"
                "<form method='post' action='https://pay.other.org/charge'><input name='amount'></form><form><input name='x'></form>")
        f = {x.action: x for x in ck.extract_forms(self.PAGE, html)}
        login = f["https://example.com/login"]
        self.assertEqual((login.method, login.password, login.csrf, login.search, login.upload, login.cross_origin, login.id), ("post", True, True, False, False, False, "login"))
        self.assertEqual([(x["name"], x["type"], x["required"]) for x in login.fields][:2], [("user", "text", False), ("pw", "password", True)])
        self.assertTrue(f["https://example.com/search"].search)
        up = f["https://example.com/upload"]
        self.assertEqual((up.upload, up.csrf, [x["type"] for x in up.fields]), (True, False, ["file", "textarea", "select"]))
        self.assertTrue(f["https://pay.other.org/charge"].cross_origin)
        self.assertEqual(f[self.PAGE].method, "get")                                # no action: submits to the page itself; no method: GET

    def test_pages_without_forms_cost_nothing(self):
        self.assertEqual(ck.extract_forms(self.PAGE, "<p>no forms</p>"), [])
        self.assertEqual(ck.extract_forms(self.PAGE, ""), [])
        ck.extract_forms(self.PAGE, "<form><<<input name=")                          # broken markup does not raise

    def test_upload_and_csrf_findings(self):
        c = {f.code: f for f in ck.analyze_html(self.PAGE, "<form method='post' action='/u' enctype='multipart/form-data'><input type='file' name='f'></form>")}
        self.assertEqual((c["form-upload"].severity, c["form-no-csrf"].severity), ("info", "low"))
        self.assertEqual(ck.analyze_html(self.PAGE, "<form action='/s'><input name='q'></form>"), [])        # a search form needs no token
        self.assertEqual(ck.analyze_html(self.PAGE, "<form method='post' action='/x'><input type='hidden' name='a'><input type='submit'></form>"), [])   # nothing to forge

    def test_forms_are_deduplicated_across_pages_and_survive_a_round_trip(self):
        si = ck.SiteInfo()
        one = ck.extract_forms(self.PAGE, "<form method='post' action='/login'><input name='user'><input type='password' name='pw'></form>")
        si.add_forms(one)
        si.add_forms(ck.extract_forms("https://example.com/other/", "<form method='post' action='/login'><input name='pw'><input name='user'></form>"))   # the same form
        self.assertEqual(len(si.forms), 1)
        again = ck.SiteInfo.from_dict(json.loads(json.dumps(si.to_dict())))
        self.assertEqual(list(again.forms.values())[0]["action"], "https://example.com/login")
        v = si.version
        si.add_forms(one)
        self.assertEqual(si.version, v)


class Hosts(unittest.TestCase):
    def test_registrable_domains(self):
        for host, want in (("www.example.com", "example.com"), ("a.b.example.com", "example.com"), ("example.com", "example.com"), ("shop.example.co.uk", "example.co.uk"),
                           ("example.co.uk", "example.co.uk"), ("a.example.com.au", "example.com.au"), ("localhost", "localhost"), ("", ""), ("EXAMPLE.com.", "example.com")):
            self.assertEqual(ck.registrable(host), want, host)

    def test_related_hosts(self):
        self.assertTrue(ck.related("api.example.com", "www.example.com"))
        self.assertFalse(ck.related("example.org", "example.com"))
        self.assertFalse(ck.related("notexample.com", "example.com"))
        self.assertFalse(ck.related("", "example.com"))

    def test_only_public_names_are_looked_up(self):
        for h in ("example.com", "api.example.co.uk"):
            self.assertTrue(ck.is_public_host(h), h)
        for h in ("localhost", "intranet", "10.0.0.5", "192.168.1.1", "::1", "printer.local", "server.corp", "db.internal", "x.test", ""):
            self.assertFalse(ck.is_public_host(h), h)

    def test_hosts_named_in_a_policy_header(self):
        v = "default-src 'self' https://cdn.example.com; img-src *.images.example.com data:; connect-src https://api.example.com:8443/ wss://ws.example.com"
        self.assertEqual(set(ck.hosts_in_policy(v)), {"cdn.example.com", "images.example.com", "api.example.com", "ws.example.com"})

    def test_site_info_keeps_only_related_hosts_and_flags_dead_ones(self):
        si = ck.SiteInfo()
        for h, src in (("api.example.com", "link"), ("api.example.com", "csp"), ("old-shop.example.com", "link"), ("cdn.other.net", "link"), ("www.example.com", "certificate")):
            si.add_host(h, src, "example.com")
        self.assertEqual(set(si.hosts), {"api.example.com", "old-shop.example.com", "www.example.com"})
        self.assertEqual(si.hosts["api.example.com"]["sources"], ["link", "csp"])
        with mock.patch.object(ck, "resolve_hosts", return_value={"api.example.com": ["93.184.216.34"], "old-shop.example.com": [], "www.example.com": ["93.184.216.34"]}):
            si.resolve_hosts()
        self.assertEqual(si.hosts["api.example.com"]["addresses"], ["93.184.216.34"])
        f = [(f.code, w) for f, w in si.findings]
        self.assertEqual(f, [("host-unresolved", "old-shop.example.com")])
        again = ck.SiteInfo.from_dict(json.loads(json.dumps(si.to_dict())))
        self.assertEqual(again.hosts["old-shop.example.com"]["addresses"], [])

    def test_certificate_names_become_hosts(self):
        si = ck.SiteInfo()
        si.add_tls({"host": "example.com", "ok": True, "verified": True, "days_left": 100, "san": ["example.com", "www.example.com", "*.example.com", "api.example.com"],
                    "protocol": "TLSv1.3", "verify_error": "", "error": ""})
        self.assertEqual(set(si.hosts), {"example.com", "www.example.com", "api.example.com"})
        self.assertEqual(si.hosts["api.example.com"]["sources"], ["certificate"])

    def test_resolution_with_the_real_resolver(self):
        r = ck.resolve_hosts(["localhost", "this-name-does-not-exist.invalid"], timeout=5)
        self.assertTrue(r.get("localhost"))
        self.assertEqual(r.get("this-name-does-not-exist.invalid"), [])


class Parameters(unittest.TestCase):
    def test_query_parameters_are_inventoried(self):
        si = ck.SiteInfo()
        for u in ("https://e.com/p?id=1&sort=asc", "https://e.com/p?id=2", "https://e.com/q?id=3&q=x", "https://e.com/plain", "https://e.com/p?id=4&a=1"):
            si.add_params(u)
        self.assertEqual({k: v["count"] for k, v in si.params.items()}, {"id": 4, "sort": 1, "q": 1, "a": 1})
        self.assertEqual(len(si.params["id"]["examples"]), 3)                           # a few examples, not all of them
        again = ck.SiteInfo.from_dict(json.loads(json.dumps(si.to_dict())))
        self.assertEqual(again.params["id"]["count"], 4)

    def test_it_cannot_grow_without_bound(self):
        si = ck.SiteInfo()
        for i in range(1500):
            si.add_params(f"https://e.com/p?param{i}=1")
        self.assertLessEqual(len(si.params), 1000)
        si.add_params("https://e.com/p?" + "x" * 200 + "=1")
        self.assertEqual(len([k for k in si.params if len(k) > 60]), 0)


class Probes(unittest.TestCase):
    def results(self, files):
        def getter(url):
            path = "/" + url.split("/", 3)[3]
            return (200, files[path]) if path in files else (404, "")
        return {r.path: r for r in ck.probe("https://example.com/anything", getter)}

    def test_real_exposures_are_detected(self):
        r = self.results({"/.git/HEAD": "ref: refs/heads/main\n", "/.env": "DB_PASSWORD=hunter2\nAPP_KEY=x\n", "/.DS_Store": "\x00\x00\x00\x01Bud1abc",
                          "/.well-known/security.txt": "Contact: mailto:sec@example.com\nExpires: 2027-01-01T00:00:00Z\n", "/sitemap.xml": "<urlset></urlset>"})
        for path in ("/.git/HEAD", "/.env", "/.DS_Store", "/.well-known/security.txt", "/sitemap.xml"):
            self.assertTrue(r[path].exposed, path)
        self.assertFalse(r["/phpinfo.php"].exposed)
        f = ck.probe_findings(list(r.values()))
        self.assertEqual(sorted(x.severity for x, _ in f if x.code == "exposed-file"), ["high", "high", "medium"])  # .git, .env, .DS_Store
        self.assertNotIn("no-security-txt", [x.code for x, _ in f])  # a security.txt exists

    def test_a_site_that_answers_200_to_everything_gives_no_false_alarms(self):
        soft404 = "<html><body><h1>Page not found</h1><a href='/'>home</a></body></html>"
        files = {p.path: soft404 for p in ck.PROBES}
        r = self.results(files)
        self.assertFalse(any(x.exposed for x in r.values()))
        self.assertEqual([x.code for x, _ in ck.probe_findings(list(r.values()))], ["no-security-txt"])

    def test_missing_security_txt_is_an_info_finding(self):
        f = ck.probe_findings(list(self.results({}).values()))
        self.assertEqual([(x.code, x.severity) for x, _ in f], [("no-security-txt", "info")])


class RobotsAndSitemaps(unittest.TestCase):
    def test_parse_robots(self):
        r = ck.parse_robots("User-agent: *\nDisallow: /admin/ # staff\nDisallow: /tmp\nAllow: /\nCrawl-delay: 2.5\nSitemap: https://e.com/sitemap.xml\nsitemap: https://e.com/news.xml\nDisallow:\n")
        self.assertEqual((r["disallow"], r["sitemaps"], r["crawl_delay"]), (["/admin/", "/tmp"], ["https://e.com/sitemap.xml", "https://e.com/news.xml"], 2.5))
        f = ck.robots_findings(r, "https://e.com/robots.txt")
        self.assertEqual(f[0][0].code, "robots-sensitive")
        self.assertEqual(ck.robots_findings(ck.parse_robots("Disallow: /search"), ""), [])

    def test_parse_sitemap_kinds(self):
        ns = 'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"'
        self.assertEqual(ck.parse_sitemap(f'<urlset {ns}><url><loc> https://e.com/a </loc></url><url><loc>https://e.com/b</loc></url></urlset>'.encode()), (["https://e.com/a", "https://e.com/b"], [], ""))
        self.assertEqual(ck.parse_sitemap(f'<sitemapindex {ns}><sitemap><loc>https://e.com/s1.xml</loc></sitemap></sitemapindex>'.encode()), ([], ["https://e.com/s1.xml"], ""))
        self.assertEqual(ck.parse_sitemap(gzip.compress(b"<urlset><url><loc>https://e.com/z</loc></url></urlset>"))[0], ["https://e.com/z"])

    def test_malicious_and_broken_sitemaps_are_refused(self):
        bomb = b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><urlset><url><loc>&b;</loc></url></urlset>'
        self.assertIn("DOCTYPE", ck.parse_sitemap(bomb)[2])
        self.assertIn("too large", ck.parse_sitemap(gzip.compress(b"0" * (ck.MAX_SITEMAP_BYTES + 5000)))[2])
        self.assertIn("not valid XML", ck.parse_sitemap(b"<urlset><url>")[2])
        self.assertIn("cannot decompress", ck.parse_sitemap(b"\x1f\x8bnot gzip")[2])

    def test_discover_seeds_follows_index_but_not_other_hosts(self):
        files = {"/robots.txt": b"Sitemap: https://e.com/index.xml\nSitemap: https://evil.test/x.xml\nDisallow: /private/\n",
                 "/index.xml": b"<sitemapindex><sitemap><loc>https://e.com/s1.xml</loc></sitemap><sitemap><loc>https://e.com/s2.xml</loc></sitemap></sitemapindex>",
                 "/s1.xml": b"<urlset><url><loc>https://e.com/a</loc></url><url><loc>https://e.com/b</loc></url></urlset>",
                 "/s2.xml": b"<urlset><url><loc>https://e.com/b</loc></url><url><loc>https://e.com/c</loc></url></urlset>"}
        asked = []

        def getter(url):
            asked.append(url)
            p = "/" + url.split("/", 3)[3]
            return (200, files[p]) if p in files and url.startswith("https://e.com") else (404, b"")
        s = ck.discover_seeds("https://e.com/x", getter)
        self.assertEqual(s.pages, ["https://e.com/a", "https://e.com/b", "https://e.com/c"])  # de-duplicated, in order
        self.assertFalse(any("evil.test" in u for u in asked))
        self.assertEqual(s.robots["disallow"], ["/private/"])

    def test_default_sitemap_location_and_errors(self):
        s = ck.discover_seeds("https://e.com", lambda u: (200, b"<urlset><url><loc>https://e.com/q</loc></url></urlset>") if u.endswith("/sitemap.xml") else (404, b""))
        self.assertEqual(s.pages, ["https://e.com/q"])
        s = ck.discover_seeds("https://e.com", lambda u: (404, b""))
        self.assertEqual((s.pages, s.errors), ([], []))  # no sitemap at all is not an error


class SiteInfoTests(unittest.TestCase):
    def test_collects_and_round_trips(self):
        si = ck.SiteInfo()
        si.add_tls({"host": "e.com", "ok": True, "verified": True, "days_left": 5, "not_after": "2026-10-26", "protocol": "TLSv1.3", "verify_error": "", "error": ""})
        si.add_tech([ck.Tech("PHP", "5.6.1", "X-Powered-By header", "language"), ck.Tech("PHP", "5.6.1")], "https://e.com/")
        si.add_probes([ck.ProbeResult("/.env", "https://e.com/.env", ".env file is publicly readable", "high", True, 200)])
        si.set_seeds(ck.Seeds(["https://e.com/a"], ["https://e.com/sitemap.xml"], {"disallow": ["/admin/"]}, []), "https://e.com/robots.txt")
        got = {f.code for f, _ in si.findings}
        self.assertTrue({"tls-expiring", "eol-php", "exposed-file", "robots-sensitive"} <= got)
        self.assertEqual(len(si.tech), 1)
        again = ck.SiteInfo.from_dict(json.loads(json.dumps(si.to_dict())))
        self.assertEqual({(f.code, w) for f, w in again.findings}, {(f.code, w) for f, w in si.findings})
        self.assertEqual(again.tech.keys(), si.tech.keys())
        v = si.version
        si.add_finding(Finding("eol-php", "medium", "x"), "https://e.com/")
        si.add_finding(Finding("eol-php", "medium", "x"), "https://e.com/")
        self.assertEqual(si.version, v + 1)  # a repeated finding is not added twice


if __name__ == "__main__":
    unittest.main()
