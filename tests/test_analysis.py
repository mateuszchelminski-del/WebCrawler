import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import analysis as an  # noqa: E402

PAGE = "https://example.com/"


def codes(href, kind="external", page=PAGE):
    return {f.code for f in an.assess_link(href, kind, page)}


class LinkChecks(unittest.TestCase):
    def test_clean_links_have_no_findings(self):
        self.assertEqual(an.assess_link("https://example.org/docs", "external", PAGE), [])
        self.assertEqual(an.assess_link("https://example.com/about", "internal", PAGE), [])
        self.assertEqual(an.assess_link("mailto:a@b.co", "mailto", PAGE), [])

    def test_downgrade_only_from_https_pages(self):
        self.assertIn("http-downgrade", codes("http://other.org/x"))
        self.assertIn("http-external", codes("http://other.org/x", page="http://example.com/"))
        self.assertNotIn("http-downgrade", codes("http://other.org/x", page="http://example.com/"))

    def test_phishing_style_urls(self):
        self.assertIn("userinfo", codes("https://paypal.com@evil.test/login"))
        self.assertIn("punycode", codes("https://xn--pple-43d.com/"))
        self.assertIn("shortener", codes("https://bit.ly/3abc"))
        self.assertIn("raw-ip", codes("http://203.0.113.9/x"))
        self.assertIn("risky-tld", codes("https://update.zip/download"))

    def test_internal_address_vs_local_page(self):
        self.assertIn("internal-address", codes("http://192.168.1.10/admin"))
        self.assertNotIn("internal-address", codes("http://192.168.1.10/x", page="http://127.0.0.1:8000/"))
        self.assertNotIn("internal-address", codes("http://192.168.1.10/x", page="file:///c:/a.html"))

    def test_open_redirect_parameter(self):
        self.assertIn("open-redirect", codes("https://example.com/out?next=https://evil.test/", "internal"))
        self.assertNotIn("open-redirect", codes("https://example.com/out?next=/home", "internal"))

    def test_sensitive_paths(self):
        self.assertIn("sensitive-file", codes("https://example.com/.git/config", "internal"))
        self.assertIn("sensitive-file", codes("https://example.com/db/backup.sql", "file"))
        self.assertIn("admin-path", codes("https://example.com/wp-admin/", "internal"))
        self.assertIn("login-path", codes("https://example.com/login", "internal"))
        self.assertIn("exec-download", codes("https://example.com/setup.exe", "file"))

    def test_obfuscation_and_length(self):
        self.assertIn("obfuscated", codes("https://x.org/%61%64%6d%69%6e%2f"))
        self.assertIn("long-url", codes("https://x.org/" + "a" * 320))

    def test_scoring(self):
        f = an.assess_link("https://paypal.com@bit.ly/x", "external", PAGE)
        self.assertEqual(an.risk_score(f), 60)
        self.assertEqual(an.rating(60), "high")
        self.assertEqual(an.rating(20), "medium")
        self.assertEqual(an.rating(8), "low")
        self.assertEqual(an.rating(0), "none")
        self.assertEqual(an.risk_score(f * 10), 100)  # capped


class HeaderChecks(unittest.TestCase):
    def check(self, headers, url="https://example.com/"):
        f, shown = an.check_headers(url, headers)
        return {x.code for x in f}, shown

    def test_bare_https_page(self):
        c, _ = self.check([("Content-Type", "text/html")])
        self.assertTrue({"no-hsts", "no-csp", "no-frame-protection", "no-nosniff", "no-referrer-policy"} <= c)

    def test_hardened_page_is_quiet(self):
        c, shown = self.check([("Strict-Transport-Security", "max-age=31536000; includeSubDomains"), ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                               ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"), ("Permissions-Policy", "camera=()")])
        self.assertEqual(c, set())
        self.assertIn("content-security-policy", shown)

    def test_weak_csp_and_disclosure(self):
        c, _ = self.check([("Content-Security-Policy", "script-src 'self' 'unsafe-inline'"), ("Server", "Apache/2.4.49"), ("X-Powered-By", "PHP/8.1")])
        self.assertTrue({"weak-csp", "server-version", "x-powered-by"} <= c)
        self.assertNotIn("no-csp", c)

    def test_http_page(self):
        c, _ = self.check([], url="http://example.com/")
        self.assertIn("no-https", c)
        self.assertNotIn("no-hsts", c)

    def test_cookies(self):
        c, _ = self.check([("Set-Cookie", "sid=1; Path=/\ntheme=dark; Secure; HttpOnly; SameSite=Lax")])
        self.assertTrue({"cookie-no-secure", "cookie-no-httponly", "cookie-no-samesite"} <= c)

    def test_cors(self):
        c, _ = self.check([("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true")])
        self.assertIn("cors-wildcard-creds", c)


class CookieChecks(unittest.TestCase):
    def check(self, *lines, url="https://example.com/", cache=""):
        return an.check_cookies(url, list(lines), cache)

    def by_code(self, findings):
        return {f.code: f for f in findings}

    def test_a_well_set_cookie_is_clean(self):
        self.assertEqual(self.check("session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"), [])

    def test_attributes_are_parsed_not_searched_for(self):
        # the old check looked for the word "secure" anywhere in the line, so a cookie *named* secure_id passed
        f = self.by_code(self.check("secure_id=1; Path=/; HttpOnly; SameSite=Lax"))
        self.assertIn("cookie-no-secure", f)
        f = self.by_code(self.check("theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax; Comment=httponly-samesite"))
        self.assertEqual(f, {})
        c = an.parse_set_cookie("a=b=c; Path=/x; Secure; HttpOnly; Max-Age=60; SameSite=None")
        self.assertEqual((c["name"], c["value"], c["path"], c["secure"], c["httponly"], c["max-age"], c["samesite"]), ("a", "b=c", "/x", True, True, "60", "None"))

    def test_session_cookies_are_held_to_a_higher_standard(self):
        f = self.by_code(self.check("PHPSESSID=abc; Path=/; Secure"))
        self.assertEqual((f["cookie-no-httponly"].severity, f["cookie-no-samesite"].severity), ("medium", "low"))
        f = self.by_code(self.check("theme=dark; Path=/; Secure"))
        self.assertEqual((f["cookie-no-httponly"].severity, f["cookie-no-samesite"].severity), ("low", "info"))

    def test_session_cookie_over_plain_http(self):
        f = self.by_code(self.check("sid=abc; HttpOnly; SameSite=Lax", url="http://example.com/"))
        self.assertEqual(f["cookie-over-http"].severity, "medium")
        self.assertNotIn("cookie-over-http", self.by_code(self.check("theme=dark; HttpOnly; SameSite=Lax", url="http://example.com/")))
        self.assertNotIn("cookie-no-secure", f)                                   # Secure is only expected on https pages

    def test_samesite_none_needs_secure(self):
        f = self.by_code(self.check("x=1; HttpOnly; SameSite=None"))
        self.assertEqual(f["cookie-samesite-none-insecure"].severity, "medium")
        self.assertNotIn("cookie-samesite-none-insecure", self.by_code(self.check("x=1; Secure; HttpOnly; SameSite=None")))

    def test_cookie_name_prefixes(self):
        self.assertIn("cookie-prefix-misuse", self.by_code(self.check("__Host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.com")))
        self.assertIn("cookie-prefix-misuse", self.by_code(self.check("__Host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/app")))
        self.assertIn("cookie-prefix-misuse", self.by_code(self.check("__Secure-id=1; HttpOnly; SameSite=Lax")))
        self.assertNotIn("cookie-prefix-misuse", self.by_code(self.check("__Host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/")))

    def test_cookie_shared_with_every_subdomain(self):
        f = self.by_code(self.check("a=1; Secure; HttpOnly; SameSite=Lax; Domain=.example.com", url="https://app.example.com/"))
        self.assertIn("cookie-broad-domain", f)
        self.assertNotIn("cookie-broad-domain", self.by_code(self.check("a=1; Secure; HttpOnly; SameSite=Lax; Domain=example.com", url="https://example.com/")))

    def test_long_lived_session_cookies_and_caching(self):
        f = self.by_code(self.check("sessionid=1; Secure; HttpOnly; SameSite=Lax; Max-Age=63072000"))
        self.assertIn("cookie-long-lived", f)
        old = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() + 3 * 365 * 86400))
        self.assertIn("cookie-long-lived", self.by_code(self.check(f"sessionid=1; Secure; HttpOnly; SameSite=Lax; Expires={old}")))
        self.assertNotIn("cookie-long-lived", self.by_code(self.check("sessionid=1; Secure; HttpOnly; SameSite=Lax; Max-Age=3600")))
        self.assertNotIn("cookie-long-lived", self.by_code(self.check("theme=1; Secure; HttpOnly; SameSite=Lax; Max-Age=63072000")))   # only sessions matter
        self.assertIn("cookie-cacheable", self.by_code(self.check("sid=1; Secure; HttpOnly; SameSite=Lax", cache="public, max-age=600")))
        self.assertNotIn("cookie-cacheable", self.by_code(self.check("sid=1; Secure; HttpOnly; SameSite=Lax", cache="private, no-store")))

    def test_check_headers_uses_it(self):
        f, _ = an.check_headers("https://example.com/", [("Set-Cookie", "sid=1; Path=/"), ("Set-Cookie", "theme=dark; Secure; HttpOnly; SameSite=Lax")])
        names = [x.title for x in f if x.code.startswith("cookie")]
        self.assertTrue(all("'sid'" in n for n in names), names)                  # only the weak one is reported


class SecretsInUrls(unittest.TestCase):
    def find(self, href):
        return [f for f in an.assess_link(href, "internal", "https://example.com/") if f.code == "url-secret"]

    def test_passwords_tokens_and_session_ids_in_urls(self):
        f = self.find("https://example.com/login?user=bob&password=hunter2")
        self.assertEqual(f[0].severity, "high")
        self.assertNotIn("hunter2", f[0].detail)                                  # the value is never repeated
        self.assertIn("password", f[0].detail)
        self.assertEqual(self.find("https://example.com/api?access_token=abcdef123456")[0].severity, "medium")
        self.assertEqual(self.find("https://example.com/p;jsessionid=ABCDEF123456?x=1")[0].severity, "medium")
        self.assertEqual(self.find("https://example.com/?apikey=abcdefgh&token=zzzzzzzz")[0].detail.count("parameter"), 1)

    def test_innocent_urls_are_left_alone(self):
        for u in ("https://example.com/search?q=password+reset", "https://example.com/?token=", "https://example.com/?token=abc", "https://example.com/?sidebar=open",
                  "https://example.com/author/session-notes"):
            self.assertEqual(self.find(u), [], u)


if __name__ == "__main__":
    unittest.main()
