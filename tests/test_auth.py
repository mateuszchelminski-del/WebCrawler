import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import auth  # noqa: E402
import frontier as fr  # noqa: E402

ROOT = "https://app.example.com/"


class Parsing(unittest.TestCase):
    def test_cookie_strings(self):
        c = auth.parse_cookie_string("Cookie: sid=abc123; theme=dark; flag", "app.example.com")
        self.assertEqual([(x["name"], x["value"], x["domain"]) for x in c], [("sid", "abc123", "app.example.com"), ("theme", "dark", "app.example.com")])
        self.assertEqual(auth.parse_cookie_string("a=b=c")[0]["value"], "b=c")
        with self.assertRaises(ValueError):
            auth.parse_cookie_string("not a cookie")
        self.assertEqual(auth.parse_cookie_string(""), [])

    def test_header_lines(self):
        self.assertEqual(auth.parse_header_line("Authorization: Bearer abc.def"), ("Authorization", "Bearer abc.def"))
        self.assertEqual(auth.parse_header_line("X-Api-Key:  k:1"), ("X-Api-Key", "k:1"))
        for bad in ("no colon", "Bad Name: v", "Host: evil", "Content-Length: 5", "X: a\r\nSet-Cookie: x=1", ": v"):
            with self.assertRaises(ValueError, msg=bad):
                auth.parse_header_line(bad)

    def write(self, text):
        d = tempfile.mkdtemp()
        p = Path(d) / "c.txt"
        p.write_text(text, encoding="utf-8")
        return str(p)

    def test_cookie_files(self):
        j = self.write(json.dumps([{"name": "sid", "value": "1", "domain": ".example.com", "path": "/app", "secure": True, "httpOnly": True}, {"name": "x"}]))
        c = auth.load_cookie_file(j)
        self.assertEqual((len(c), c[0]["domain"], c[0]["path"], c[0]["secure"]), (1, ".example.com", "/app", True))
        state = self.write(json.dumps({"cookies": [{"name": "t", "value": "v", "domain": "a.com", "path": "/"}], "origins": []}))
        self.assertEqual(auth.load_cookie_file(state)[0]["name"], "t")
        net = self.write("# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tTRUE\t0\tsession\tabc\n#HttpOnly_.example.com\tTRUE\t/\tFALSE\t0\tpriv\tdef\n")
        c = auth.load_cookie_file(net)
        self.assertEqual([(x["name"], x["secure"], x["httpOnly"]) for x in c], [("session", True, False), ("priv", False, True)])
        self.assertEqual(auth.load_cookie_file(self.write("a=1; b=2"), "h.com")[1]["name"], "b")
        with self.assertRaises(ValueError):
            auth.load_cookie_file(self.write("[]"))

    def test_oversized_file_refused(self):
        with self.assertRaises(ValueError):
            auth.load_cookie_file(self.write("a=" + "x" * (auth.MAX_FILE + 10)))


class Scoping(unittest.TestCase):
    def cfg(self):
        return auth.AuthConfig.build(cookie="sid=1; other=2", headers=["Authorization: Bearer tok"], domain="app.example.com")

    def test_credentials_only_go_to_the_crawled_site(self):
        a = self.cfg()
        h = a.headers_for("https://app.example.com/dash", ROOT)
        self.assertEqual((h["Authorization"], h["Cookie"]), ("Bearer tok", "sid=1; other=2"))
        for other in ("https://evil.test/", "https://example.com/", "https://app.example.com.evil.test/", "http://app.example.com:8080/"):
            self.assertEqual(a.headers_for(other, ROOT), {}, other)

    def test_subdomain_scope_widens_but_any_does_not(self):
        a = auth.AuthConfig.build(headers=["X-Token: t"])
        self.assertEqual(a.headers_for("https://api.example.com/", "https://app.example.com/", "subdomains"), {})  # app.example.com is the root host
        a = auth.AuthConfig.build(headers=["X-Token: t"])
        self.assertTrue(a.headers_for("https://api.example.com/", "https://example.com/", "subdomains"))
        self.assertEqual(a.headers_for("https://other.org/", "https://example.com/", "any"), {})

    def test_cookie_matching_rules(self):
        a = auth.AuthConfig(cookies=[{"name": "s", "value": "1", "domain": ".example.com", "path": "/app", "secure": True}, {"name": "p", "value": "2", "domain": "", "path": "/"}])
        self.assertEqual(a.cookie_header("https://www.example.com/app/x"), "s=1; p=2")
        self.assertEqual(a.cookie_header("http://www.example.com/app/x"), "p=2")        # Secure cookie never goes over HTTP
        self.assertEqual(a.cookie_header("https://www.example.com/other"), "p=2")       # path does not match
        self.assertEqual(a.cookie_header("https://example.org/app"), "p=2")             # domain does not match

    def test_empty_config_adds_nothing(self):
        a = auth.AuthConfig()
        self.assertTrue(a.empty)
        self.assertEqual(a.headers_for(ROOT, ROOT), {})

    def test_describe_never_shows_values(self):
        d = self.cfg().describe()
        self.assertIn("sid", d)
        self.assertIn("Authorization", d)
        self.assertNotIn("Bearer tok", d)
        self.assertNotRegex(d, r"=1\b")

    def test_playwright_cookies(self):
        a = auth.AuthConfig(cookies=[{"name": "a", "value": "1", "domain": ".example.com", "path": "/"}, {"name": "b", "value": "2", "domain": ""}])
        pw = a.for_playwright("https://app.example.com/")
        self.assertEqual(pw[0]["domain"], ".example.com")
        self.assertEqual(pw[1]["url"], "https://app.example.com/")


class Logout(unittest.TestCase):
    def test_logout_links_are_excluded(self):
        pats = [re.compile(p, re.I) for p in auth.logout_excludes()]
        for u in ("https://a.com/logout", "https://a.com/Sign-Out", "https://a.com/user/log_off", "https://a.com/x?action=logout", "https://a.com/session/destroy"):
            self.assertTrue(any(p.search(u) for p in pats), u)
        for u in ("https://a.com/blog/log-analysis", "https://a.com/outlook", "https://a.com/dashboard"):
            self.assertFalse(any(p.search(u) for p in pats), u)

    def test_frontier_honours_them(self):
        o = fr.CrawlOptions(exclude=auth.logout_excludes())
        f = fr.Frontier(ROOT, o)
        f.pop()
        self.assertFalse(f.push("https://app.example.com/logout", 1, ROOT))
        self.assertTrue(f.push("https://app.example.com/account", 1, ROOT))


if __name__ == "__main__":
    unittest.main()
