"""Scans of real public practice sites. Skipped unless WEBCRAWLER_LIVE=1 (they need the internet and depend on other people's servers)."""
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

LIVE = os.environ.get("WEBCRAWLER_LIVE") == "1"
if LIVE:
    import realworld


@unittest.skipUnless(LIVE, "set WEBCRAWLER_LIVE=1 to scan real sites")
class Live(unittest.TestCase):
    def scan(self, name):
        site = next(s for s in realworld.SITES if s[0] == name)
        return realworld.scan(site[1], site[2])

    def test_a_catalogue_site_is_crawled(self):
        r = self.scan("books.toscrape")
        self.assertEqual(r["rc"], 0)
        self.assertGreaterEqual(r["pages"], 20)
        self.assertGreater(r["links"], 100)

    def test_certificate_problems_are_named(self):
        for name, codes in (("badssl expired", ("tls-expired", "tls-invalid")), ("badssl self-signed", ("tls-invalid",)), ("badssl wrong host", ("tls-invalid",)),
                            ("badssl untrusted root", ("tls-invalid",)), ("badssl tls 1.0", ("tls-old-protocol",))):
            with self.subTest(name):
                got = self.scan(name)["codes"]
                self.assertTrue(set(codes) & set(got), got)

    def test_a_big_key_is_not_called_weak(self):
        codes = self.scan("badssl rsa8192")["codes"]            # the server is slow and its certificate has lapsed at times: only the key size is asserted
        self.assertNotIn("tls-weak-key", codes)


if __name__ == "__main__":
    unittest.main()
