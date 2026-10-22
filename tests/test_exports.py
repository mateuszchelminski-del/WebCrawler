"""SARIF and JUnit exports, the rules catalog behind them, and the JSON schemas of the files the tool writes."""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import accepted as ac  # noqa: E402
import analysis as an  # noqa: E402
import history as hi  # noqa: E402
import rules  # noqa: E402
import sarif  # noqa: E402
import snapshot as sn  # noqa: E402
import test_cli_monitoring as tcm  # noqa: E402
import test_snapshot as ts  # noqa: E402

try:
    import jsonschema
    HAVE_JSONSCHEMA = True
except ImportError:       # pragma: no cover
    HAVE_JSONSCHEMA = False

SARIF_SCHEMA = Path(os.environ.get("SARIF_SCHEMA") or ROOT / "tests" / "fixtures" / "sarif-schema-2.1.0.json")   # the OASIS schema: not redistributed here, CI downloads it


def acc(*entries):
    from datetime import date
    return ac.Accepted([{"code": c, "where": w, "reason": r, "expires": "", "added": ""} for c, w, r in entries], today=date(2026, 10, 21))


def sample():
    s, _ = ts.crawl(["https://bit.ly/x", "https://paypal.com@evil.test/login"], findings=[an.Finding("no-csp", "low", "No <Content-Security-Policy> & friends")],
                    site_findings=[(an.Finding("exposed-file", "high", ".env file is publicly readable", "/.env"), "https://example.com/.env")])
    return s


class Rules(unittest.TestCase):
    def source_codes(self):
        found = set()
        for p in ROOT.glob("*.py"):
            if p.name in ("rules.py",):
                continue
            text = p.read_text(encoding="utf-8")
            found |= set(re.findall(r'Finding\(\s*f?"([a-z0-9-]+)"', text))
            found |= set(re.findall(r'\bF\(\s*"([a-z0-9-]+)"', text))
        return found

    def test_every_finding_code_in_the_program_is_explained(self):
        missing = sorted(self.source_codes() - set(rules.RULES) - {"broken"})
        self.assertEqual(missing, [], "add these to rules.RULES")

    def test_nothing_in_the_catalog_is_stale(self):
        literals = set()
        for p in ROOT.glob("*.py"):
            if p.name != "rules.py":
                literals |= set(re.findall(r'"([a-z0-9]+(?:-[a-z0-9]+)*)"', p.read_text(encoding="utf-8")))
        stale = sorted(c for c in rules.RULES if c not in literals and c != "broken")
        self.assertEqual(stale, [], "these codes are described but never produced")

    def test_entries_are_complete(self):
        for code, (name, advice, cwes) in rules.RULES.items():
            self.assertRegex(code, r"^[a-z0-9]+(-[a-z0-9]+)*$")
            self.assertTrue(name and advice, code)
            self.assertTrue(advice.endswith((".", ")")), code)
            for c in cwes:
                self.assertRegex(c, r"^CWE-\d+$")

    def test_the_checks_document_is_current(self):
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "make_checks_doc.py"), "--check"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class Sarif(unittest.TestCase):
    def test_structure(self):
        log = sarif.build(sample())
        self.assertEqual((log["version"], len(log["runs"])), ("2.1.0", 1))
        run = log["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "WebCrawler")
        ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue({"shortener", "userinfo", "no-csp", "exposed-file"} <= set(ids))
        for r in run["results"]:
            self.assertEqual(ids[r["ruleIndex"]], r["ruleId"])
            self.assertIn(r["level"], ("error", "warning", "note"))
            loc = r["locations"][0]["physicalLocation"]
            self.assertTrue(loc["artifactLocation"]["uri"])
            self.assertEqual(loc["region"]["startLine"], 1)
            self.assertEqual(len(r["partialFingerprints"]["webcrawlerFinding/v1"]), 32)
        rules_by_id = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        env = rules_by_id["exposed-file"]
        self.assertEqual(env["properties"]["security-severity"], "8.0")
        self.assertIn("external/cwe/cwe-538", env["properties"]["tags"])
        self.assertIn("Remove the file", env["help"]["text"])

    def test_worst_findings_come_first_and_levels_follow_severity(self):
        results = sarif.build(sample())["runs"][0]["results"]
        scores = [float(rules.SEVERITY_SCORE[r["properties"]["severity"]]) for r in results]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(results[0]["level"], "error")
        by = {r["ruleId"]: r["level"] for r in results}
        self.assertEqual((by["exposed-file"], by["userinfo"], by["shortener"], by["no-csp"]), ("error", "error", "warning", "note"))

    def test_a_link_finding_is_placed_on_the_page_that_has_the_link(self):
        results = [r for r in sarif.build(sample())["runs"][0]["results"] if r["ruleId"] == "shortener"]
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "https://example.com/")
        self.assertIn("https://bit.ly/x", results[0]["message"]["text"])
        self.assertEqual(results[0]["properties"]["url"], "https://bit.ly/x")

    def test_fingerprints_identify_a_finding_across_crawls(self):
        a = {r["ruleId"] + r["properties"]["url"]: r["partialFingerprints"] for r in sarif.build(sample())["runs"][0]["results"]}
        b = {r["ruleId"] + r["properties"]["url"]: r["partialFingerprints"] for r in sarif.build(sample())["runs"][0]["results"]}
        self.assertEqual(a, b)
        self.assertEqual(len({json.dumps(v) for v in a.values()}), len(a))               # different findings, different identities

    def test_accepted_findings_are_suppressed_not_dropped(self):
        log = sarif.build(sample(), acc(("shortener", "https://bit.ly/*", "marketing")))
        by = {r["ruleId"]: r for r in log["runs"][0]["results"]}
        self.assertEqual(by["shortener"]["suppressions"], [{"kind": "external", "status": "accepted", "justification": "marketing"}])
        self.assertNotIn("suppressions", by["userinfo"])
        self.assertEqual((log["runs"][0]["properties"]["open"] > 0, log["runs"][0]["properties"]["accepted"]), (True, 1))

    def test_locations_can_be_mapped_onto_the_repository(self):
        loc = sarif.location_uri
        start = "https://example.com/"
        for place, prefix, want in (("https://example.com/about.html", "public", "public/about.html"), ("https://example.com/", "public/", "public/index.html"),
                                    ("https://example.com/docs/", "/site/", "site/docs/index.html"), ("https://example.com/a%20b.html", "", "https://example.com/a%20b.html"),
                                    ("https://example.com/a%20b.html", ".", "a b.html"), ("example.com", "public", "public/index.html"), ("https://example.com/x?y=1#z", "src", "src/x")):
            self.assertEqual(loc(place, start, prefix), want, (place, prefix))
        self.assertEqual(loc("example.com", start, ""), start)

    @unittest.skipUnless(HAVE_JSONSCHEMA and SARIF_SCHEMA.exists(), "needs jsonschema and the SARIF 2.1.0 schema (set SARIF_SCHEMA, or see .github/workflows/ci.yml)")
    def test_it_is_valid_sarif(self):
        schema = json.loads(SARIF_SCHEMA.read_text(encoding="utf-8"))
        jsonschema.Draft4Validator.check_schema(schema)
        for acceptance in (None, acc(("shortener", "*", "ok"))):
            for prefix in ("", "public"):
                jsonschema.Draft4Validator(schema).validate(sarif.build(sample(), acceptance, prefix))
        jsonschema.Draft4Validator(schema).validate(sarif.build({"start": "", "links": [], "pages": [], "broken": [], "site": {}}))          # an empty crawl


class Junit(unittest.TestCase):
    def parse(self, xml):
        return ET.fromstring(xml)

    def test_findings_become_test_cases(self):
        root = self.parse(sarif.junit(sample()))
        suite = root.find("testsuite")
        cases = suite.findall("testcase")
        self.assertEqual(int(suite.get("tests")), len(cases))
        failing = [c for c in cases if c.find("failure") is not None]
        self.assertEqual(int(suite.get("failures")), len(failing))
        self.assertTrue(any("exposed-file" in c.get("name") and c.find("failure").get("type") == "high" for c in failing))
        self.assertTrue(any("No <Content-Security-Policy> & friends" in (c.find("failure").get("message") or "") for c in failing))      # escaped on the way out, intact after parsing

    def test_threshold_and_accepted(self):
        medium = self.parse(sarif.junit(sample(), fail_at="medium")).find("testsuite")
        everything = self.parse(sarif.junit(sample(), fail_at="low")).find("testsuite")
        self.assertLess(int(medium.get("failures")), int(everything.get("failures")))
        quiet = self.parse(sarif.junit(sample(), acc(("*", "*", "all fine")), fail_at="low")).find("testsuite")
        self.assertEqual(int(quiet.get("failures")), 0)
        skipped = [c for c in quiet.findall("testcase") if c.find("skipped") is not None]
        self.assertEqual(len(skipped), int(quiet.get("tests")))
        self.assertIn("accepted: all fine", skipped[0].find("skipped").get("message"))

    def test_an_empty_crawl_is_valid_xml(self):
        s = self.parse(sarif.junit({"start": "https://e.com/", "links": [], "pages": [], "broken": [], "site": {}})).find("testsuite")
        self.assertEqual((s.get("tests"), s.get("failures")), ("0", "0"))


class OnTheCommandLine(tcm.Monitoring):
    def test_exports_and_exit_codes(self):
        self.srv.extra = "<a href='https://bit.ly/x'>s</a>"
        out = self.tmp / "o"
        rc, text = tcm.cli(self.base + "/", "--quick", "--delay", "0", "--depth", "2", "-q", "--no-tls", "--out", str(out), "--format", "sarif", "junit", "json", "--sarif-prefix", "public")
        self.assertEqual(rc, 0)
        log = json.loads((out / "results.sarif").read_text(encoding="utf-8"))
        shortener = [r for r in log["runs"][0]["results"] if r["ruleId"] == "shortener"]
        self.assertTrue(shortener)
        self.assertTrue(shortener[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("public/"))
        ET.parse(out / "junit.xml")
        # --fail-on: absolute, not relative to an earlier crawl
        self.assertEqual(self.crawl("b", "--fail-on", "high")[0], 0)
        rc, text, _ = self.crawl("c", "--fail-on", "medium")
        self.assertEqual(rc, 3)
        self.assertIn("open finding(s) at medium or above", text)
        f = self.tmp / "accepted.json"
        tcm.cli("--accepted", str(f), "--accept", "*", "--reason", "everything on this test server is expected")
        rc, text, _ = self.crawl("d", "--fail-on", "medium", "--accepted", str(f))
        self.assertEqual(rc, 0)
        self.assertIn("accepted, not counted", text)

    def test_the_version_flag(self):
        import version
        rc, text = tcm.cli("--version")
        self.assertIn(version.VERSION, text)


for _name in [n for n in dir(tcm.Monitoring) if n.startswith("test_") and n not in vars(OnTheCommandLine)]:
    setattr(OnTheCommandLine, _name, None)


# ------------------------------------------------------------------------------------------------ schemas

@unittest.skipUnless(HAVE_JSONSCHEMA, "needs the jsonschema package (pip install -r requirements-dev.txt)")
class Schemas(unittest.TestCase):
    def load(self, name):
        return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))

    def validate(self, name, data):
        schema = self.load(name)
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(data)

    def test_the_schemas_are_valid_schemas(self):
        for p in (ROOT / "schemas").glob("*.json"):
            jsonschema.Draft202012Validator.check_schema(json.loads(p.read_text(encoding="utf-8")))

    def test_session(self):
        s = sample()
        self.validate("session.schema.json", s)
        s["site"]["forms"] = [{"page": "https://e.com/", "action": "https://e.com/login", "method": "post", "enctype": "", "password": True, "upload": False, "csrf": False,
                               "search": False, "cross_origin": False, "id": "", "fields": [{"name": "pw", "type": "password", "required": True}]}]
        s["site"]["dns"] = {"domain": "e.com", "ns": [], "mx": [], "spf": "", "spf_lookups": 0, "dmarc": "", "dkim": [], "mta_sts": False, "tls_rpt": False, "caa": [], "dnssec": False}
        s["site"]["scripts"] = {"cdn.x.net": {"count": 1, "pages": ["https://e.com/"]}}
        s["graph"]["nodes"][0].update({"fp": "00ff00ff00ff00ff", "words": 12})
        self.validate("session.schema.json", s)
        bad = json.loads(json.dumps(s))
        bad["format"] = "other"
        with self.assertRaises(jsonschema.ValidationError):
            self.validate("session.schema.json", bad)
        bad = json.loads(json.dumps(s))
        bad["pages"][0]["findings"][0]["severity"] = "catastrophic"
        with self.assertRaises(jsonschema.ValidationError):
            self.validate("session.schema.json", bad)

    def test_changes(self):
        old, _ = ts.crawl()
        new, _ = ts.crawl(["https://bit.ly/x"])
        self.validate("changes.schema.json", json.loads(json.dumps(sn.diff(old, new, acc(("zzz", "*", "")) ).to_dict())))
        urls = [f"https://e.com/p{i}" for i in range(12)]
        from test_accepted import page_session
        self.validate("changes.schema.json", json.loads(json.dumps(sn.diff(page_session(urls, code=None), page_session(urls)).to_dict())))

    def test_accepted_and_history(self):
        a = acc(("no-csp", "https://e.com/*", "static"))
        a.entries[0]["expires"] = "2027-01-01"
        d = Path(tempfile.mkdtemp())
        a.save(d / "a.json")
        self.validate("accepted.schema.json", json.loads((d / "a.json").read_text(encoding="utf-8")))
        h = hi.History("https://e.com/")
        old, _ = ts.crawl()
        new, _ = ts.crawl(["https://bit.ly/x"])
        h.add(hi.summarize(old), "https://e.com/")
        h.add(hi.summarize(new, a, sn.diff(old, new)))
        h.save(d / "h.json")
        self.validate("history.schema.json", json.loads((d / "h.json").read_text(encoding="utf-8")))
        bad = json.loads((d / "a.json").read_text(encoding="utf-8"))
        bad["accepted"][0]["expires"] = "next week"
        with self.assertRaises(jsonschema.ValidationError):
            self.validate("accepted.schema.json", bad)

    def test_the_real_files_a_crawl_writes(self):
        out = Path(tempfile.mkdtemp())
        # a real scan of the local test server, through the command line
        import test_httpscan_checks as ths
        srv = ths.serve()
        srv.other_base = srv.base
        try:
            rc, _ = tcm.cli(srv.base + "/", "--quick", "--delay", "0", "--depth", "2", "-q", "--no-tls", "--out", str(out), "--history", str(out / "history.json"))
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(rc, 0)
        self.validate("session.schema.json", json.loads((out / "session.json").read_text(encoding="utf-8")))
        self.validate("links.schema.json", json.loads((out / "links.json").read_text(encoding="utf-8")))
        self.validate("history.schema.json", json.loads((out / "history.json").read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
