"""sarif.py: the findings of a crawl as SARIF 2.1.0, the format GitHub code scanning, Azure DevOps and most security dashboards read,
and as JUnit XML for CI systems that show test results.

    python webcrawler.py https://example.com --quick --format sarif
    # then, in a workflow:   uses: github/codeql-action/upload-sarif@v3   with: {sarif_file: results.sarif}

A web finding has no line of code, so by default its location is the page's URL. If the site is built from a repository, give the folder that
holds the site's files (--sarif-prefix public/) and GitHub can place each alert on the file the page comes from.
Findings you have accepted are kept in the file but marked as suppressed, which dashboards show as dismissed.
"""
from __future__ import annotations

import hashlib
import json
from urllib.parse import unquote, urlparse
from xml.sax.saxutils import escape, quoteattr

import rules
import snapshot
from version import REPO_URL, VERSION

SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"


def _pascal(code: str) -> str:
    return "".join(p.capitalize() for p in code.replace("_", "-").split("-"))


def location_uri(place: str, start: str, prefix: str = "") -> str:
    """Where a finding is, as a SARIF artifact URI. With `prefix`, a page URL is mapped onto a file under that folder of the repository
    (/ and /docs/ become index.html), so code scanning can show the alert on the file; otherwise the URL itself is used."""
    u = urlparse(place if "//" in place else start or "")
    if not prefix:
        return place if "//" in place else (start or place)
    path = unquote(u.path or "/")
    if path.endswith("/"):
        path += "index.html"
    base = prefix.replace("\\", "/").strip("/")
    base = "" if base == "." else base[2:] if base.startswith("./") else base
    return (base + "/" if base else "") + path.lstrip("/")


def fingerprint(f: dict) -> str:
    """A stable identity for a finding across crawls (so the dashboard tracks the same alert, not a new one each time)."""
    basis = "\n".join((f["code"], f.get("where", ""), f.get("page", "")))
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:32]


def build(session: dict, accepted=None, prefix: str = "") -> dict:
    """The SARIF log for a session (as built by snapshot.build or loaded from a file)."""
    start = session.get("start", "")
    findings = snapshot.all_findings(session)
    if accepted:
        open_, done = accepted.split(findings)
    else:
        open_, done = findings, []
    order = sorted(enumerate(open_ + done), key=lambda t: (-float(rules.SEVERITY_SCORE.get(t[1]["severity"], "0")), t[0]))        # worst first, stable
    rule_list, index = [], {}
    results = []
    for _, f in order:
        code = f["code"]
        if code not in index:
            name, advice, cwes = rules.describe(code, f["title"])
            index[code] = len(rule_list)
            rule_list.append({
                "id": code, "name": _pascal(code), "shortDescription": {"text": name},
                "fullDescription": {"text": advice or name}, "help": {"text": advice or name, "markdown": (advice or name)},
                "helpUri": REPO_URL + "/blob/main/docs/CHECKS.md#" + code,
                "defaultConfiguration": {"level": rules.SARIF_LEVEL.get(f["severity"], "note")},
                "properties": {"tags": ["security", "web"] + [f"external/cwe/{c.lower()}" for c in cwes], "precision": "medium",
                               "security-severity": rules.SEVERITY_SCORE.get(f["severity"], "1.0"), "problem.severity": f["severity"]}})
        place = f["page"] if f.get("kind") in ("link", "broken") and f.get("page") else f["where"]       # fix it where it is written: on the page that has the link
        text = f["title"] + (f": {f['detail']}" if f.get("detail") and f["kind"] != "broken" else "")
        if f.get("kind") in ("link", "broken") and f.get("page"):
            text += f"  [{f['where']} on {f['page']}]"
        elif "//" in f["where"] and f["where"] != place:
            text += f"  [{f['where']}]"
        r = {"ruleId": code, "ruleIndex": index[code], "level": rules.SARIF_LEVEL.get(f["severity"], "note"), "message": {"text": text},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": location_uri(place, start, prefix)}, "region": {"startLine": 1, "startColumn": 1}}}],
             "partialFingerprints": {"webcrawlerFinding/v1": fingerprint(f)},
             "properties": {"severity": f["severity"], "url": f["where"], "kind": f["kind"]}}
        if "accepted_reason" in f:
            r["suppressions"] = [{"kind": "external", "status": "accepted", "justification": f["accepted_reason"] or "accepted"}]
        results.append(r)
    host = urlparse(start).netloc or "site"
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "WebCrawler", "version": VERSION, "semanticVersion": VERSION, "informationUri": REPO_URL, "rules": rule_list}},
        "automationDetails": {"id": f"webcrawler/{host}/"},
        "invocations": [{"executionSuccessful": True, "endTimeUtc": session.get("created") or "1970-01-01T00:00:00Z", "properties": {"start": start}}],
        "results": results,
        "properties": {"start": start, "open": len(open_), "accepted": len(done)}}]}


def to_json(session: dict, accepted=None, prefix: str = "") -> str:
    return json.dumps(build(session, accepted, prefix), indent=2)


# ------------------------------------------------------------------------------------------------ JUnit

def junit(session: dict, accepted=None, fail_at: str = "low") -> str:
    """JUnit XML: one test case per finding. Findings at `fail_at` or worse fail; lighter ones and accepted ones are skipped (so a CI
    system's test tab lists everything but only the findings that matter turn the build red)."""
    start = session.get("start", "")
    findings = snapshot.all_findings(session)
    open_, done = accepted.split(findings) if accepted else (findings, [])
    rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    cases, failures, skipped = [], 0, 0
    for f in open_ + done:
        name = f"{f['code']} @ {f['where']}"
        body = ""
        if "accepted_reason" in f:
            body, skipped = f'<skipped message={quoteattr("accepted: " + f["accepted_reason"])}/>', skipped + 1
        elif rank.get(f["severity"], 3) <= rank.get(fail_at, 2):
            body = f'<failure type={quoteattr(f["severity"])} message={quoteattr(f["title"])}>{escape(f["title"] + ((chr(10) + f["detail"]) if f.get("detail") else ""))}</failure>'
            failures += 1
        else:
            body, skipped = f'<skipped message={quoteattr(f["severity"] + ": " + f["title"])}/>', skipped + 1
        cases.append(f'<testcase classname={quoteattr("webcrawler." + f["kind"])} name={quoteattr(name[:300])}>{body}</testcase>')
    suite = (f'<testsuite name={quoteattr("WebCrawler " + start)} tests="{len(cases)}" failures="{failures}" errors="0" skipped="{skipped}" '
             f'timestamp={quoteattr(session.get("created", ""))}>{"".join(cases)}</testsuite>')
    return '<?xml version="1.0" encoding="UTF-8"?>\n<testsuites>' + suite + "</testsuites>\n"
