"""snapshot.py: save a crawl, reopen it, resume it, and compare two of them.

A session file is plain JSON holding everything a crawl learned (links, pages and their findings, the site map, site-wide
checks) and, if the crawl was stopped early, the exact queue to carry on from. Credentials are never part of it.

    data = build(...)          # from live objects
    save(path, data); data = load(path)
    restore(data, ...)         # back into live objects
    d = diff(old, new)         # what changed between two crawls: d.to_text(), d.regressions()
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import analysis
import content
import frontier as fr

FORMAT = "webcrawler-session"
VERSION = 2
MAX_FILE = 300 * 1024 * 1024

# response-header findings: the ones that say "the site's hardening got worse" when they appear
HEADER_CODES = {"no-https", "no-hsts", "short-hsts", "no-csp", "weak-csp", "no-frame-protection", "no-nosniff", "no-referrer-policy",
                "no-permissions-policy", "server-version", "x-powered-by", "cors-wildcard-creds", "cors-wildcard",
                "cookie-no-secure", "cookie-no-httponly", "cookie-no-samesite"}
TRACKED_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy")
# the finding that already says "this header is missing", so a removed header is not reported twice
HEADER_FINDING = {"strict-transport-security": "no-hsts", "content-security-policy": "no-csp", "x-frame-options": "no-frame-protection",
                  "x-content-type-options": "no-nosniff", "referrer-policy": "no-referrer-policy", "permissions-policy": "no-permissions-policy"}


# ============================================================================ build / save / load / restore

def _finding(f: analysis.Finding) -> dict:
    return {"code": f.code, "severity": f.severity, "title": f.title, "detail": f.detail}


def build(start: str, opts, store, graph, security: dict, broken: list, site, resume: dict | None = None) -> dict:
    """A session as plain data. `opts` is a CrawlOptions; `security` maps URL -> PageSecurity; `site` is a checks.SiteInfo."""
    o = asdict(opts)
    return {
        "format": FORMAT, "version": VERSION, "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "start": start, "options": o,
        "links": [asdict(l) for l in store.all()],
        "pages": [{"url": p.url, "status": p.status, "findings": [_finding(f) for f in p.findings], "headers": dict(p.headers)} for p in security.values()],
        "broken": [list(b) for b in broken],
        "graph": graph.to_state(),
        "site": site.to_dict() if site is not None else {},
        "resume": resume,
    }


def save(path: str, data: dict) -> None:
    """Write atomically, so a crash or a full disk never leaves a half-written session behind."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=p.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, separators=(",", ":"))
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load(path: str) -> dict:
    p = Path(path).expanduser()
    if p.stat().st_size > MAX_FILE:
        raise ValueError("that file is too large to be a session")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"not a session file: {e}")
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise ValueError("not a WebCrawler session file")
    if int(data.get("version", 0)) > VERSION:
        raise ValueError(f"this session was saved by a newer version (format {data.get('version')}); update the tool to open it")
    for key in ("links", "pages", "broken"):
        data.setdefault(key, [])
    data.setdefault("graph", {})
    data.setdefault("site", {})
    data.setdefault("resume", None)
    return data


def restore(data: dict, store, graph, security: dict, site) -> tuple[list, dict | None]:
    """Load a session into live objects. Returns (broken list, resume state or None)."""
    store.load(data.get("links", []))
    graph.load_state(data.get("graph", {}))
    security.clear()
    for p in data.get("pages", []):
        security[p["url"]] = analysis.PageSecurity(p["url"], p.get("status", 0),
                                                   [analysis.Finding(f["code"], f["severity"], f["title"], f.get("detail", "")) for f in p.get("findings", [])], dict(p.get("headers", {})))
    if site is not None:
        site.load(data.get("site", {}))
    return [tuple(b) for b in data.get("broken", [])], data.get("resume")


def options_from(data: dict) -> fr.CrawlOptions:
    """CrawlOptions saved with a session, ignoring any fields this version does not know."""
    known = {f for f in fr.CrawlOptions.__dataclass_fields__}
    return fr.CrawlOptions(**{k: v for k, v in data.get("options", {}).items() if k in known}).clamped()


# ============================================================================ comparing two sessions

@dataclass
class Change:
    section: str
    subject: str
    detail: str = ""
    severity: str = "info"
    code: str = ""              # the finding this is about, if it is about one
    count: int = 1              # how many separate findings it stands for (see _group)


SECTIONS = [
    ("risk-new", "New problems"), ("header-weaker", "Hardening got weaker"), ("site-new", "New site-wide problems"), ("script-new", "New third-party scripts"),
    ("status-changed", "Pages that changed status"), ("page-changed", "Pages whose content changed"),
    ("page-added", "New pages"), ("page-removed", "Pages that disappeared"), ("link-added", "New links"), ("link-removed", "Links that disappeared"),
    ("tech-changed", "Technology changes"), ("tls-changed", "Certificate / TLS changes"), ("dns-changed", "DNS and e-mail record changes"),
    ("input-new", "New places that accept input"), ("input-removed", "Inputs that disappeared"), ("host-changed", "Subdomain changes"),
    ("risk-resolved", "Problems fixed"), ("header-improved", "Hardening improved"), ("site-resolved", "Site-wide problems fixed"),
]
REGRESSION_SECTIONS = {"risk-new", "header-weaker", "site-new", "status-changed", "dns-changed", "script-new"}
GROUP_AT = 6        # this many pages with the same new/fixed finding are reported as one line
SEV_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class Diff:
    old: dict = field(default_factory=dict)
    new: dict = field(default_factory=dict)
    changes: list = field(default_factory=list)
    suppressed: int = 0         # new findings left out because they are accepted (accepted.py)

    def by_section(self) -> dict:
        out: dict = {}
        for c in self.changes:
            out.setdefault(c.section, []).append(c)
        for v in out.values():
            v.sort(key=lambda c: (SEV_RANK.get(c.severity, 9), c.subject))
        return out

    def regressions(self, level: str = "medium") -> list:
        """Changes that made things worse: new problems at `level` or above, weaker headers, pages that started failing."""
        limit = SEV_RANK[level]
        return [c for c in self.changes if c.section in REGRESSION_SECTIONS and SEV_RANK.get(c.severity, 9) <= limit]

    def counts(self) -> dict:
        s = self.by_section()
        return {k: len(s.get(k, [])) for k, _ in SECTIONS}

    def summary(self) -> str:
        c = self.counts()
        reg = len(self.regressions())
        parts = [f"{reg} regression(s)", f"{c['page-added']} new page(s)", f"{c['page-removed']} removed", f"{c['risk-new'] + c['site-new']} new problem(s)",
                 f"{c['risk-resolved'] + c['site-resolved'] + c['header-improved']} fixed"]
        if self.suppressed:
            parts.append(f"{self.suppressed} accepted finding(s) not counted")
        return ", ".join(parts)

    def to_dict(self) -> dict:
        return {"old": self.old, "new": self.new, "summary": self.summary(), "suppressed": self.suppressed, "changes": [asdict(c) for c in self.changes]}

    def to_text(self, limit: int = 0) -> str:
        sec = self.by_section()
        lines = [f"Comparing  {self.old.get('created', '?')}  ->  {self.new.get('created', '?')}", f"Start: {self.new.get('start') or self.old.get('start')}", self.summary(), ""]
        for key, title in SECTIONS:
            items = sec.get(key, [])
            if not items:
                continue
            lines.append(f"{title} ({len(items)})")
            for c in items[:limit or None]:
                mark = {"high": "[HIGH]  ", "medium": "[MEDIUM]", "low": "[LOW]   "}.get(c.severity, "        ")
                lines.append(f"  {mark} {c.subject}" + (f"  {c.detail}" if c.detail else ""))
            if limit and len(items) > limit:
                lines.append(f"  ... and {len(items) - limit} more")
            lines.append("")
        if not self.changes:
            lines.append("No differences.")
        return "\n".join(lines).rstrip() + "\n"


def _meta(d: dict) -> dict:
    return {"created": d.get("created", ""), "start": d.get("start", ""), "links": len(d.get("links", [])), "pages": len(d.get("pages", []))}


def _norm(u: str) -> str:
    return fr.normalize(u)


def _pages(d: dict) -> dict[str, dict]:
    src = set(d.get("graph", {}).get("sources", []))
    return {_norm(n["url"]): n for n in d.get("graph", {}).get("nodes", [])
            if n.get("visited") and n.get("kind") == "page" and n["url"] not in src and not (n.get("status") is not None and 300 <= n["status"] < 400)}


def _link_findings(d: dict) -> tuple[dict, dict]:
    links, found = {}, {}
    for l in d.get("links", []):
        links[l["href"]] = l
        for f in analysis.assess_link(l["href"], l.get("kind", "other"), l.get("page", "")):
            if f.severity != "info":
                found[(l["href"], f.code)] = f
    return links, found


def _page_findings(d: dict) -> tuple[dict, dict]:
    pages, found = {}, {}
    for p in d.get("pages", []):
        u = _norm(p["url"])
        pages[u] = p
        for f in p.get("findings", []):
            if f.get("severity") != "info":
                found[(u, f["code"])] = f
    return pages, found


def _hsts_age(v: str) -> int:
    import re
    m = re.search(r"max-age=(\d+)", v or "", re.I)
    return int(m.group(1)) if m else 0


def all_findings(d: dict) -> list[dict]:
    """Every finding in a session as plain dicts {code, severity, title, detail, where, kind}: link findings are recomputed from the links
    (they are not stored), page and site findings are read as saved, and broken links are included."""
    import checks
    out = []
    start_host = urlparse(d.get("start", "")).hostname or ""
    for l in d.get("links", []):
        for f in analysis.assess_link(l["href"], l.get("kind", "other"), l.get("page", "")):
            out.append({"code": f.code, "severity": f.severity, "title": f.title, "detail": f.detail, "where": l["href"], "kind": "link", "page": l.get("page", "")})
    for p in d.get("pages", []):
        for f in p.get("findings", []):
            out.append({"code": f["code"], "severity": f["severity"], "title": f["title"], "detail": f.get("detail", ""), "where": p["url"], "kind": "page"})
    for f in d.get("site", {}).get("findings", []):
        out.append({"code": f["code"], "severity": f["severity"], "title": f["title"], "detail": f.get("detail", ""), "where": f.get("where", ""), "kind": "site"})
    for b in d.get("broken", []):
        url, status, ref, reason = (list(b) + ["", "", "", ""])[:4]
        internal = not ref or checks.related(urlparse(url).hostname or "", start_host)
        out.append({"code": "broken", "severity": "medium" if internal else "low", "title": f"Broken link: {reason}", "detail": ref, "where": url, "kind": "broken", "page": ref})
    return out


def _group(changes: list) -> list:
    """The same finding on many pages (a header missing everywhere) becomes one line instead of hundreds."""
    buckets: dict = {}
    for c in changes:
        if c.code and c.section in ("risk-new", "header-weaker", "risk-resolved", "header-improved"):
            buckets.setdefault((c.section, c.code, c.severity, c.detail), []).append(c)
    drop = set()
    grouped = []
    for (section, code, sev, detail), items in buckets.items():
        if len(items) >= GROUP_AT:
            drop.update(id(i) for i in items)
            e = ", ".join(i.subject for i in items[:3])
            grouped.append(Change(section, f"{len(items)} places", f"{detail}  (e.g. {e})", sev, code, len(items)))
    return [c for c in changes if id(c) not in drop] + grouped


def diff(old: dict, new: dict, accepted=None) -> Diff:
    """What changed from `old` to `new`. Findings covered by `accepted` (an accepted.Accepted) are not reported as new."""
    out = Diff(_meta(old), _meta(new))

    def add(section, subject, detail="", sev="info", code=""):
        if accepted and code and section in ("risk-new", "header-weaker", "site-new"):
            if accepted.match(code, subject):
                out.suppressed += 1
                return
        out.changes.append(Change(section, subject, detail, sev, code))

    # ---- pages and their status
    op, np_ = _pages(old), _pages(new)
    for u in sorted(np_.keys() - op.keys()):
        add("page-added", u, f"status {np_[u].get('status')}" if np_[u].get("status") is not None else "")
    for u in sorted(op.keys() - np_.keys()):
        add("page-removed", u, f"was status {op[u].get('status')}" if op[u].get("status") is not None else "")
    for u in sorted(op.keys() & np_.keys()):
        a, b = op[u].get("status"), np_[u].get("status")
        if a is not None and b is not None and a != b:
            def broken(x):
                return x == 0 or (x >= 400 and x not in (401, 403))     # asking for a login is not "broken"
            add("status-changed", u, f"{a} -> {b}", "medium" if broken(b) and not broken(a) else "info")

    # ---- links and their findings
    ol, of = _link_findings(old)
    nl, nf = _link_findings(new)
    for h in sorted(nl.keys() - ol.keys()):
        add("link-added", h, f"{nl[h].get('kind')}, found on {nl[h].get('page')}")
    for h in sorted(ol.keys() - nl.keys()):
        add("link-removed", h, f"{ol[h].get('kind')}")
    for key in sorted(nf.keys() - of.keys()):
        f = nf[key]
        add("risk-new", key[0], f.title, f.severity, key[1])
    for key in sorted(of.keys() - nf.keys()):
        if key[0] in nl:  # a link that disappeared is reported as removed, not as "fixed"
            add("risk-resolved", key[0], of[key].title, of[key].severity, key[1])

    # ---- page headers and markup
    opg, opf = _page_findings(old)
    npg, npf = _page_findings(new)
    for key in sorted(npf.keys() - opf.keys()):
        f = npf[key]
        add("header-weaker" if f["code"] in HEADER_CODES and key[0] in opg else "risk-new", key[0], f["title"], f["severity"], f["code"])
    for key in sorted(opf.keys() - npf.keys()):
        if key[0] in npg:
            f = opf[key]
            add("header-improved" if f["code"] in HEADER_CODES else "risk-resolved", key[0], f["title"], f["severity"], f["code"])
    for u in sorted(opg.keys() & npg.keys()):
        oh, nh = opg[u].get("headers", {}), npg[u].get("headers", {})
        for h in TRACKED_HEADERS:
            if h in oh and h not in nh and (u, HEADER_FINDING[h]) not in npf:
                add("header-weaker", u, f"{h} was removed", "medium", HEADER_FINDING[h])
        if _hsts_age(nh.get("strict-transport-security", "")) < _hsts_age(oh.get("strict-transport-security", "")) and "strict-transport-security" in nh:
            add("header-weaker", u, f"HSTS max-age lowered ({_hsts_age(oh['strict-transport-security'])} -> {_hsts_age(nh['strict-transport-security'])})", "low")

    # ---- technologies, site-wide findings, TLS
    ot = {(t["name"], t.get("version", "")): t for t in old.get("site", {}).get("tech", [])}
    nt = {(t["name"], t.get("version", "")): t for t in new.get("site", {}).get("tech", [])}
    old_names = {n for n, _ in ot}
    from checks import Tech, tech_findings
    for (name, ver) in sorted(nt.keys() - ot.keys()):
        bad = tech_findings([Tech(name, ver)])
        verb = "version changed" if name in old_names else "appeared"
        add("tech-changed", f"{name} {ver}".strip(), verb + (f": {bad[0].title}" if bad else ""), bad[0].severity if bad else "info")
    for (name, ver) in sorted(ot.keys() - nt.keys()):
        if name not in {n for n, _ in nt}:
            add("tech-changed", f"{name} {ver}".strip(), "no longer detected")
    osf = {(f["code"], f.get("where", "")): f for f in old.get("site", {}).get("findings", []) if f["severity"] != "info"}
    nsf = {(f["code"], f.get("where", "")): f for f in new.get("site", {}).get("findings", []) if f["severity"] != "info"}
    for key in sorted(nsf.keys() - osf.keys()):
        add("site-new", key[1] or key[0], nsf[key]["title"], nsf[key]["severity"], key[0])
    for key in sorted(osf.keys() - nsf.keys()):
        add("site-resolved", key[1] or key[0], osf[key]["title"], osf[key]["severity"])
    otl, ntl = old.get("site", {}).get("tls", {}), new.get("site", {}).get("tls", {})
    for host in sorted(otl.keys() & ntl.keys()):
        a, b = otl[host], ntl[host]
        if a.get("issuer") != b.get("issuer") and (a.get("issuer") or b.get("issuer")):
            add("tls-changed", host, f"issuer {a.get('issuer') or '?'} -> {b.get('issuer') or '?'}")
        if a.get("protocol") != b.get("protocol") and (a.get("protocol") or b.get("protocol")):
            add("tls-changed", host, f"protocol {a.get('protocol') or '?'} -> {b.get('protocol') or '?'}")
        if a.get("days_left") is not None and b.get("days_left") is not None and b["days_left"] > a["days_left"] + 30:
            add("tls-changed", host, f"certificate renewed (expires {b.get('not_after')})")
    _diff_inputs(old.get("site", {}), new.get("site", {}), add)

    # ---- the pages' own text, and who else's code they load
    for u in sorted(op.keys() & np_.keys()):
        a, b = op[u], np_[u]
        if a.get("fp") is None or b.get("fp") is None or bool(a.get("rendered")) != bool(b.get("rendered")):
            continue        # not measured in one of the crawls, or measured differently (with and without running the page's JavaScript)
        if (a.get("status") or 0) >= 400 or (b.get("status") or 0) >= 400:
            continue        # an error page's text is the error page's text; the status change says it already
        msg = content.compare(a["fp"], a.get("words", 0), b["fp"], b.get("words", 0))
        if msg:
            add("page-changed", u, msg, "low" if "largely" in msg else "info")
    os_, ns = old.get("site", {}).get("scripts"), new.get("site", {}).get("scripts")
    if os_ is not None and ns is not None:
        for host in sorted(ns.keys() - os_.keys()):
            e = ns[host]
            more = f" (and {e['count'] - 1} more)" if e.get("count", 1) > 1 else ""
            add("script-new", host, f"a script is now loaded from this other site by {(e.get('pages') or ['?'])[0]}{more}", "medium")
    out.changes = _group(out.changes)
    return out


def _form_key(f: dict) -> tuple:
    return (f.get("action", ""), f.get("method", "get"), tuple(sorted(x["name"] for x in f.get("fields", []))))


def _diff_inputs(old: dict, new: dict, add) -> None:
    """Forms, query parameters, subdomains and DNS records. A session saved before these were collected has no such keys and is not compared
    (everything would look new)."""
    if "forms" in old and "forms" in new:
        of, nf = {_form_key(f): f for f in old["forms"]}, {_form_key(f): f for f in new["forms"]}
        for k in sorted(nf.keys() - of.keys()):
            f = nf[k]
            traits = [t for t, on in (("password", f.get("password")), ("file upload", f.get("upload")), ("sends to another site", f.get("cross_origin"))) if on]
            add("input-new", f"{f.get('method', 'get').upper()} {f.get('action', '')}", "form on " + f.get("page", "") + (" (" + ", ".join(traits) + ")" if traits else ""),
                "low" if traits else "info")
        for k in sorted(of.keys() - nf.keys()):
            add("input-removed", f"{of[k].get('method', 'get').upper()} {of[k].get('action', '')}", "form on " + of[k].get("page", ""))
    if "params" in old and "params" in new:
        for name in sorted(new["params"].keys() - old["params"].keys()):
            add("input-new", "?" + name, f"query parameter, {new['params'][name]['count']} URL(s)")
        for name in sorted(old["params"].keys() - new["params"].keys()):
            add("input-removed", "?" + name, "query parameter")
    if "hosts" in old and "hosts" in new:
        for h in sorted(new["hosts"].keys() - old["hosts"].keys()):
            add("host-changed", h, "new subdomain referenced")
        for h in sorted(old["hosts"].keys() - new["hosts"].keys()):
            add("host-changed", h, "no longer referenced")
    od, nd = old.get("dns") or {}, new.get("dns") or {}
    if od and nd and od.get("domain") == nd.get("domain"):
        dom = nd["domain"]
        for key, label in (("ns", "name servers"), ("mx", "mail servers")):
            if set(od.get(key, [])) != set(nd.get(key, [])):
                add("dns-changed", dom, f"{label}: {', '.join(od.get(key, [])) or 'none'} -> {', '.join(nd.get(key, [])) or 'none'}", "medium")
        for key, label in (("spf", "SPF"), ("dmarc", "DMARC")):
            if od.get(key, "") != nd.get(key, ""):
                add("dns-changed", dom, f"{label} changed: {(od.get(key) or 'none')[:80]} -> {(nd.get(key) or 'none')[:80]}")
        if od.get("dnssec") and not nd.get("dnssec"):
            add("dns-changed", dom, "DNSSEC was turned off", "medium")
        if od.get("mta_sts") and not nd.get("mta_sts"):
            add("dns-changed", dom, "MTA-STS policy is gone", "low")
        if set(od.get("caa", [])) != set(nd.get("caa", [])):
            add("dns-changed", dom, "CAA records changed")
