"""report.py: a self-contained HTML report (no scripts, no external files) from a crawl."""
from __future__ import annotations

import html
from collections import Counter
from datetime import datetime

import analysis

CSS = """
:root{color-scheme:dark light;--bg:#0b1020;--card:#121a30;--line:#25304f;--text:#e8eefc;--mut:#9aa8c7;--acc:#3fd1ff;--hi:#ff6b6b;--md:#ffb454;--lo:#ffe082;--ok:#43ffb1}
@media (prefers-color-scheme:light){:root{--bg:#f5f7fc;--card:#fff;--line:#d9e0f0;--text:#18203a;--mut:#56627f;--acc:#0a6ea8;--hi:#c62828;--md:#b26a00;--lo:#8a6d00;--ok:#13795b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,Segoe UI,Arial,sans-serif;padding:28px}
main{max-width:1100px;margin:0 auto}h1{margin:0 0 4px}h2{margin:30px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
.sub{color:var(--mut);margin:0 0 18px;word-break:break-all}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px;text-align:center}
.card b{display:block;font-size:26px}.card span{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
table{border-collapse:collapse;width:100%;font-size:13px;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{padding:7px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{color:var(--mut);font-weight:600}
td.u{font-family:ui-monospace,Consolas,monospace;word-break:break-all}
.sev{font-weight:700;text-transform:uppercase;font-size:11px;letter-spacing:.05em}.high{color:var(--hi)}.medium{color:var(--md)}.low{color:var(--lo)}.info,.none{color:var(--mut)}
.note{color:var(--mut);font-size:13px}
"""


def _e(x) -> str:
    return html.escape(str(x), quote=True)


def _table(head: list[str], rows: list[list[str]], classes: list[str] | None = None) -> str:
    out = ["<table><thead><tr>" + "".join(f"<th>{_e(h)}</th>" for h in head) + "</tr></thead><tbody>"]
    for r in rows:
        out.append("<tr>" + "".join(f'<td class="{(classes or [""] * len(r))[i]}">{c}</td>' for i, c in enumerate(r)) + "</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def _site_section(site: dict, accepted=None) -> list[str]:
    out = []
    fs = sorted([f for f in site.get("findings", []) if not (accepted and accepted.match(f["code"], f.get("where", "")))], key=lambda f: analysis.SEVERITIES.index(f["severity"]))
    if fs:
        out.append(_table(["Severity", "Finding", "Where"], [[f'<span class="sev {f["severity"]}">{f["severity"]}</span>', _e(f["title"] + (f": {f['detail']}" if f.get("detail") else "")), _e(f.get("where", ""))] for f in fs], ["", "", "u"]))
    tls = list(site.get("tls", {}).values())
    if tls:
        out.append("<h3>TLS</h3>" + _table(["Host", "Protocol", "Issuer", "Expires", "Trusted"],
                                            [[_e(t["host"]), _e(t.get("protocol", "")), _e(t.get("issuer", "")), _e(f"{t.get('not_after', '')} ({t['days_left']} days)" if t.get("days_left") is not None else ""),
                                              "yes" if t.get("verified") else _e("no: " + (t.get("verify_error") or t.get("unverified") or t.get("error") or "unknown"))] for t in tls]))
    tech = site.get("tech", [])
    if tech:
        out.append("<h3>Technologies</h3>" + _table(["Name", "Version", "Type", "Seen from"], [[_e(t["name"]), _e(t.get("version", "")), _e(t.get("category", "")), _e(t.get("evidence", ""))] for t in tech]))
    files = site.get("files", [])
    if files:
        out.append("<h3>Well-known files</h3>" + _table(["Path", "Result"], [[_e(f["path"]), ('<span class="sev ' + f["severity"] + '">exposed</span> ' + _e(f["title"])) if f["exposed"] and f["severity"] != "info"
                                                                          else ("found" if f["exposed"] else "not found")] for f in files], ["u", ""]))
    dns = site.get("dns") or {}
    if dns:
        rows = [["Name servers", ", ".join(dns.get("ns", [])) or "none found"], ["Mail servers (MX)", ", ".join(dns.get("mx", [])) or "none"],
                ["SPF", (dns.get("spf") or "none") + (f"  ({dns['spf_lookups']} DNS lookups)" if dns.get("spf_lookups") else "")], ["DMARC", dns.get("dmarc") or "none"],
                ["DKIM keys found", ", ".join(dns.get("dkim", [])) or "none at the common selector names"], ["MTA-STS", "yes" if dns.get("mta_sts") else "no"],
                ["TLS reporting", "yes" if dns.get("tls_rpt") else "no"], ["CAA", "; ".join(dns.get("caa", [])) or "none"], ["DNSSEC", "enabled" if dns.get("dnssec") else "not enabled"]]
        out.append(f"<h3>DNS and e-mail security: {_e(dns.get('domain', ''))}</h3>" + _table(["Record", "Value"], [[_e(a), _e(b)] for a, b in rows], ["", "u"])
                   + f"<p class=note>Read through {_e(dns.get('provider', ''))} ({_e(dns.get('queries', 0))} queries). DKIM selectors are guessed from common names, so 'none' is not proof.</p>")
    seeds = site.get("seeds") or {}
    if seeds:
        r = seeds.get("robots", {})
        out.append(f"<p class=note>Sitemaps read: {_e(len(seeds.get('sitemaps', [])))}; pages they list: {_e(seeds.get('pages', 0))}; robots.txt Disallow entries: {_e(len(r.get('disallow', [])))}.</p>")
    return out or ["<p class=note>No site-wide checks were run or nothing was found.</p>"]


def _inputs_section(site: dict) -> list[str]:
    """Where the site takes input (forms, query parameters) and the subdomains it refers to."""
    out = []
    forms = site.get("forms", [])
    if forms:
        rows = []
        for f in sorted(forms, key=lambda f: (not f.get("password"), f.get("action", ""))):
            notes = [n for n, on in (("password", f.get("password")), ("file upload", f.get("upload")), ("search", f.get("search")), ("sends to another site", f.get("cross_origin")),
                                     ("no CSRF token seen", f.get("method") == "post" and not f.get("csrf") and not f.get("search")
                                      and any(x["type"] not in ("hidden", "submit", "button") for x in f.get("fields", [])))) if on]
            rows.append([_e(f.get("method", "get").upper()), _e(f.get("action", "")), _e(", ".join(x["name"] or "(" + x["type"] + ")" for x in f.get("fields", [])[:12])),
                         _e(", ".join(notes)), _e(f.get("page", ""))])
        out.append("<h3>Forms</h3>" + _table(["Method", "Sends to", "Fields", "Notes", "Found on"], rows, ["", "u", "", "", "u"]))
    params = site.get("params", {})
    if params:
        rows = [[_e("?" + k), _e(v["count"]), _e(v["examples"][0] if v.get("examples") else "")] for k, v in sorted(params.items(), key=lambda kv: -kv[1]["count"])[:150]]
        out.append("<h3>Query parameters</h3>" + _table(["Parameter", "URLs", "Example"], rows, ["u", "", "u"]))
    hosts = site.get("hosts", {})
    if hosts:
        rows = [[_e(h), _e(", ".join(e.get("addresses") or []) if e.get("addresses") else ("does not resolve" if e.get("addresses") == [] else "not looked up")), _e(", ".join(e.get("sources", [])))]
                for h, e in sorted(hosts.items())]
        out.append("<h3>Subdomains the site refers to</h3>" + _table(["Host", "Resolves to", "Seen in"], rows, ["u", "", ""]))
    if out:
        out.append("<p class=note>Read from the pages themselves. Nothing was submitted: testing what these inputs do with hostile data is active testing and needs the owner's permission.</p>")
    return out


_DIFF_TITLES = None


def build_diff_html(diff) -> str:
    """A self-contained report of what changed between two crawls."""
    import snapshot
    sec = diff.by_section()
    cards = [("Regressions", len(diff.regressions())), ("New pages", len(sec.get("page-added", []))), ("Removed", len(sec.get("page-removed", []))),
             ("New problems", len(sec.get("risk-new", [])) + len(sec.get("site-new", []))), ("Fixed", len(sec.get("risk-resolved", [])) + len(sec.get("site-resolved", [])) + len(sec.get("header-improved", [])))]
    parts = [f"<!doctype html><html lang=en><head><meta charset=utf-8><title>WebCrawler: what changed</title><meta name=viewport content='width=device-width,initial-scale=1'><style>{CSS}</style></head><body><main>",
             "<h1>What changed</h1>", f"<p class=sub>{_e(diff.new.get('start') or diff.old.get('start'))}<br>{_e(diff.old.get('created', '?'))} &rarr; {_e(diff.new.get('created', '?'))}</p>",
             '<div class="cards">' + "".join(f'<div class="card"><b>{n}</b><span>{_e(t)}</span></div>' for t, n in cards) + "</div>"]
    if not diff.changes:
        parts.append("<p class=note>No differences between the two crawls.</p>")
    for key, title in snapshot.SECTIONS:
        items = sec.get(key, [])
        if not items:
            continue
        parts.append(f"<h2>{_e(title)} ({len(items)})</h2>")
        parts.append(_table(["Severity", "What", "Detail"], [[f'<span class="sev {c.severity}">{c.severity}</span>', _e(c.subject), _e(c.detail)] for c in items], ["", "u", ""]))
    if getattr(diff, "suppressed", 0):
        parts.append(f"<p class=note>{_e(diff.suppressed)} new finding(s) are accepted and were not counted as changes.</p>")
    parts.append("<p class=note>Differences are between what each crawl could see: a page missing from the newer crawl may have been out of its reach (depth, limits, login) rather than removed.</p></main></body></html>")
    return "".join(parts)


def _accepted_section(start: str, links: list, pages: list, broken: list, site: dict, accepted) -> list[str]:
    """What was left out of the counts above because it is accepted, with the reason, so nothing is hidden."""
    import snapshot
    from dataclasses import asdict
    session = {"start": start, "links": [asdict(l) for l in links], "broken": [list(b) for b in broken], "site": site,
               "pages": [{"url": p.url, "findings": [{"code": f.code, "severity": f.severity, "title": f.title, "detail": f.detail} for f in p.findings]} for p in pages]}
    _, done = accepted.split(snapshot.all_findings(session))
    rows = [[f'<span class="sev {f["severity"]}">{f["severity"]}</span>', _e(f["title"]), _e(f["where"]), _e(f.get("accepted_reason", "")), _e(f.get("accepted_until") or "no expiry")] for f in done[:500]]
    out = ["<h2>Accepted findings</h2>"]
    out.append(_table(["Severity", "Finding", "Where", "Why it is accepted", "Until"], rows, ["", "", "u", "", ""]) if rows else "<p class=note>None of the accepted findings occurred in this crawl.</p>")
    expired = [e for e in accepted.entries if accepted.is_expired(e)]
    if expired:
        out.append("<p class=note>Expired acceptances (these findings count again): " + _e(", ".join(f"{e['code']} until {e['expires']}" for e in expired[:20])) + ".</p>")
    return out if rows or expired else []


def build_html(start: str, links: list, pages: list | None = None, broken: list | None = None, graph_stats: dict | None = None, site: dict | None = None,
               accepted=None) -> str:
    pages = pages or []
    site = site or {}
    broken = broken or []
    scored = []
    for l in links:
        f = analysis.assess_link(l.href, l.kind, l.page)
        if accepted:
            f = [x for x in f if not accepted.match(x.code, l.href)]
        scored.append((analysis.risk_score(f), l, f))
    kinds = Counter(l.kind for l in links)
    risky = [t for t in scored if t[2] and t[0] >= 8]
    risky.sort(key=lambda t: -t[0])
    sev_total = Counter(f.severity for _, _, fs in scored for f in fs)
    for p in pages:
        for f in p.findings:
            if not (accepted and accepted.match(f.code, p.url)):
                sev_total[f.severity] += 1

    crawled = (graph_stats or {}).get("pages") or len(pages)
    cards = [("Links", len(links)), ("Internal", kinds["internal"] + kinds["anchor"]), ("External", kinds["external"]),
             ("Pages crawled", crawled), ("Broken", len(broken)), ("High", sev_total["high"]), ("Medium", sev_total["medium"]), ("Low", sev_total["low"])]
    parts = [f"<!doctype html><html lang=en><head><meta charset=utf-8><title>WebCrawler report</title><meta name=viewport content='width=device-width,initial-scale=1'><style>{CSS}</style></head><body><main>",
             "<h1>WebCrawler report</h1>", f"<p class=sub>{_e(start)} · generated {datetime.now():%Y-%m-%d %H:%M}</p>",
             '<div class="cards">' + "".join(f'<div class="card"><b>{n}</b><span>{_e(t)}</span></div>' for t, n in cards) + "</div>"]

    parts.append("<h2>Risky links</h2>")
    if risky:
        rows = []
        for score, l, fs in risky:
            fs_sorted = sorted(fs, key=lambda f: analysis.SEVERITIES.index(f.severity))
            rows.append([f'<span class="sev {analysis.rating(score)}">{analysis.rating(score)}</span> {score}', _e(l.href),
                         "<br>".join(f'<span class="sev {f.severity}">{f.severity}</span> {_e(f.title)}' for f in fs_sorted), _e(l.page)])
        parts.append(_table(["Risk", "Link", "Why", "Found on"], rows, ["", "u", "", "u"]))
    else:
        parts.append("<p class=note>No link scored above informational.</p>")

    parts.append("<h2>Broken links and pages</h2>")
    if broken:
        parts.append(_table(["Status", "URL", "Reason", "Linked from"], [[_e(s if s else "no answer"), _e(u), _e(reason), _e(ref)] for u, s, ref, reason in broken], ["", "u", "", "u"]))
    else:
        parts.append("<p class=note>No broken links were found in what was crawled.</p>")

    parts.append("<h2>Site-wide checks</h2>")
    parts.extend(_site_section(site, accepted))
    ins = _inputs_section(site)
    if ins:
        parts.append("<h2>Where the site accepts input</h2>")
        parts.extend(ins)

    parts.append("<h2>Page security headers</h2>")
    if pages:
        rows = []
        for p in pages:
            fs = sorted([f for f in p.findings if not (accepted and accepted.match(f.code, p.url))], key=lambda f: analysis.SEVERITIES.index(f.severity))
            rows.append([_e(p.url), _e(p.status), "<br>".join(f'<span class="sev {f.severity}">{f.severity}</span> {_e(f.title)}' for f in fs) or '<span class="sev none">no issues found</span>'])
        parts.append(_table(["Page", "Status", "Findings"], rows, ["u", "", ""]))
    else:
        parts.append("<p class=note>No page responses were recorded for this crawl.</p>")

    if accepted:
        parts.extend(_accepted_section(start, links, pages, broken, site, accepted))
    parts.append("<h2>All links</h2>")
    rows = [[_e(l.n), _e(l.kind), _e(l.href), _e(l.text), f'<span class="sev {analysis.rating(s)}">{analysis.rating(s)}</span>', _e(l.page)] for s, l, _ in scored]
    parts.append(_table(["#", "Type", "URL", "Text", "Risk", "Found on"], rows, ["", "", "u", "", "", "u"]))
    parts.append("<p class=note>Heuristic findings: each says 'worth a look', not 'vulnerable'. Only test systems you are authorised to test.</p></main></body></html>")
    return "".join(parts)
