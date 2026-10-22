"""dnscheck.py: what a domain's DNS says about its e-mail and name security.

SPF, DKIM, DMARC, MTA-STS, TLS-RPT, CAA and DNSSEC, read through DNS-over-HTTPS (a DNS query carried in an HTTPS request, so it
needs nothing but the HTTP client the rest of the tool already has). This is opt-in: the queries go to a public resolver
(Cloudflare by default; --doh picks another), which therefore learns the domain being checked. Names that only exist on a
private network are never sent there (checks.is_public_host).

Every check is a read of public DNS records; nothing is sent to the site's mail servers.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import quote

import checks
from analysis import Finding

DEFAULT_DOH = "https://cloudflare-dns.com/dns-query"
RTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257, "DS": 43, "DNSKEY": 48}
DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2", "smtp", "mandrill", "zoho", "mxvault")


class Doh:
    """A DNS-over-HTTPS resolver. query() never raises."""

    def __init__(self, url: str = DEFAULT_DOH, client=None, timeout: float = 6.0, user_agent: str = "WebCrawler/2.0") -> None:
        import httpclient
        self.url = url
        self.client = client or httpclient.Client(user_agent, timeout, True, max_idle=2)
        self.own = client is None
        self.queries = 0

    def close(self) -> None:
        if self.own:
            self.client.close()

    def query(self, name: str, rtype: str) -> dict:
        """{"status": DNS rcode (0 = fine, 3 = no such name), "ad": DNSSEC-validated, "answers": [{"type", "data"}], "error": str}"""
        self.queries += 1
        sep = "&" if "?" in self.url else "?"
        r = self.client.get(f"{self.url}{sep}name={quote(name)}&type={rtype}", {"Accept": "application/dns-json"}, max_body=256 * 1024)
        if r.error or r.status != 200:
            return {"status": -1, "ad": False, "answers": [], "error": r.error or f"HTTP {r.status}"}
        try:
            d = json.loads(r.body.decode("utf-8", "replace"))
        except ValueError:
            return {"status": -1, "ad": False, "answers": [], "error": "the resolver did not answer in JSON"}
        return {"status": int(d.get("Status", -1)), "ad": bool(d.get("AD")),
                "answers": [{"type": int(a.get("type", 0)), "data": str(a.get("data", ""))} for a in d.get("Answer", []) if isinstance(a, dict)], "error": ""}

    def txt(self, name: str) -> list[str]:
        out = []
        for a in self.query(name, "TXT")["answers"]:
            if a["type"] == RTYPES["TXT"]:
                out.append(unquote_txt(a["data"]))
        return out


def unquote_txt(data: str) -> str:
    """A TXT answer comes quoted, in pieces of up to 255 characters: "v=spf1 ..." "...more" -> v=spf1 ...more"""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    return "".join(re.sub(r"\\(.)", r"\1", p) for p in parts) if parts else data.strip()


# ------------------------------------------------------------------------------------------------ SPF

def parse_spf(record: str) -> dict:
    """The parts of an SPF record that matter: how it ends, which mechanisms cost DNS lookups."""
    terms = record.split()[1:]
    out = {"all": "", "lookups": [], "ptr": False, "redirect": "", "includes": []}
    for t in terms:
        q = t[0] if t[0] in "+-~?" else "+"
        m = t.lstrip("+-~?")
        low = m.lower()
        if low == "all":
            out["all"] = {"+": "+all", "-": "-all", "~": "~all", "?": "?all"}[q]
        elif low.startswith("include:"):
            out["includes"].append(m[8:])
            out["lookups"].append(m)
        elif low.startswith("redirect="):
            out["redirect"] = m[9:]
            out["lookups"].append(m)
        elif low.split(":")[0].split("/")[0] in ("a", "mx", "exists"):
            out["lookups"].append(m)
        elif low.split(":")[0] == "ptr":
            out["ptr"] = True
            out["lookups"].append(m)
    return out


def count_spf_lookups(record: str, doh: Doh, budget: list, depth: int = 0) -> int:
    """DNS lookups an SPF evaluation costs, following include: and redirect= (the standard's limit is 10). budget is a one-item list of
    DNS queries this function may still spend; if it runs out the count so far is returned."""
    p = parse_spf(record)
    total = len(p["lookups"])
    if depth >= 5:
        return total
    for target in p["includes"] + ([p["redirect"]] if p["redirect"] else []):
        if budget[0] <= 0:
            break
        budget[0] -= 1
        for txt in doh.txt(target):
            if txt.lower().startswith("v=spf1"):
                total += count_spf_lookups(txt, doh, budget, depth + 1)
                break
    return total


def parse_dmarc(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            tags[k.strip().lower()] = v.strip()
    return tags


# ------------------------------------------------------------------------------------------------ the check

@dataclass
class DnsReport:
    domain: str
    provider: str = DEFAULT_DOH
    ns: list = field(default_factory=list)
    mx: list = field(default_factory=list)
    spf: str = ""
    spf_lookups: int = 0
    dmarc: str = ""
    dkim: list = field(default_factory=list)
    mta_sts: bool = False
    tls_rpt: bool = False
    caa: list = field(default_factory=list)
    dnssec: bool = False
    queries: int = 0
    errors: list = field(default_factory=list)
    findings: list = field(default_factory=list)       # [Finding]

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in ("domain", "provider", "ns", "mx", "spf", "spf_lookups", "dmarc", "dkim", "mta_sts", "tls_rpt", "caa", "dnssec", "queries", "errors")}


def check_domain(domain: str, doh: Doh, dkim_selectors=DKIM_SELECTORS) -> DnsReport:
    """Read the e-mail and name-security records of `domain` and say what is missing or weak."""
    rep = DnsReport(domain, doh.url)
    add = rep.findings.append
    ns = doh.query(domain, "NS")
    if ns["status"] < 0:
        rep.errors.append("DNS lookup failed: " + ns["error"])
        rep.queries = doh.queries
        return rep
    rep.ns = sorted({a["data"].rstrip(".") for a in ns["answers"] if a["type"] == RTYPES["NS"]})
    mx = doh.query(domain, "MX")
    rep.mx = sorted({a["data"].split(None, 1)[-1].rstrip(".").lower() for a in mx["answers"] if a["type"] == RTYPES["MX"]})
    null_mx = rep.mx == [""] or rep.mx == ["."]
    sends_mail = bool(rep.mx) and not null_mx

    # ---- SPF
    spfs = [t for t in doh.txt(domain) if t.lower().startswith("v=spf1")]
    rep.spf = spfs[0] if spfs else ""
    if len(spfs) > 1:
        add(Finding("email-spf-multiple", "medium", "More than one SPF record", f"{domain} publishes {len(spfs)} v=spf1 records; receivers treat that as an error and ignore SPF."))
    if not spfs:
        if sends_mail:
            add(Finding("email-no-spf", "medium", "No SPF record", f"{domain} receives mail but publishes no SPF record, so anyone can send mail claiming to be from it."))
        else:
            add(Finding("email-no-spf", "low", "No SPF record", f"{domain} does not appear to handle mail; a record of `v=spf1 -all` states that and stops spoofing."))
    else:
        p = parse_spf(rep.spf)
        if p["all"] == "+all":
            add(Finding("email-spf-permissive", "high", "SPF allows any server to send mail (+all)", rep.spf[:160]))
        elif p["all"] == "?all":
            add(Finding("email-spf-permissive", "medium", "SPF ends in ?all (neutral): it does not tell receivers to reject anything", rep.spf[:160]))
        elif not p["all"] and not p["redirect"]:
            add(Finding("email-spf-permissive", "medium", "SPF has no closing all mechanism", "Senders that match nothing are not told to fail. " + rep.spf[:120]))
        elif p["all"] == "~all":
            add(Finding("email-spf-softfail", "info", "SPF ends in ~all (soft fail)", "Acceptable alongside an enforcing DMARC policy."))
        if p["ptr"]:
            add(Finding("email-spf-ptr", "low", "SPF uses the deprecated ptr mechanism", "It is slow, unreliable and discouraged by the standard."))
        rep.spf_lookups = count_spf_lookups(rep.spf, doh, [12])
        if rep.spf_lookups > 10:
            add(Finding("email-spf-lookups", "medium", f"SPF needs {rep.spf_lookups} DNS lookups (the limit is 10)", "Over the limit, SPF evaluation fails with a permanent error and is ignored."))

    # ---- DMARC (the organisational domain's policy applies to its subdomains too)
    dm = [t for t in doh.txt("_dmarc." + domain) if t.lower().startswith("v=dmarc1")]
    rep.dmarc = dm[0] if dm else ""
    if not dm:
        add(Finding("email-no-dmarc", "medium" if sends_mail else "low", "No DMARC record",
                    f"Without DMARC, receivers have no instruction on what to do with mail that fails SPF and DKIM for {domain}."))
    else:
        t = parse_dmarc(rep.dmarc)
        pol = t.get("p", "").lower()
        if pol == "none":
            add(Finding("email-dmarc-none", "low", "DMARC policy is p=none (monitoring only)", "Spoofed mail is reported but still delivered."))
        elif pol not in ("quarantine", "reject"):
            add(Finding("email-dmarc-invalid", "medium", "DMARC record has no valid p= policy", rep.dmarc[:120]))
        if pol in ("quarantine", "reject") and t.get("pct", "100").isdigit() and int(t.get("pct", "100")) < 100:
            add(Finding("email-dmarc-partial", "low", f"DMARC applies to only {t['pct']}% of mail (pct={t['pct']})", "The rest is treated as if the policy were p=none."))
        if pol in ("quarantine", "reject") and t.get("sp", "").lower() == "none":
            add(Finding("email-dmarc-subdomains", "low", "DMARC leaves subdomains unprotected (sp=none)", "Spoofing from a subdomain is not blocked."))
        if "rua" not in t:
            add(Finding("email-dmarc-no-rua", "info", "DMARC has no aggregate report address (rua=)", "Without reports you cannot see who is sending mail as this domain."))

    # ---- DKIM: the selector is not discoverable, so a few common ones are tried
    for sel in dkim_selectors if sends_mail or rep.spf else ():
        rec = [t for t in doh.txt(f"{sel}._domainkey.{domain}") if "v=dkim1" in t.lower() or "k=rsa" in t.lower() or "p=" in t.lower()]
        if rec:
            rep.dkim.append(sel)
    if (sends_mail or rep.spf) and not rep.dkim:
        add(Finding("email-no-dkim-found", "info", "No DKIM key found at the common selector names",
                    f"Tried {', '.join(dkim_selectors[:6])}... This does not prove DKIM is absent: the selector name is chosen by whoever sends the mail."))

    # ---- MTA-STS and TLS reporting (only meaningful for a domain that receives mail)
    rep.mta_sts = any(t.lower().startswith("v=stsv1") for t in doh.txt("_mta-sts." + domain))
    rep.tls_rpt = any(t.lower().startswith("v=tlsrptv1") for t in doh.txt("_smtp._tls." + domain))
    if sends_mail and not rep.mta_sts:
        add(Finding("email-no-mta-sts", "info", "No MTA-STS policy", "MTA-STS makes other mail servers insist on encrypted delivery to this domain."))

    # ---- CAA and DNSSEC
    caa = doh.query(domain, "CAA")
    rep.caa = sorted(a["data"] for a in caa["answers"] if a["type"] == RTYPES["CAA"])
    if not rep.caa and caa["status"] >= 0:
        add(Finding("dns-no-caa", "info", "No CAA record", "A CAA record limits which certificate authorities may issue certificates for the domain."))
    ds = doh.query(domain, "DS")
    rep.dnssec = any(a["type"] == RTYPES["DS"] for a in ds["answers"])
    if not rep.dnssec and ds["status"] >= 0:
        add(Finding("dns-no-dnssec", "info", "DNSSEC is not enabled", "Without it, DNS answers for the domain cannot be verified as genuine."))
    rep.queries = doh.queries
    return rep


# ------------------------------------------------------------------------------------------------ subdomains from certificate logs

CT_URL = "https://crt.sh/?q=%25.{domain}&output=json"
MAX_CT_NAMES = 500


def ct_subdomains(domain: str, url: str = CT_URL, client=None, timeout: float = 20.0, user_agent: str = "WebCrawler/2.0") -> tuple[list[str], str]:
    """Names under `domain` that certificates were ever issued for, from a public Certificate Transparency search (crt.sh). Returns
    (names, error). Passive: the site itself is not contacted, but the search service learns which domain is being looked at."""
    import httpclient
    if not checks.is_public_host(domain):
        return [], ""
    own = client is None
    if own:
        client = httpclient.Client(user_agent, timeout, True, max_idle=1)
    try:
        r = client.get(url.replace("{domain}", quote(domain)), {"Accept": "application/json"}, max_body=8 * 1024 * 1024)
    finally:
        if own:
            client.close()
    if r.error or r.status != 200:
        return [], r.error or f"HTTP {r.status}"
    try:
        rows = json.loads(r.body.decode("utf-8", "replace"))
    except ValueError:
        return [], "the certificate log search did not answer in JSON"
    names = set()
    for row in rows if isinstance(rows, list) else []:
        for n in str(row.get("name_value", "") if isinstance(row, dict) else "").splitlines():
            n = n.strip().lower().lstrip("*.").rstrip(".")
            if re.fullmatch(r"(?:[a-z0-9_-]+\.)+[a-z]{2,}", n) and checks.related(n, domain):
                names.add(n)
    return sorted(names)[:MAX_CT_NAMES], ""


def run(host: str, doh_url: str = DEFAULT_DOH, client=None, timeout: float = 6.0, user_agent: str = "WebCrawler/2.0") -> "DnsReport | None":
    """Check the registrable domain of `host`, or return None for a host that is not on the public internet (nothing is sent anywhere)."""
    if not checks.is_public_host(host):
        return None
    doh = Doh(doh_url, client, timeout, user_agent)
    try:
        return check_domain(checks.registrable(host), doh)
    finally:
        doh.close()
