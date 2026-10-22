"""analysis.py: security checks for crawled links and page response headers. Pure functions, no browser needed.

Links are scored for patterns that matter to a defender or a tester: downgrades to HTTP, raw-IP and punycode hosts,
URL shorteners, user@host tricks, open-redirect parameters, exposed admin/backup/VCS paths and executable downloads.
Response headers are checked against the usual hardening list (HSTS, CSP, clickjacking, MIME sniffing, cookies, CORS).
These are heuristics that say "worth a look", not proof of a vulnerability.
"""
from __future__ import annotations

import email.utils
import ipaddress
import re
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlparse

SEVERITIES = ("high", "medium", "low", "info")
SEV_SCORE = {"high": 40, "medium": 20, "low": 8, "info": 0}

SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
              "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "lnkd.in", "s.id"}
RISKY_TLDS = {"zip", "mov", "click", "top", "tk", "gq", "ml", "cf", "ga", "country", "kim", "work", "loan", "men"}
PASSWORD_PARAMS = {"password", "passwd", "pwd", "pass", "secret", "passphrase"}
TOKEN_PARAMS = {"token", "access_token", "refresh_token", "id_token", "auth", "authorization", "api_key", "apikey", "api-key", "sessionid", "session_id",
                "sessid", "phpsessid", "jsessionid", "sid", "sig", "signature", "x-amz-signature", "x-api-key"}
REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "redirect_url", "redir", "next", "return", "returnurl",
                   "return_to", "dest", "destination", "goto", "continue", "target", "forward"}
HIGH_PATH = re.compile(r"/(\.git|\.svn|\.hg|\.env|\.ds_store|\.htpasswd|\.aws|id_rsa|phpmyadmin|wp-config\.php)(/|$|\?|\.)", re.I)
ADMIN_PATH = re.compile(r"/(admin|administrator|wp-admin|manager|console|actuator|server-status|cpanel|dashboard|debug|swagger|graphql)(/|$|\?)", re.I)
LOGIN_PATH = re.compile(r"/(login|signin|sign-in|wp-login\.php|auth|sso|oauth)(/|$|\?|\.)", re.I)
BACKUP_EXT = re.compile(r"\.(bak|old|orig|sql|swp|log|conf|ini|pem|key|tar\.gz|tgz|7z|rar)$|~$", re.I)
EXEC_EXT = re.compile(r"\.(exe|msi|dmg|iso|apk|bat|cmd|ps1|scr|jar|vbs|com|pkg|deb|rpm)$", re.I)


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    title: str
    detail: str = ""


DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _is_internal(ip) -> bool:
    return (ip.is_private or ip.is_loopback or ip.is_link_local) and not any(ip in n for n in DOC_NETS if ip.version == 4)


def _is_ip(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def assess_link(href: str, kind: str, page_url: str = "", rel: str = "") -> list[Finding]:
    """Findings for one link. `kind` is the crawler's classification (internal, external, file, ...)."""
    u = urlparse(href)
    if u.scheme not in ("http", "https"):
        return []
    out: list[Finding] = []
    page = urlparse(page_url)
    host = (u.hostname or "").lower()
    external = kind == "external"

    if u.scheme == "http":
        if page.scheme == "https":
            out.append(Finding("http-downgrade", "medium", "Link downgrades from HTTPS to HTTP", "An https page links to an unencrypted URL."))
        elif external:
            out.append(Finding("http-external", "low", "Unencrypted external link"))
    if u.username or "@" in (u.netloc or ""):
        out.append(Finding("userinfo", "high", "user@host in the URL", "The text before @ is not the destination. A common phishing trick."))
    ip = _is_ip(host)
    if ip is not None:
        local_page = page.scheme == "file" or _is_ip(page.hostname or "") is not None or (page.hostname or "") in ("localhost", "")
        if _is_internal(ip) and not local_page:
            out.append(Finding("internal-address", "medium", "Link points at an internal address", f"{host} is not routable on the internet (SSRF and leaked-internal-name signal)."))
        elif not _is_internal(ip):
            out.append(Finding("raw-ip", "medium", "Link goes to a raw IP address", "Legitimate services rarely link by IP."))
    if "xn--" in host:
        out.append(Finding("punycode", "medium", "Punycode (internationalised) host", "May be a lookalike of a familiar domain."))
    if host in SHORTENERS:
        out.append(Finding("shortener", "medium", "URL shortener", "The real destination is hidden until it is followed."))
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in RISKY_TLDS:
        out.append(Finding("risky-tld", "low", f".{tld} domain", "A TLD that is heavily used for abuse or easily confused with a file extension."))
    if u.port and u.port not in (80, 443):
        out.append(Finding("odd-port", "low" if external else "info", f"Non-standard port {u.port}"))
    for k, v in parse_qsl(u.query, keep_blank_values=True):
        if k.lower() in REDIRECT_PARAMS and re.match(r"^(https?:)?//", unquote(v), re.I):
            out.append(Finding("open-redirect", "medium", f"Redirect parameter '{k}' carries a URL", "Possible open redirect. Test whether the destination is validated."))
            break
    secret_names = []
    for k, v in parse_qsl(u.query, keep_blank_values=True):
        kl = k.lower()
        if (kl in PASSWORD_PARAMS and v) or (kl in TOKEN_PARAMS and len(v) >= 6):
            secret_names.append((k, kl in PASSWORD_PARAMS))
    for m in re.finditer(r";(jsessionid|phpsessid|sid)=([^;/?]{6,})", u.path + (";" + u.params if u.params else ""), re.I):   # urlparse moves ;params out of the path
        secret_names.append((m.group(1), False))
    if secret_names:
        worst_high = any(p for _, p in secret_names)
        out.append(Finding("url-secret", "high" if worst_high else "medium", "Secret or session value in the URL",
                           "parameter " + ", ".join(sorted({n for n, _ in secret_names})) + " (value hidden). URLs end up in logs, browser history and Referer headers."))
    path = unquote(u.path)
    if HIGH_PATH.search(path) or BACKUP_EXT.search(path):
        out.append(Finding("sensitive-file", "high", "Sensitive or backup file path", f"{path} usually should not be reachable from a link."))
    elif ADMIN_PATH.search(path):
        out.append(Finding("admin-path", "medium", "Admin or debug interface path", path))
    elif LOGIN_PATH.search(path):
        out.append(Finding("login-path", "info", "Login or authentication endpoint", "Part of the attack surface: check rate limiting and MFA."))
    if EXEC_EXT.search(path):
        out.append(Finding("exec-download", "medium" if external else "low", "Executable or installer download", path.rsplit("/", 1)[-1]))
    if len(re.findall(r"%[0-9a-f]{2}", href, re.I)) >= 6 or "%25" in href:
        out.append(Finding("obfuscated", "low", "Heavily percent-encoded URL", "Encoding can hide the real destination or smuggle payloads."))
    if len(href) > 300:
        out.append(Finding("long-url", "low", f"Very long URL ({len(href)} characters)"))
    return out


def risk_score(findings: list[Finding]) -> int:
    return min(100, sum(SEV_SCORE[f.severity] for f in findings))


def rating(score: int) -> str:
    return "high" if score >= 40 else "medium" if score >= 20 else "low" if score >= 8 else "none"


# ----------------------------------------------------------------------------- cookies

SESSION_LIKE = re.compile(r"(?<![a-z])sid(?![a-z])|sess|token|auth|jwt|login|logged|remember|csrf|xsrf|secret", re.I)


def parse_set_cookie(line: str) -> dict:
    """One Set-Cookie header value as {"name", "value", and each attribute lower-cased} (an attribute without a value is True)."""
    parts = [p.strip() for p in line.split(";")]
    name, _, value = parts[0].partition("=")
    c: dict = {"name": name.strip(), "value": value.strip()}
    for p in parts[1:]:
        k, eq, v = p.partition("=")
        if k.strip():
            c[k.strip().lower()] = v.strip() if eq else True
    return c


def check_cookies(url: str, set_cookie_lines: list[str], cache_control: str = "") -> list[Finding]:
    """Cookie hardening, read from the attributes themselves (a cookie that is merely *named* 'secure' does not pass)."""
    out: list[Finding] = []
    u = urlparse(url)
    https, host = u.scheme == "https", (u.hostname or "").lower()
    cc = cache_control.lower()
    for line in set_cookie_lines:
        c = parse_set_cookie(line)
        name = c["name"]
        if not name:
            continue
        sess = bool(SESSION_LIKE.search(name))
        secure, httponly = "secure" in c, "httponly" in c
        samesite = str(c.get("samesite", "")).lower()
        if https and not secure:
            out.append(Finding("cookie-no-secure", "medium", f"Cookie '{name}' lacks Secure", "It can be sent over an unencrypted connection."))
        elif not https and sess and u.scheme == "http":
            out.append(Finding("cookie-over-http", "medium", f"Session cookie '{name}' is set over plain HTTP", "It can be read or replaced by anyone on the network."))
        if not httponly:
            out.append(Finding("cookie-no-httponly", "medium" if sess else "low", f"Cookie '{name}' lacks HttpOnly",
                               "Scripts on the page (and any injected script) can read it." if sess else ""))
        if not samesite:
            out.append(Finding("cookie-no-samesite", "low" if sess else "info", f"Cookie '{name}' lacks SameSite"))
        elif samesite == "none" and not secure:
            out.append(Finding("cookie-samesite-none-insecure", "medium", f"Cookie '{name}' is SameSite=None without Secure", "Browsers reject it."))
        low = name.lower()
        if (low.startswith("__host-") and (not secure or c.get("domain") or c.get("path") != "/")) or (low.startswith("__secure-") and not secure):
            out.append(Finding("cookie-prefix-misuse", "medium", f"Cookie '{name}' breaks the rules of its prefix",
                               "__Host- needs Secure, Path=/ and no Domain; __Secure- needs Secure. Browsers drop it."))
        dom = str(c.get("domain", "")).lstrip(".").lower()
        if dom and host and host != dom and host.endswith("." + dom):
            out.append(Finding("cookie-broad-domain", "low", f"Cookie '{name}' is shared with every subdomain of {dom}", "A weaker sibling site can read or overwrite it."))
        if sess:
            life = None
            if str(c.get("max-age", "")).lstrip("-").isdigit():
                life = int(c["max-age"])
            elif isinstance(c.get("expires"), str):
                try:
                    life = email.utils.parsedate_to_datetime(c["expires"]).timestamp() - time.time()
                except (TypeError, ValueError, IndexError):
                    pass
            if life is not None and life > 366 * 86400:
                out.append(Finding("cookie-long-lived", "low", f"Session cookie '{name}' lasts more than a year", "A stolen cookie stays useful for that long."))
            if "public" in cc or ("max-age" in cc and not re.search(r"private|no-store|no-cache|max-age=0", cc)):
                out.append(Finding("cookie-cacheable", "low", f"Response setting session cookie '{name}' may be cached", f"Cache-Control: {cache_control}"))
    return out


# ----------------------------------------------------------------------------- response headers

def _get(headers: dict[str, str], name: str) -> str:
    return headers.get(name, "")


def check_headers(url: str, headers: list[tuple[str, str]], status: int = 200) -> tuple[list[Finding], dict[str, str]]:
    """Audit the main-document response of a page. Returns (findings, selected header values)."""
    h: dict[str, str] = {}
    cookies: list[str] = []
    for name, value in headers:
        n = name.lower()
        if n == "set-cookie":
            cookies.extend(c for c in value.split("\n") if c.strip())
        else:
            h[n] = value
    https = urlparse(url).scheme == "https"
    out: list[Finding] = []
    csp = _get(h, "content-security-policy")

    if urlparse(url).scheme == "http":
        out.append(Finding("no-https", "medium", "Page served over plain HTTP", "Traffic can be read or modified in transit."))
    if https and "strict-transport-security" not in h:
        out.append(Finding("no-hsts", "medium", "No Strict-Transport-Security header", "Browsers are not told to insist on HTTPS."))
    elif https:
        m = re.search(r"max-age=(\d+)", h["strict-transport-security"], re.I)
        if m and int(m.group(1)) < 15552000:
            out.append(Finding("short-hsts", "low", "HSTS max-age is under 180 days", h["strict-transport-security"]))
    if not csp:
        out.append(Finding("no-csp", "medium", "No Content-Security-Policy header", "Nothing limits where scripts and other content may load from."))
    else:
        weak = [t for t in ("'unsafe-inline'", "'unsafe-eval'") if t in csp]
        if re.search(r"(script-src|default-src)[^;]*\s\*(\s|;|$)", csp):
            weak.append("wildcard source")
        if weak:
            out.append(Finding("weak-csp", "low", "Content-Security-Policy allows risky sources", ", ".join(weak)))
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        out.append(Finding("no-frame-protection", "low", "No clickjacking protection", "Neither X-Frame-Options nor CSP frame-ancestors is set."))
    if _get(h, "x-content-type-options").lower() != "nosniff":
        out.append(Finding("no-nosniff", "low", "X-Content-Type-Options: nosniff missing"))
    if "referrer-policy" not in h:
        out.append(Finding("no-referrer-policy", "low", "No Referrer-Policy header", "Full URLs may leak to other sites."))
    if "permissions-policy" not in h:
        out.append(Finding("no-permissions-policy", "info", "No Permissions-Policy header"))
    server = _get(h, "server")
    if re.search(r"\d+\.\d+", server):
        out.append(Finding("server-version", "low", "Server header discloses a version", server))
    if "x-powered-by" in h:
        out.append(Finding("x-powered-by", "low", "X-Powered-By discloses the stack", h["x-powered-by"]))
    acao = _get(h, "access-control-allow-origin")
    if acao == "*" and _get(h, "access-control-allow-credentials").lower() == "true":
        out.append(Finding("cors-wildcard-creds", "high", "CORS allows any origin with credentials"))
    elif acao == "*":
        out.append(Finding("cors-wildcard", "info", "CORS allows any origin", "Fine for public data, risky if the response is user-specific."))
    out.extend(check_cookies(url, cookies, _get(h, "cache-control")))
    wanted = ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options",
              "referrer-policy", "permissions-policy", "server", "x-powered-by")
    return out, {k: h[k] for k in wanted if k in h}


# ----------------------------------------------------------------------------- page-level helper for the browser layer

@dataclass
class PageSecurity:
    url: str
    status: int
    findings: list
    headers: dict
    pairs: list = field(default_factory=list, repr=False, compare=False)   # every response header as (name, value); not saved


def security_from_response(resp) -> "PageSecurity | None":
    """Build a PageSecurity from a Playwright Response if it is the top-level document of a navigation, else None.
    Duck-typed so this module never imports Playwright."""
    try:
        req = resp.request
        if not req.is_navigation_request() or req.frame.parent_frame is not None:
            return None
        if 300 <= resp.status < 400 or urlparse(resp.url).scheme not in ("http", "https"):  # redirect hops and local files carry no headers to audit
            return None
        pairs = [(h["name"], h["value"]) for h in resp.headers_array()]
        findings, shown = check_headers(resp.url, pairs, resp.status)
        return PageSecurity(resp.url, resp.status, findings, shown, pairs)
    except Exception:
        return None
