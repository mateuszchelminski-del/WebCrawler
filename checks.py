"""checks.py: passive security checks beyond links and headers, plus site discovery from robots.txt and sitemaps.

    analyze_html()   what a page's markup gets wrong: third-party scripts without Subresource Integrity, mixed content,
                     insecure forms and password fields, leaked keys and tokens
    fingerprint()    which technologies a site runs, and which versions are known to be a problem
    tls_info()       the TLS certificate and protocol, and what is wrong with them
    PROBES / probe() well-known files (security.txt, sitemap.xml) and files that should never be public (.git, .env)
    parse_robots(), parse_sitemap()   where a site says its pages are

Everything is heuristic and passive except probe(), which requests a short fixed list of paths and is therefore opt-in.
No function here talks to the network unless it takes a connection or a `getter` argument.
"""
from __future__ import annotations

import gzip
import re
import socket
import ssl
import threading
import warnings
import zlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlparse

from analysis import Finding

MAX_SITEMAP_BYTES = 20 * 1024 * 1024


# ============================================================================ HTML analysis

class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[dict] = []
        self.styles: list[dict] = []
        self.forms: list[dict] = []
        self.frames: list[dict] = []
        self.media: list[tuple[str, str]] = []     # (tag, src)
        self.anchors: list[dict] = []
        self.meta: dict[str, str] = {}
        self.comments: list[str] = []
        self._form: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.scripts.append(a)
        elif tag == "link" and a.get("href"):
            rel = a.get("rel", "").lower()
            if "stylesheet" in rel:
                self.styles.append(a)
            elif "icon" in rel or "preload" in rel and a.get("as") in ("image", "font", "media"):
                self.media.append(("link", a["href"]))
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "password": False, "inputs": [], "fields": [],
                          "enctype": (a.get("enctype") or "").lower(), "id": a.get("id") or a.get("name") or "", "role": a.get("role", "")}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None:
            t = (a.get("type") or ("textarea" if tag == "textarea" else "select" if tag == "select" else "text")).lower()
            self._form["inputs"].append(t)
            self._form["fields"].append({"name": a.get("name", ""), "type": t, "autocomplete": a.get("autocomplete", ""), "required": "required" in a})
            if t == "password":
                self._form["password"] = True
        elif tag in ("iframe", "frame") and a.get("src"):
            self.frames.append(a)
        elif tag in ("img", "audio", "video", "source", "embed", "object") and (a.get("src") or a.get("data")):
            self.media.append((tag, a.get("src") or a.get("data")))
        elif tag == "a" and a.get("href"):
            self.anchors.append(a)
        elif tag == "meta" and a.get("name"):
            self.meta[a["name"].lower()] = a.get("content", "")
            if a["name"].lower() in ("csrf-token", "csrf-param", "_csrf", "xsrf-token"):
                self.meta["csrf"] = "1"

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None

    def handle_comment(self, data):
        if len(self.comments) < 200:
            self.comments.append(data)


SECRET_PATTERNS = [
    ("AWS access key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "medium"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high"),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "high"),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "medium"),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"), "high"),
]
COMMENT_SECRET = re.compile(r"(password|passwd|secret|api[_-]?key|token|credential)s?\s*[:=]\s*\S+", re.I)


def _redact(s: str) -> str:
    return s[:6] + "…" + f"({len(s)} chars)"


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


CSRF_NAME = re.compile(r"csrf|xsrf|authenticity_token|requestverificationtoken|anti-?forgery|anticsrf|^_token$|nonce|formkey|form_key", re.I)
SEARCH_NAME = re.compile(r"^(q|s|search|query|keyword|keywords|term|find)$", re.I)


@dataclass
class FormInfo:
    page: str
    action: str
    method: str
    enctype: str = ""
    fields: list = field(default_factory=list)       # [{"name", "type", "autocomplete", "required"}]
    password: bool = False
    upload: bool = False
    csrf: bool = False
    search: bool = False
    cross_origin: bool = False
    id: str = ""

    def key(self) -> tuple:
        return (self.action, self.method, tuple(sorted(f["name"] for f in self.fields)))


def extract_forms(url: str, html: str) -> list[FormInfo]:
    """Every place the page accepts input: its forms, with what they ask for and where they send it."""
    if not html or "<form" not in html.lower():
        return []
    p = _PageParser()
    try:
        p.feed(html[:2_000_000])
        p.close()
    except Exception:
        pass
    out = []
    for f in p.forms:
        action = urljoin(url, f["action"]) if f["action"] else url
        names = [x["name"] for x in f["fields"]]
        visible = [x for x in f["fields"] if x["type"] not in ("hidden", "submit", "button", "image", "reset")]
        upload = "file" in f["inputs"] or "multipart" in f["enctype"]
        csrf = bool(p.meta.get("csrf")) or any(CSRF_NAME.search(n or "") for n in names)
        search = f["role"].lower() == "search" or (f["method"] != "post" and len(visible) == 1 and bool(SEARCH_NAME.match(visible[0]["name"] or "")))
        a = urlparse(action)
        out.append(FormInfo(url, action, f["method"] or "get", f["enctype"], f["fields"][:60], f["password"], upload, csrf, search,
                            a.scheme in ("http", "https") and _host(action) != _host(url), f["id"]))
    return out


def analyze_html(url: str, html: str) -> list[Finding]:
    """Findings from one page's markup. `url` is the page's final URL; relative references are resolved against it."""
    if not html:
        return []
    p = _PageParser()
    try:
        p.feed(html[:2_000_000])
        p.close()
    except Exception:  # broken markup must not stop a crawl
        pass
    out: list[Finding] = []
    seen: set = set()

    def add(f: Finding) -> None:
        k = (f.code, f.detail)
        if k not in seen:
            seen.add(k)
            out.append(f)

    page, https, here = urlparse(url), urlparse(url).scheme == "https", _host(url)

    for s in p.scripts:
        src = urljoin(url, s["src"])
        u = urlparse(src)
        if u.scheme in ("http", "https") and _host(src) != here and "integrity" not in s:
            add(Finding("no-sri-script", "medium", "Third-party script without Subresource Integrity", f"{u.netloc}{u.path}"))
        if https and u.scheme == "http":
            add(Finding("mixed-active", "high", "Mixed content: script loaded over HTTP", src))
    for s in p.styles:
        src = urljoin(url, s["href"])
        u = urlparse(src)
        if u.scheme in ("http", "https") and _host(src) != here and "integrity" not in s:
            add(Finding("no-sri-style", "low", "Third-party stylesheet without Subresource Integrity", f"{u.netloc}{u.path}"))
        if https and u.scheme == "http":
            add(Finding("mixed-active", "high", "Mixed content: stylesheet loaded over HTTP", src))
    for f in p.frames:
        src = urljoin(url, f["src"])
        u = urlparse(src)
        if https and u.scheme == "http":
            add(Finding("mixed-active", "high", "Mixed content: frame loaded over HTTP", src))
        if u.scheme in ("http", "https") and _host(src) != here and "sandbox" not in f:
            add(Finding("iframe-no-sandbox", "low", "Third-party iframe without a sandbox", f"{u.netloc}{u.path}"))
    for tag, ref in p.media:
        src = urljoin(url, ref)
        if https and urlparse(src).scheme == "http":
            add(Finding("mixed-passive", "low", f"Mixed content: {tag} loaded over HTTP", src))

    for form in p.forms:
        action = urljoin(url, form["action"]) if form["action"] else url
        a = urlparse(action)
        if form["password"]:
            if page.scheme == "http":
                add(Finding("password-over-http", "high", "Password field on a page served over HTTP", url))
            if form["method"] != "post":
                add(Finding("password-in-url", "high", "Password form submits with GET", f"{action} (the password would appear in the URL)"))
            if a.scheme == "http" and https:
                add(Finding("form-http", "high", "Login form posts to HTTP", action))
            elif _host(action) != here and a.scheme in ("http", "https"):
                add(Finding("login-cross-origin", "medium", "Login form posts to another site", f"{a.netloc}"))
        elif a.scheme == "http" and https:
            add(Finding("form-http", "high", "Form posts to HTTP from an HTTPS page", action))

    for form in p.forms:
        action = urljoin(url, form["action"]) if form["action"] else url
        names = [x["name"] for x in form["fields"]]
        visible = [x for x in form["fields"] if x["type"] not in ("hidden", "submit", "button", "image", "reset")]
        if "file" in form["inputs"] or "multipart" in form["enctype"]:
            add(Finding("form-upload", "info", "File upload form", f"{action}: check what types, sizes and names it accepts"))
        csrf = bool(p.meta.get("csrf")) or any(CSRF_NAME.search(n or "") for n in names)
        if form["method"] == "post" and visible and not csrf:
            add(Finding("form-no-csrf", "low", "POST form without an anti-CSRF token field", f"{action} (a heuristic: tokens set by scripts or headers are not visible here)"))
    for a in p.anchors:
        if a.get("target", "").lower() == "_blank" and not re.search(r"noopener|noreferrer", a.get("rel", ""), re.I):
            h = urljoin(url, a["href"])
            if _host(h) and _host(h) != here:
                add(Finding("tabnabbing", "info", "External link opens a new tab without rel=noopener", h))
                break  # one example is enough

    body = html[:1_000_000]
    for label, rx, sev in SECRET_PATTERNS:
        m = rx.search(body)
        if m:
            add(Finding("exposed-secret", sev, f"{label} in page source", _redact(m.group(0))))
    for c in p.comments:
        m = COMMENT_SECRET.search(c)
        if m:
            add(Finding("comment-secret", "low", "Sensitive-looking HTML comment", _redact(m.group(0))))
            break
    return out


# ============================================================================ technology fingerprinting

@dataclass(frozen=True)
class Tech:
    name: str
    version: str = ""
    evidence: str = ""
    category: str = ""


def _ver(s: str) -> tuple:
    """'3.5' -> (3, 5, 0): always three parts, so '3.5' and '3.5.0' compare equal."""
    n = [int(x) for x in re.findall(r"\d+", s)[:3]]
    return tuple(n + [0] * (3 - len(n)))


HEADER_TECH = [
    (re.compile(r"^Apache(?:/([\d.]+))?", re.I), "Apache", "web server"),
    (re.compile(r"^nginx(?:/([\d.]+))?", re.I), "nginx", "web server"),
    (re.compile(r"^Microsoft-IIS(?:/([\d.]+))?", re.I), "IIS", "web server"),
    (re.compile(r"^LiteSpeed", re.I), "LiteSpeed", "web server"),
    (re.compile(r"^cloudflare", re.I), "Cloudflare", "CDN"),
    (re.compile(r"^openresty(?:/([\d.]+))?", re.I), "OpenResty", "web server"),
    (re.compile(r"^Caddy", re.I), "Caddy", "web server"),
]
POWERED_TECH = [
    (re.compile(r"PHP(?:/([\d.]+))?", re.I), "PHP", "language"),
    (re.compile(r"ASP\.NET", re.I), "ASP.NET", "framework"),
    (re.compile(r"Express", re.I), "Express", "framework"),
    (re.compile(r"Next\.js(?:\s*([\d.]+))?", re.I), "Next.js", "framework"),
    (re.compile(r"Phusion Passenger", re.I), "Passenger", "app server"),
]
HEADER_PRESENCE = {"x-drupal-cache": ("Drupal", "CMS"), "x-pingback": ("WordPress", "CMS"), "cf-ray": ("Cloudflare", "CDN"),
                   "x-vercel-id": ("Vercel", "hosting"), "x-amz-cf-id": ("Amazon CloudFront", "CDN"), "x-shopify-stage": ("Shopify", "platform"),
                   "x-github-request-id": ("GitHub Pages", "hosting"), "x-served-by": ("Fastly", "CDN"), "x-aspnet-version": ("ASP.NET", "framework"),
                   "x-generator": ("", "")}
COOKIE_TECH = {"phpsessid": ("PHP", "language"), "jsessionid": ("Java servlet", "app server"), "asp.net_sessionid": ("ASP.NET", "framework"),
               "laravel_session": ("Laravel", "framework"), "wordpress_logged_in": ("WordPress", "CMS"), "csrftoken": ("Django", "framework"),
               "_rails": ("Ruby on Rails", "framework"), "connect.sid": ("Express", "framework")}
HTML_TECH = [
    (re.compile(r"/wp-content/|/wp-includes/", re.I), "WordPress", "CMS"),
    (re.compile(r"/sites/default/files|Drupal\.settings", re.I), "Drupal", "CMS"),
    (re.compile(r"/media/jui/|/components/com_", re.I), "Joomla", "CMS"),
    (re.compile(r"cdn\.shopify\.com", re.I), "Shopify", "platform"),
    (re.compile(r"static\.wixstatic\.com", re.I), "Wix", "platform"),
    (re.compile(r"squarespace\.com|static1\.squarespace", re.I), "Squarespace", "platform"),
    (re.compile(r"/_next/static/", re.I), "Next.js", "framework"),
    (re.compile(r"__NUXT__|/_nuxt/", re.I), "Nuxt", "framework"),
    (re.compile(r"data-reactroot|__REACT_DEVTOOLS", re.I), "React", "library"),
    (re.compile(r"googletagmanager\.com|google-analytics\.com|gtag\(", re.I), "Google Analytics/Tag Manager", "analytics"),
    (re.compile(r"cdn\.jsdelivr\.net", re.I), "jsDelivr CDN", "CDN"),
]
VERSIONED_HTML = [
    (re.compile(r"jquery[-.@/]?v?(\d+\.\d+(?:\.\d+)?)(?:\.min)?(?:\.js)?", re.I), "jQuery", "library"),
    (re.compile(r"bootstrap[-.@/]v?(\d+\.\d+(?:\.\d+)?)", re.I), "Bootstrap", "library"),
    (re.compile(r"angular(?:js)?[-.@/]v?(1\.\d+(?:\.\d+)?)", re.I), "AngularJS", "framework"),
    (re.compile(r'ng-version="(\d+\.\d+(?:\.\d+)?)"', re.I), "Angular", "framework"),
    (re.compile(r"vue(?:\.runtime)?[-.@/]v?(\d+\.\d+(?:\.\d+)?)", re.I), "Vue", "library"),
    (re.compile(r"lodash[-.@/]v?(\d+\.\d+(?:\.\d+)?)", re.I), "lodash", "library"),
]


def fingerprint(headers: list[tuple[str, str]], html: str = "") -> list[Tech]:
    """Technologies visible in a response's headers, cookies and markup. Never contacts the site."""
    out: dict[tuple, Tech] = {}

    def add(t: Tech) -> None:
        out.setdefault((t.name, t.version), t)

    h = {k.lower(): v for k, v in headers if k.lower() != "set-cookie"}
    cookies = [v for k, v in headers if k.lower() == "set-cookie"]
    for rx, name, cat in HEADER_TECH:
        m = rx.match(h.get("server", ""))
        if m:
            add(Tech(name, (m.group(1) if m.groups() else "") or "", "Server header", cat))
    for rx, name, cat in POWERED_TECH:
        m = rx.search(h.get("x-powered-by", ""))
        if m:
            add(Tech(name, (m.group(1) if m.groups() else "") or "", "X-Powered-By header", cat))
    for k, (name, cat) in HEADER_PRESENCE.items():
        if k in h and name:
            add(Tech(name, "", f"{k} header", cat))
    if "x-generator" in h:
        m = re.match(r"([A-Za-z .]+?)\s*([\d.]+)?$", h["x-generator"].strip())
        if m:
            add(Tech(m.group(1).strip(), m.group(2) or "", "X-Generator header", "CMS"))
    for c in cookies:
        name = c.split("=", 1)[0].strip().lower()
        for key, (tn, cat) in COOKIE_TECH.items():
            if name.startswith(key):
                add(Tech(tn, "", f"{name} cookie", cat))
    if html:
        body = html[:1_000_000]
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
        if m:
            g = re.match(r"([A-Za-z][A-Za-z .]*?)\s*v?([\d.]+)?\s*$", m.group(1).strip())
            if g:
                add(Tech(g.group(1).strip(), g.group(2) or "", "meta generator", "CMS"))
        for rx, name, cat in HTML_TECH:
            if rx.search(body):
                add(Tech(name, "", "page markup", cat))
        for rx, name, cat in VERSIONED_HTML:
            m = rx.search(body)
            if m:
                add(Tech(name, m.group(1), "script/style reference", cat))
    return sorted(out.values(), key=lambda t: (t.category, t.name, t.version))


def tech_findings(techs: list[Tech]) -> list[Finding]:
    """Known-problem versions among the fingerprinted technologies. Version-based only: the site may have patched it."""
    out = []
    for t in techs:
        v = t.version
        if t.name == "jQuery" and v and _ver(v) < (3, 5, 0):
            out.append(Finding("old-jquery", "medium", f"jQuery {v} has known XSS issues", "Fixed in 3.5.0 (CVE-2020-11022, CVE-2020-11023)"))
        elif t.name == "Bootstrap" and v and (_ver(v) < (3, 4, 1) or (4, 0) <= _ver(v)[:2] and _ver(v) < (4, 3, 1)):
            out.append(Finding("old-bootstrap", "low", f"Bootstrap {v} has a known XSS issue", "Fixed in 3.4.1 and 4.3.1 (CVE-2019-8331)"))
        elif t.name == "AngularJS":
            out.append(Finding("eol-angularjs", "medium", f"AngularJS {v or '1.x'} is end-of-life", "No security fixes since December 2021"))
        elif t.name == "PHP" and v and _ver(v) < (8, 1):
            out.append(Finding("eol-php", "medium", f"PHP {v} is end-of-life", "Check the vendor's support status: unsupported versions get no security fixes"))
        elif t.name == "Apache" and v in ("2.4.49", "2.4.50"):
            out.append(Finding("apache-path-traversal", "high", f"Apache {v} has a path-traversal flaw", "CVE-2021-41773 / CVE-2021-42013 (can lead to file disclosure or code execution)"))
        elif t.name == "IIS" and v and _ver(v) < (8, 5):
            out.append(Finding("old-iis", "medium", f"IIS {v} is out of support"))
        elif t.name == "nginx" and v and _ver(v) < (1, 20):
            out.append(Finding("old-nginx", "low", f"nginx {v} is several years old", "Check for security updates"))
    return out


# ============================================================================ TLS

# A small X.509 reader: enough to say who a certificate is for, who issued it, when it expires, how it is signed and how strong
# its key is, even when the certificate fails verification (Python's own parser returns nothing for an unverified certificate).

_OIDS = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.29.17": "SAN", "1.2.840.113549.1.1.1": "RSA", "1.2.840.10045.2.1": "EC",
         "1.2.840.113549.1.1.2": "md2WithRSA", "1.2.840.113549.1.1.4": "md5WithRSA", "1.2.840.113549.1.1.5": "sha1WithRSA",
         "1.2.840.113549.1.1.11": "sha256WithRSA", "1.2.840.113549.1.1.12": "sha384WithRSA", "1.2.840.113549.1.1.13": "sha512WithRSA",
         "1.2.840.113549.1.1.10": "RSASSA-PSS", "1.2.840.10045.4.1": "ecdsa-with-SHA1", "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
         "1.2.840.10045.4.3.3": "ecdsa-with-SHA384", "1.2.840.10045.4.3.4": "ecdsa-with-SHA512", "1.3.101.112": "Ed25519"}
WEAK_SIGNATURES = {"md2WithRSA": "high", "md5WithRSA": "high", "sha1WithRSA": "high", "ecdsa-with-SHA1": "high"}


def _tlv(b: bytes, i: int):
    """(tag, content start, content end) of the DER element at b[i]."""
    tag = b[i]
    n = b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[i:i + k], "big")
        i += k
    if i + n > len(b):
        raise ValueError("truncated certificate")
    return tag, i, i + n


def _kids(b: bytes, start: int, end: int):
    i = start
    while i < end:
        tag, cs, ce = _tlv(b, i)
        yield tag, cs, ce
        i = ce


def _oid(b: bytes, cs: int, ce: int) -> str:
    first = b[cs]
    parts = [str(first // 40), str(first % 40)]
    v = 0
    for x in b[cs + 1:ce]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(str(v))
            v = 0
    return ".".join(parts)


def _name(b: bytes, cs: int, ce: int) -> dict:
    out = {}
    for _, rs, re_ in _kids(b, cs, ce):                    # SET
        for _, as_, ae in _kids(b, rs, re_):               # SEQUENCE { OID, value }
            kids = list(_kids(b, as_, ae))
            if len(kids) == 2 and kids[0][0] == 0x06:
                key = _OIDS.get(_oid(b, kids[0][1], kids[0][2]))
                if key:
                    out.setdefault(key, b[kids[1][1]:kids[1][2]].decode("utf-8", "replace"))
    return out


def _time(b: bytes, tag: int, cs: int, ce: int) -> datetime:
    t = b[cs:ce].decode("ascii")
    if tag == 0x17:                                         # UTCTime: two-digit year
        yy = int(t[:2])
        t = ("19" if yy >= 50 else "20") + t
    return datetime.strptime(t[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)


def parse_cert(der: bytes) -> dict:
    """Subject, issuer, validity, alternative names, signature algorithm and key size of a DER certificate. Never raises:
    a certificate that cannot be read returns {}."""
    try:
        _, cs, ce = _tlv(der, 0)
        _, ts, te = next(_kids(der, cs, ce))              # tbsCertificate
        kids = list(_kids(der, ts, te))
        k = 1 if kids[0][0] == 0xA0 else 0                 # skip the optional [0] version
        sig_alg = _OIDS.get(_oid(der, *next(((a, b) for t, a, b in _kids(der, kids[k + 1][1], kids[k + 1][2]) if t == 0x06))), "")
        issuer = _name(der, kids[k + 2][1], kids[k + 2][2])
        v = list(_kids(der, kids[k + 3][1], kids[k + 3][2]))
        nb, na = _time(der, v[0][0], v[0][1], v[0][2]), _time(der, v[1][0], v[1][1], v[1][2])
        subject = _name(der, kids[k + 4][1], kids[k + 4][2])
        key_type, key_bits = "", 0
        spki = list(_kids(der, kids[k + 5][1], kids[k + 5][2]))
        alg_oid = _OIDS.get(_oid(der, *next(((a, b) for t, a, b in _kids(der, spki[0][1], spki[0][2]) if t == 0x06))), "")
        key_type = alg_oid
        if alg_oid == "RSA":
            bits_start = spki[1][1] + 1                    # skip the unused-bits byte of the BIT STRING
            _, rs, re_ = _tlv(der, bits_start)             # RSAPublicKey SEQUENCE
            _, ms, me = _tlv(der, rs)                      # modulus INTEGER
            mod = der[ms:me].lstrip(b"\x00")
            key_bits = len(mod) * 8 - (8 - mod[0].bit_length()) if mod else 0
        elif alg_oid == "EC":
            key_bits = (spki[1][2] - spki[1][1] - 2) * 8 // 2 if spki[1][2] - spki[1][1] > 3 else 0   # 0x04 || X || Y
        san = []
        for tag, es, ee in kids[k + 6:]:
            if tag != 0xA3:                                # [3] extensions
                continue
            _, xs, xe = next(_kids(der, es, ee))
            for _, s0, e0 in _kids(der, xs, xe):           # each Extension
                parts = list(_kids(der, s0, e0))
                if _OIDS.get(_oid(der, parts[0][1], parts[0][2])) == "SAN":
                    _, vs, ve = parts[-1]                  # OCTET STRING holding a SEQUENCE of GeneralNames
                    _, gs, ge = _tlv(der, vs)
                    for gtag, a, b in _kids(der, gs, ge):
                        if gtag == 0x82:
                            san.append(der[a:b].decode("ascii", "replace"))
        now = datetime.now(timezone.utc)
        return {"subject": subject.get("CN") or subject.get("O", ""), "issuer": issuer.get("O") or issuer.get("CN", ""),
                "issuer_cn": issuer.get("CN", ""), "self_signed": bool(subject) and subject == issuer,
                "not_before": nb.strftime("%Y-%m-%d"), "not_after": na.strftime("%Y-%m-%d"), "days_left": (na - now).days,
                "valid_days": (na - nb).days, "san": san[:30], "sig_alg": sig_alg, "key_type": key_type, "key_bits": key_bits}
    except (ValueError, IndexError, StopIteration, UnicodeDecodeError, TypeError):
        return {}


def _legacy_protocols(host: str, port: int, timeout: float) -> list[str]:
    """Which obsolete protocol versions (TLS 1.0, 1.1) the server will still negotiate. Best effort: if this machine's TLS library
    cannot speak them, nothing is reported rather than something wrong."""
    found = []
    for name, ver_name in (("TLSv1", "TLSv1"), ("TLSv1.1", "TLSv1_1")):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            with warnings.catch_warnings():                 # Python marks these versions deprecated; that is the point of the probe
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ctx.maximum_version = getattr(ssl.TLSVersion, ver_name)
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
                if s.version() == name:
                    found.append(name)
        except (OSError, ssl.SSLError, ValueError):
            pass
    return found


def _connect_tls(host: str, port: int, timeout: float, verify: bool = True, legacy: bool = False):
    """(version, cipher, DER certificate) of a completed handshake; raises on failure."""
    if legacy:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    else:
        ctx = ssl.create_default_context()
    if not verify or legacy:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
        return s.version() or "", (s.cipher() or ("",))[0], s.getpeercert(binary_form=True) or b""


def tls_info(host: str, port: int = 443, timeout: float = 8.0, probe_legacy: bool = True) -> dict:
    """Connect and describe the certificate and protocol. Never raises."""
    info: dict = {"host": host, "port": port, "ok": False, "verified": False, "error": "", "verify_error": "", "protocol": "", "cipher": "",
                  "subject": "", "issuer": "", "not_after": "", "days_left": None, "san": [], "legacy": [], "sig_alg": "", "key_bits": 0,
                  "key_type": "", "self_signed": False}
    der = b""
    try:
        info["protocol"], info["cipher"], der = _connect_tls(host, port, timeout)
        info["ok"] = info["verified"] = True
    except ssl.SSLCertVerificationError as e:
        info["verify_error"] = getattr(e, "verify_message", "") or str(e)
        try:                                               # the certificate is bad, but the protocol and the certificate itself are still worth reading
            info["protocol"], info["cipher"], der = _connect_tls(host, port, timeout, verify=False)
            info["ok"] = True
        except (OSError, ssl.SSLError, ValueError):
            pass
    except (OSError, ssl.SSLError, ValueError) as e:
        info["error"] = str(e)[:160]
        try:                                               # perhaps the server only speaks an obsolete protocol
            info["protocol"], info["cipher"], der = _connect_tls(host, port, timeout, legacy=True)
            info["ok"], info["error"] = True, ""
            info["unverified"] = "certificate not checked: the server only offers an obsolete protocol"
        except (OSError, ssl.SSLError, ValueError):
            pass
    if der:
        c = parse_cert(der)
        if c:
            info.update({k: c[k] for k in ("subject", "issuer", "not_after", "days_left", "san", "sig_alg", "key_bits", "key_type", "self_signed")})
            info["not_before"], info["valid_days"] = c["not_before"], c["valid_days"]
    if info["ok"] and probe_legacy:
        info["legacy"] = _legacy_protocols(host, port, timeout)
    return info


def tls_findings(info: dict) -> list[Finding]:
    out: list[Finding] = []
    host = info.get("host", "")
    if info.get("error") and not info.get("ok"):
        return [Finding("tls-unreachable", "info", "Could not complete a TLS handshake", info["error"])]
    ve = info.get("verify_error", "")
    if ve:
        low = ve.lower()
        if "expired" in low:
            d0 = info.get("days_left")
            what, extra = "Certificate has expired", (f" ({-d0} day(s) ago, on {info.get('not_after', '')})" if d0 is not None and d0 < 0 else "")
        elif "self signed certificate in certificate chain" in low or "self-signed certificate in certificate chain" in low:
            what, extra = "Certificate chain ends in an untrusted root", " (a private or unknown certificate authority)"
        elif "self" in low and "signed" in low:
            what, extra = "Certificate is self-signed", " (browsers will warn)"
        elif "unable to get local issuer" in low or "unknown ca" in low or "unable to verify the first certificate" in low:
            what, extra = "Certificate chain is incomplete or from an unknown authority", " (the server may not be sending its intermediate certificates)"
        elif "hostname" in low or "doesn't match" in low or "does not match" in low:
            what, extra = "Certificate does not match the host name", ""
        else:
            what, extra = "Certificate failed verification", ""
        out.append(Finding("tls-invalid", "high", what, f"{host}: {ve}{extra}"))
    d = info.get("days_left")
    if d is not None:
        if d < 0:
            if "expired" not in ve.lower():           # the verification message already said so, with the date
                out.append(Finding("tls-expired", "high", f"Certificate expired {-d} day(s) ago", info.get("not_after", "")))
        elif d < 14:
            out.append(Finding("tls-expiring", "high", f"Certificate expires in {d} day(s)", info.get("not_after", "")))
        elif d < 30:
            out.append(Finding("tls-expiring", "medium", f"Certificate expires in {d} days", info.get("not_after", "")))
    proto = info.get("protocol", "")
    old = sorted(set(info.get("legacy", []) + ([proto] if proto in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1") else [])))
    if old:
        # SSLv2/3 are broken outright. TLS 1.0/1.1 are obsolete: a medium finding if the server also offers a modern version,
        # high if it offers nothing else (modern browsers cannot connect at all).
        only_old = proto in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
        sev = "high" if (only_old or any(p.startswith("SSL") for p in old)) else "medium"
        out.append(Finding("tls-old-protocol", sev, "Server accepts obsolete " + " and ".join(old),
                           "Browsers have dropped these; servers should require TLS 1.2 or newer" + (" (this server offers nothing newer)" if only_old else "")))
    sig = info.get("sig_alg", "")
    if sig in WEAK_SIGNATURES:
        out.append(Finding("tls-weak-signature", WEAK_SIGNATURES[sig], f"Certificate is signed with a weak algorithm ({sig})", "Browsers reject it"))
    bits = info.get("key_bits", 0)
    if info.get("key_type") == "RSA" and 0 < bits < 2048:
        out.append(Finding("tls-weak-key", "high" if bits < 1024 else "medium", f"Certificate uses a weak {bits}-bit RSA key", "2048 bits is the minimum today"))
    return out


# ============================================================================ well-known files

@dataclass
class Probe:
    path: str
    title: str
    severity: str                 # severity if the file is exposed; "info" for files that are good to have
    validator: "re.Pattern"
    good: bool = False            # True: presence is a good thing (security.txt)


def _rx(p, flags=0):
    return re.compile(p, flags | re.S)


PROBES = [
    Probe("/.well-known/security.txt", "security.txt (vulnerability disclosure contact)", "info", _rx(r"^\s*(Contact|Expires)\s*:", re.M | re.I), True),
    Probe("/security.txt", "security.txt at the site root", "info", _rx(r"^\s*(Contact|Expires)\s*:", re.M | re.I), True),
    Probe("/robots.txt", "robots.txt", "info", _rx(r"^\s*(User-agent|Disallow|Sitemap)\s*:", re.M | re.I)),
    Probe("/sitemap.xml", "sitemap.xml", "info", _rx(r"<(urlset|sitemapindex)\b", re.I)),
    Probe("/humans.txt", "humans.txt", "info", _rx(r"/\*\s*TEAM|Developer|Contact", re.I)),
    Probe("/.well-known/openid-configuration", "OpenID Connect configuration", "info", _rx(r'"issuer"\s*:')),
    Probe("/.git/HEAD", "Git repository is publicly readable (.git/HEAD)", "high", _rx(r"^ref:\s*refs/", re.M)),
    Probe("/.git/config", "Git configuration is publicly readable", "high", _rx(r"\[core\]|\[remote ")),
    Probe("/.env", ".env file is publicly readable", "high", _rx(r"^[A-Z][A-Z0-9_]{2,}\s*=\s*\S*", re.M)),
    Probe("/.svn/entries", "Subversion metadata is publicly readable", "medium", _rx(r"^\d+\s*$|dir|svn", re.M | re.I)),
    Probe("/.DS_Store", "macOS .DS_Store file is public (lists folder contents)", "medium", _rx(r"\x00\x00\x00\x01Bud1")),
    Probe("/phpinfo.php", "phpinfo() page is public", "high", _rx(r"PHP Version|phpinfo\(\)", re.I)),
    Probe("/server-status", "Apache server-status page is public", "medium", _rx(r"Apache Server Status|Server Version:", re.I)),
    Probe("/web.config", "web.config is publicly readable", "medium", _rx(r"<configuration\b", re.I)),
    Probe("/.htpasswd", ".htpasswd is publicly readable", "high", _rx(r"^[\w.\-]+:(\$apr1\$|\{SHA\}|\$2y\$|[A-Za-z0-9./]{13})", re.M)),
    Probe("/backup.sql", "Database dump is publicly readable", "high", _rx(r"-- (MySQL|PostgreSQL) dump|CREATE TABLE|INSERT INTO", re.I)),
    Probe("/config.php.bak", "Backup of config.php is publicly readable", "high", _rx(r"DB_PASSWORD|\$db_?pass|password\s*=", re.I)),
    Probe("/crossdomain.xml", "crossdomain.xml allows any domain", "medium", _rx(r'allow-access-from[^>]+domain="\*"', re.I)),
    Probe("/actuator/env", "Spring Boot actuator /env is public", "high", _rx(r'"propertySources"\s*:')),
]


@dataclass
class ProbeResult:
    path: str
    url: str
    title: str
    severity: str
    exposed: bool
    status: int = 0
    good: bool = False


def probe(base: str, getter) -> list[ProbeResult]:
    """Request each PROBES path. `getter(url)` returns (status, text) and must never raise. A hit needs both a 200 and
    content that matches the file's real format, so a site that answers 200 to everything does not produce false alarms."""
    root = f"{urlparse(base).scheme}://{urlparse(base).netloc}"
    out = []
    for p in PROBES:
        url = root + p.path
        status, text = getter(url)
        out.append(ProbeResult(p.path, url, p.title, p.severity, status == 200 and bool(p.validator.search(text or "")), status, p.good))
    return out


def probe_findings(results: list[ProbeResult]) -> list[tuple[Finding, str]]:
    """Site-level findings (with the URL they apply to) from probe results."""
    out = []
    have_sec = any(r.good and r.exposed for r in results)
    for r in results:
        if r.exposed and r.severity != "info":
            out.append((Finding("exposed-file", r.severity, r.title, r.path), r.url))
    if results and not have_sec:
        out.append((Finding("no-security-txt", "info", "No security.txt found", "A security.txt tells researchers how to report a vulnerability (RFC 9116)"), results[0].url.rsplit("/.well-known", 1)[0]))
    return out


# ============================================================================ robots.txt and sitemaps

SENSITIVE_WORDS = re.compile(r"admin|backup|private|internal|secret|staging|\bdev\b|test|\bold\b|config|\bdb\b|sql|tmp|temp|logs?\b|dump|api/v\d|cgi-bin|phpmyadmin|upload", re.I)


def parse_robots(text: str) -> dict:
    """The parts of robots.txt that matter for recon: Sitemap lines, Disallow paths, Crawl-delay."""
    sitemaps, disallow, allow, delay = [], [], [], 0.0
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        k, v = (x.strip() for x in line.split(":", 1))
        k = k.lower()
        if k == "sitemap" and v:
            sitemaps.append(v)
        elif k == "disallow" and v:
            disallow.append(v)
        elif k == "allow" and v:
            allow.append(v)
        elif k == "crawl-delay":
            try:
                delay = max(delay, float(v))
            except ValueError:
                pass
    return {"sitemaps": list(dict.fromkeys(sitemaps)), "disallow": list(dict.fromkeys(disallow)), "allow": allow, "crawl_delay": delay}


def robots_findings(robots: dict, url: str = "") -> list[tuple[Finding, str]]:
    hidden = [p for p in robots.get("disallow", []) if SENSITIVE_WORDS.search(p)]
    out = []
    if hidden:
        out.append((Finding("robots-sensitive", "low", f"robots.txt advertises {len(hidden)} sensitive-looking path(s)",
                            ", ".join(hidden[:8]) + (" …" if len(hidden) > 8 else "") + ". Listing a path in robots.txt does not protect it."), url))
    return out


def parse_sitemap(data: bytes) -> tuple[list[str], list[str], str]:
    """(page URLs, child sitemap URLs, error). Safe against XML bombs: DOCTYPE/ENTITY is refused and sizes are capped."""
    try:
        if data[:2] == b"\x1f\x8b":
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            data = d.decompress(data, MAX_SITEMAP_BYTES)
            if d.unconsumed_tail:
                return [], [], "sitemap is too large"
        if len(data) > MAX_SITEMAP_BYTES:
            return [], [], "sitemap is too large"
    except (zlib.error, OSError) as e:
        return [], [], f"cannot decompress: {e}"
    head = data[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in data[:65536].lower():
        return [], [], "refused: sitemap declares a DOCTYPE/ENTITY"
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        return [], [], f"not valid XML: {e}"
    pages, children = [], []
    kind = root.tag.rsplit("}", 1)[-1].lower()
    for el in root.iter():
        if el.tag.rsplit("}", 1)[-1].lower() == "loc" and (el.text or "").strip():
            (children if kind == "sitemapindex" else pages).append(el.text.strip())
    return pages, children, ""


@dataclass
class Seeds:
    pages: list = field(default_factory=list)
    sitemaps: list = field(default_factory=list)
    robots: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)


def discover_seeds(origin: str, getter, max_urls: int = 5000) -> Seeds:
    """URLs a site publishes about itself. `getter(url)` returns (status, bytes) and never raises."""
    root = f"{urlparse(origin).scheme}://{urlparse(origin).netloc}"
    s = Seeds()
    status, body = getter(root + "/robots.txt")
    if status == 200:
        s.robots = parse_robots(body.decode("utf-8", errors="replace"))
    todo = list(s.robots.get("sitemaps", [])) or [root + "/sitemap.xml"]
    seen: set = set()
    depth = 0
    while todo and depth < 3 and len(s.pages) < max_urls:
        nxt = []
        for sm in todo[:50]:
            if sm in seen or urlparse(sm).netloc != urlparse(root).netloc and not sm.startswith(root):
                continue
            seen.add(sm)
            st, data = getter(sm)
            if st != 200:
                if sm != root + "/sitemap.xml" or s.robots.get("sitemaps"):
                    s.errors.append(f"{sm}: " + ("larger than the %d MB limit" % (MAX_SITEMAP_BYTES // (1024 * 1024)) if st == 413 else f"HTTP {st}"))
                continue
            pages, kids, err = parse_sitemap(data)
            if err:
                s.errors.append(f"{sm}: {err}")
                continue
            s.sitemaps.append(sm)
            s.pages.extend(pages)
            nxt.extend(kids)
        todo, depth = nxt, depth + 1
    s.pages = list(dict.fromkeys(s.pages))[:max_urls]
    return s


# ============================================================================ hosts and parameters

SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil", "nom", "sch", "ltd", "plc", "me", "info"}


def registrable(host: str) -> str:
    """The domain a host belongs to (example.com for www.example.com, example.co.uk for a.b.example.co.uk). An approximation that
    needs no public-suffix list: it knows the common two-part suffixes."""
    labels = [l for l in (host or "").lower().strip(".").split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def related(host: str, root: str) -> bool:
    """Is `host` on the same registrable domain as `root`?"""
    return bool(host and root) and registrable(host) == registrable(root)


def is_public_host(host: str) -> bool:
    """A name that exists on the public internet, so it is safe to look up in public DNS (not an IP, localhost or an internal name)."""
    h = (host or "").lower().strip(".")
    if not h or "." not in h or re.fullmatch(r"[\d.]+|[\da-f:]+", h):
        return False
    return not re.search(r"\.(local|localhost|internal|intranet|lan|corp|home|test|example|invalid|localdomain|private)$", h)


def hosts_in_policy(value: str) -> list[str]:
    """Host names mentioned in a Content-Security-Policy or similar header value."""
    out = []
    for m in re.finditer(r"(?:https?://)?((?:\*\.)?(?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+|/|\s|;|$)", value or "", re.I):
        out.append(m.group(1).lower().lstrip("*."))
    return list(dict.fromkeys(out))


def resolve_hosts(hosts: list[str], timeout: float = 4.0, workers: int = 8) -> dict:
    """{host: [addresses]} using the system resolver; an empty list means the name does not resolve; a host that did not answer in time is left out."""
    from concurrent.futures import ThreadPoolExecutor, wait

    def one(h):
        try:
            return h, sorted({ai[4][0] for ai in socket.getaddrinfo(h, None)})
        except socket.gaierror:
            return h, []
        except OSError:
            return h, None
    out = {}
    ex = ThreadPoolExecutor(max_workers=workers)
    try:
        futs = [ex.submit(one, h) for h in hosts[:200]]
        done, _ = wait(futs, timeout=timeout + 2)
        for f in done:
            h, addrs = f.result()
            if addrs is not None:
                out[h] = addrs
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return out


# ============================================================================ everything learned about a site as a whole

class SiteInfo:
    """Site-wide results shared between a crawler (writer) and the app (reader). Thread-safe."""

    def __init__(self) -> None:
        self.tls: dict[str, dict] = {}
        self.tech: dict[tuple, dict] = {}
        self.files: list[dict] = []
        self.findings: list[tuple[Finding, str]] = []
        self.seeds: dict = {}
        self.forms: dict[tuple, dict] = {}       # form key -> {page, action, method, fields...}
        self.params: dict[str, dict] = {}        # query parameter name -> {count, examples}
        self.hosts: dict[str, dict] = {}         # related host -> {sources, addresses}
        self.dns: dict = {}                      # DNS and e-mail security records of the site's domain (dnscheck.py)
        self.scripts: dict[str, dict] = {}       # third-party host a <script src> loads code from -> {count, pages}
        self.version = 0
        self._lock = threading.RLock()

    def clear(self) -> None:
        with self._lock:
            self.tls.clear(), self.tech.clear(), self.files.clear(), self.findings.clear(), self.seeds.clear()
            self.forms.clear(), self.params.clear(), self.hosts.clear(), self.dns.clear(), self.scripts.clear()
            self.version += 1

    def add_forms(self, forms: list) -> None:
        with self._lock:
            added = False
            for f in forms:
                k = f.key()
                if k not in self.forms and len(self.forms) < 2000:
                    self.forms[k] = {"page": f.page, "action": f.action, "method": f.method, "enctype": f.enctype, "fields": f.fields, "password": f.password,
                                     "upload": f.upload, "csrf": f.csrf, "search": f.search, "cross_origin": f.cross_origin, "id": f.id}
                    added = True
            if added:
                self.version += 1

    def add_scripts(self, page: str, hosts: list) -> None:
        """Note which other sites a page loads scripts from."""
        if not hosts:
            return
        with self._lock:
            changed = False
            for h in hosts:
                e = self.scripts.get(h)
                if e is None and len(self.scripts) < 500:
                    e = self.scripts[h] = {"count": 0, "pages": []}
                    changed = True
                if e is not None:
                    e["count"] += 1
                    if len(e["pages"]) < 5 and page not in e["pages"]:
                        e["pages"].append(page)
                        changed = True
            if changed:
                self.version += 1

    def add_params(self, url: str) -> None:
        """Note the query parameters of a URL the site links to: the places input can be fed in."""
        q = urlparse(url).query
        if not q:
            return
        with self._lock:
            changed = False
            for k, _ in parse_qsl(q, keep_blank_values=True):
                if not k or len(k) > 60:
                    continue
                e = self.params.get(k)
                if e is None and len(self.params) < 1000:
                    e = self.params[k] = {"count": 0, "examples": []}
                if e is not None:
                    e["count"] += 1
                    if len(e["examples"]) < 3 and url not in e["examples"]:
                        e["examples"].append(url)
                    changed = True
            if changed:
                self.version += 1

    def add_host(self, host: str, source: str, root: str) -> None:
        """Remember a host name that belongs to the site's domain (a subdomain the site refers to)."""
        host = (host or "").lower().strip(".")
        if not host or not related(host, root):
            return
        with self._lock:
            e = self.hosts.setdefault(host, {"sources": [], "addresses": None})
            if source not in e["sources"]:
                e["sources"].append(source)
                self.version += 1

    def resolve_hosts(self, timeout: float = 4.0) -> None:
        """Look the discovered hosts up, and flag references to names that no longer resolve."""
        with self._lock:
            todo = [h for h, e in self.hosts.items() if e["addresses"] is None and is_public_host(h)]
        if not todo:
            return
        found = resolve_hosts(todo, timeout)
        with self._lock:
            for h, addrs in found.items():
                self.hosts[h]["addresses"] = addrs
                if not addrs and set(self.hosts[h]["sources"]) != {"certificate-log"}:      # a name only a certificate log remembers may be long retired
                    self.add_finding(Finding("host-unresolved", "low", "The site refers to a host name that does not resolve",
                                             f"{h} (seen in: {', '.join(self.hosts[h]['sources'])}). A stale record can be taken over if it points at a service that has been removed."), h)
            self.version += 1

    def add_dns(self, rep) -> None:
        """Store a dnscheck.DnsReport and its findings."""
        with self._lock:
            self.dns = rep.to_dict()
            for f in rep.findings:
                self.add_finding(f, rep.domain)
            self.version += 1

    def add_finding(self, f: Finding, where: str) -> None:
        with self._lock:
            if (f, where) not in self.findings:
                self.findings.append((f, where))
                self.version += 1

    def add_tls(self, info: dict) -> None:
        with self._lock:
            self.tls[info["host"]] = info
            for f in tls_findings(info):
                self.add_finding(f, info["host"])
            for name in info.get("san", []):
                if "*" not in name:
                    self.add_host(name, "certificate", info["host"])
            self.version += 1

    def add_tech(self, techs: list[Tech], url: str) -> None:
        with self._lock:
            new = []
            for t in techs:
                k = (t.name, t.version)
                if k not in self.tech:
                    self.tech[k] = {**asdict(t), "url": url}
                    new.append(t)
            for f in tech_findings(new):
                self.add_finding(f, url)
            if new:
                self.version += 1

    def add_probes(self, results: list[ProbeResult]) -> None:
        with self._lock:
            self.files = [asdict(r) for r in results]
            for f, where in probe_findings(results):
                self.add_finding(f, where)
            self.version += 1

    def set_seeds(self, seeds: Seeds, url: str = "") -> None:
        with self._lock:
            self.seeds = {"sitemaps": seeds.sitemaps, "pages": len(seeds.pages), "robots": seeds.robots, "errors": seeds.errors}
            for f, where in robots_findings(seeds.robots, url):
                self.add_finding(f, where)
            self.version += 1

    def to_dict(self) -> dict:
        with self._lock:
            return {"tls": dict(self.tls), "tech": list(self.tech.values()), "files": list(self.files), "seeds": dict(self.seeds),
                    "findings": [{**asdict(f), "where": w} for f, w in self.findings],
                    "forms": list(self.forms.values()), "params": dict(self.params), "hosts": dict(self.hosts), "dns": dict(self.dns), "scripts": dict(self.scripts)}

    @classmethod
    def from_dict(cls, d: dict) -> "SiteInfo":
        s = cls()
        s.tls = dict(d.get("tls", {}))
        s.tech = {(t["name"], t.get("version", "")): t for t in d.get("tech", [])}
        s.files = list(d.get("files", []))
        s.seeds = dict(d.get("seeds", {}))
        s.findings = [(Finding(f["code"], f["severity"], f["title"], f.get("detail", "")), f.get("where", "")) for f in d.get("findings", [])]
        s.forms = {(f["action"], f["method"], tuple(sorted(x["name"] for x in f.get("fields", [])))): f for f in d.get("forms", [])}
        s.params = dict(d.get("params", {}))
        s.hosts = dict(d.get("hosts", {}))
        s.dns = dict(d.get("dns", {}))
        s.scripts = dict(d.get("scripts", {}))
        s.version = 1
        return s

    def load(self, d: dict) -> None:
        o = SiteInfo.from_dict(d)
        with self._lock:
            self.tls, self.tech, self.files, self.seeds, self.findings = o.tls, o.tech, o.files, o.seeds, o.findings
            self.forms, self.params, self.hosts, self.dns, self.scripts = o.forms, o.params, o.hosts, o.dns, o.scripts
            self.version += 1
