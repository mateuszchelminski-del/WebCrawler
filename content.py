"""content.py: noticing that a page's *content* changed, and that it started loading someone else's script.

Comparing two crawls by their links and headers misses the changes that matter most for a monitored site: text rewritten (a defaced page,
an injected block of spam) and a new <script src> pointing at a third party (how card skimmers get onto shop pages). So each page is
reduced to a 64-bit similarity fingerprint (SimHash) of its visible text, which is tiny to store and tells *how much* changed:
near-identical pages differ in a few bits, unrelated ones in about half of them.
"""
from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

MAX_TEXT = 400_000
SKIP = {"script", "style", "noscript", "template", "svg", "head", "iframe", "canvas"}
TOKEN = re.compile(r"[^\W_]+", re.UNICODE)
OPAQUE = re.compile(r"^[A-Za-z0-9+/=_-]{20,}$")      # hashes, tokens, base64: different on every load
SAME = 5            # bits of difference that are just noise (a counter, a date)
REPLACED = 22       # bits of difference at which the page reads as largely another page (unrelated pages differ in ~26-36)
MIN_WORDS = 12      # fewer words than this and a fingerprint says little


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.size = 0
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in SKIP:
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in SKIP and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip and self.size < MAX_TEXT:
            self.parts.append(data)
            self.size += len(data)


def words(html: str) -> list[str]:
    """The visible words of a page, lowercased, with numbers and opaque tokens flattened so that a date, a counter or a CSRF token
    does not look like a content change."""
    p = _Text()
    try:
        p.feed(html or "")
        p.close()
    except Exception:       # broken markup must not stop a crawl
        pass
    out = []
    for raw in " ".join(p.parts).split():
        if OPAQUE.match(raw) and re.search(r"\d", raw):
            continue
        for w in TOKEN.findall(raw.lower()):
            out.append("#" if w.isdigit() else w)
    return out


def _h64(s: str) -> int:
    return int.from_bytes(hashlib.blake2b(s.encode("utf-8", "replace"), digest_size=8).digest(), "big")


def simhash(tokens: list[str]) -> int:
    """64-bit SimHash over 3-word shingles (single words for very short texts)."""
    if not tokens:
        return 0
    shingles = [" ".join(tokens[i:i + 3]) for i in range(max(1, len(tokens) - 2))] if len(tokens) >= 3 else [" ".join(tokens)]
    weights = [0] * 64
    for sh in shingles:
        h = _h64(sh)
        for bit in range(64):
            weights[bit] += 1 if (h >> bit) & 1 else -1
    return sum(1 << bit for bit in range(64) if weights[bit] > 0)


def fingerprint(html: str) -> tuple[str, int]:
    """(hex fingerprint, word count) of a page's visible text. ("", 0) for a page with no text."""
    t = words(html)
    return (f"{simhash(t):016x}", len(t)) if t else ("", 0)


def distance(a: str, b: str) -> int:
    """How many of 64 fingerprint bits differ."""
    return bin(int(a or "0", 16) ^ int(b or "0", 16)).count("1")


def compare(old_fp: str, old_words: int, new_fp: str, new_words: int) -> str:
    """"" when the text is the same for practical purposes, else a short description of the change."""
    if not old_fp and not new_fp:
        return ""
    if not old_fp or not new_fp:
        return "the page's text " + ("disappeared" if not new_fp else "appeared")
    d = distance(old_fp, new_fp)
    if min(old_words, new_words) < MIN_WORDS:
        return "" if old_fp == new_fp else f"short page changed ({old_words} -> {new_words} words)"
    if d <= SAME:
        return ""
    size = f"{old_words} -> {new_words} words" if abs(old_words - new_words) > max(5, old_words // 20) else f"{new_words} words"
    return ("text largely different" if d >= REPLACED else "text changed") + f" ({size})"


class _Scripts(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.srcs: list[str] = []
        self.base = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script" and a.get("src"):
            self.srcs.append(a["src"].strip())
        elif tag == "base" and a.get("href") and not self.base:
            self.base = a["href"]


def script_hosts(page_url: str, html: str, same_site=None) -> list[str]:
    """Host names that <script src> pulls code from, other than the page's own site. `same_site(host)` says what counts as the site's own
    (default: the page's host and its subdomains of the same registrable domain)."""
    p = _Scripts()
    try:
        p.feed(html or "")
        p.close()
    except Exception:
        pass
    base = urljoin(page_url, p.base) if p.base else page_url
    own = urlparse(page_url).hostname or ""
    if same_site is None:
        import checks
        same_site = lambda h: checks.related(h, own)
    out = []
    for s in p.srcs[:400]:
        u = urlparse(urljoin(base, s))
        h = (u.hostname or "").lower()
        if u.scheme in ("http", "https") and h and not same_site(h) and h not in out:
            out.append(h)
    return out
