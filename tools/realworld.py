"""Run the crawler against public sites that exist to be crawled and tested, and print what happened.

    python tools/realworld.py              # every site below, quick scans
    python tools/realworld.py badssl       # only sites whose name contains "badssl"

These are practice targets run by their owners for exactly this (crawler and scanner developers use them), and the scans are polite: a delay
between requests and a small page limit. Do not add a site you do not own or have permission to test. For your own site use the normal
command line. The point of this script is to see how the tool copes with things local test servers never produce: real certificates, CDNs,
redirect chains, compression, slow servers and odd HTML.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import webcrawler as wc  # noqa: E402

# (name, address, extra options)
SITES = [
    ("books.toscrape", "https://books.toscrape.com/", ["--depth", "1", "--max-pages", "30"]),
    ("quotes.toscrape", "https://quotes.toscrape.com/", ["--depth", "1", "--max-pages", "20"]),
    ("httpbin", "https://httpbin.org/", ["--depth", "0"]),
    ("badssl expired", "https://expired.badssl.com/", ["--depth", "0", "--insecure"]),
    ("badssl self-signed", "https://self-signed.badssl.com/", ["--depth", "0", "--insecure"]),
    ("badssl wrong host", "https://wrong.host.badssl.com/", ["--depth", "0", "--insecure"]),
    ("badssl untrusted root", "https://untrusted-root.badssl.com/", ["--depth", "0", "--insecure"]),
    ("badssl tls 1.0", "https://tls-v1-0.badssl.com:1010/", ["--depth", "0", "--insecure"]),
    ("badssl rsa8192", "https://rsa8192.badssl.com/", ["--depth", "0"]),
    ("the-internet", "https://the-internet.herokuapp.com/", ["--depth", "1", "--max-pages", "25"]),
]


def scan(address: str, extra: list) -> dict:
    out = Path(tempfile.mkdtemp(prefix="wc-realworld-"))
    buf = io.StringIO()
    t = time.perf_counter()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            rc = wc.main([address, "--quick", "--delay", "0.3", "--timeout", "20", "-q", "--out", str(out), "--format", "session", "json", *extra])
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 2
    took = time.perf_counter() - t
    row = {"rc": rc, "seconds": round(took, 1), "pages": 0, "links": 0, "findings": {}, "codes": []}
    try:
        session = json.loads((out / "session.json").read_text(encoding="utf-8"))
        import snapshot
        found = snapshot.all_findings(session)
        row.update(pages=len(session.get("pages", [])), links=len(session.get("links", [])), codes=sorted({f["code"] for f in found}))
        for f in found:
            row["findings"][f["severity"]] = row["findings"].get(f["severity"], 0) + 1
        row["tls"] = {h: (t.get("protocol") or "?", "trusted" if t.get("verified") else (t.get("verify_error") or t.get("error") or t.get("unverified") or "not verified"))
                      for h, t in session.get("site", {}).get("tls", {}).items()}
    except (OSError, ValueError):
        row["error"] = buf.getvalue().strip().splitlines()[-1] if buf.getvalue().strip() else "no output"
    return row


def main(argv: list[str]) -> int:
    want = [a.lower() for a in argv]
    sites = [s for s in SITES if not want or any(w in s[0].lower() for w in want)]
    if not sites:
        print("no site matches", argv)
        return 2
    print(f"{'site':<22} {'rc':>3} {'sec':>5} {'pages':>5} {'links':>5}  findings (high/medium/low)  notes")
    for name, address, extra in sites:
        r = scan(address, extra)
        f = r["findings"]
        tls = next(iter(r.get("tls", {}).values()), None)
        note = r.get("error") or (f"TLS: {tls[0]}, {tls[1][:50]}" if tls else "")
        print(f"{name:<22} {r['rc']:>3} {r['seconds']:>5} {r['pages']:>5} {r['links']:>5}  {f.get('high', 0)}/{f.get('medium', 0)}/{f.get('low', 0)}  {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
