"""accepted.py: findings you have looked at and decided to live with.

A crawl of a site you run keeps reporting the same things (a CSP that needs 'unsafe-inline', a login page that is meant to be public).
Marking them *accepted* stops them showing up as new problems and failing a build, without hiding them: they are still listed, as accepted,
with the reason, and an acceptance can carry an expiry date so it comes back for another look.

The file is plain JSON you can keep in the repository next to the code it describes:

    {"format": "webcrawler-accepted", "version": 1, "accepted": [
        {"code": "no-csp", "where": "https://example.com/*", "reason": "static pages, no scripts", "expires": "2027-06-30"}]}

`code` and `where` are glob patterns (* and ?), matched case-insensitively; `where` is a URL or, for site-wide findings, a host or domain.
"""
from __future__ import annotations

import fnmatch
import json
import os
import tempfile
from datetime import date, datetime
from pathlib import Path

FORMAT = "webcrawler-accepted"
VERSION = 1
MAX_ENTRIES = 2000


def _day(value: str) -> date | None:
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d").date()
    except (ValueError, AttributeError):
        return None


def _glob(pattern: str, text: str) -> bool:
    return fnmatch.fnmatchcase((text or "").lower(), (pattern or "*").lower())


class Accepted:
    def __init__(self, entries: list | None = None, today: date | None = None) -> None:
        self.entries: list[dict] = [dict(e) for e in (entries or [])]
        self.today = today or date.today()

    # ------------------------------------------------------------------ files
    @classmethod
    def load(cls, path: str | os.PathLike | None, today: date | None = None) -> "Accepted":
        """The acceptances in a file. A file that does not exist is an empty list (so a standing --accepted path works before the first entry)."""
        if not path:
            return cls(today=today)
        p = Path(path).expanduser()
        if not p.exists():
            return cls(today=today)
        if p.stat().st_size > 5 * 1024 * 1024:
            raise ValueError(f"{p} is too large to be an accepted-findings file")
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"{p} is not valid JSON: {e}")
        if not isinstance(data, dict) or data.get("format") != FORMAT:
            raise ValueError(f"{p} is not a WebCrawler accepted-findings file (format should be '{FORMAT}')")
        out = []
        for i, e in enumerate(data.get("accepted", [])[:MAX_ENTRIES]):
            if not isinstance(e, dict) or not str(e.get("code", "")).strip():
                raise ValueError(f"{p}: entry {i + 1} has no 'code'")
            if e.get("expires") and _day(str(e["expires"])) is None:
                raise ValueError(f"{p}: entry {i + 1} has an expiry of '{e['expires']}': write it as YYYY-MM-DD")
            out.append({"code": str(e["code"]).strip(), "where": str(e.get("where") or "*").strip(), "reason": str(e.get("reason", "")),
                        "expires": str(e.get("expires", "")), "added": str(e.get("added", ""))})
        return cls(out, today)

    def save(self, path: str | os.PathLike) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=p.name + ".", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                json.dump({"format": FORMAT, "version": VERSION, "accepted": self.entries}, f, indent=2)
                f.write("\n")
            os.replace(tmp, p)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------ editing
    def add(self, code: str, where: str = "*", reason: str = "", expires: str = "") -> dict:
        """Accept a finding (or a pattern of them). Accepting the same code and place again replaces the earlier entry."""
        code, where = code.strip(), (where or "*").strip()
        if not code:
            raise ValueError("say which finding to accept (its code, such as no-csp)")
        if expires and _day(expires) is None:
            raise ValueError(f"expiry '{expires}' is not a date: write it as YYYY-MM-DD")
        if len(self.entries) >= MAX_ENTRIES:
            raise ValueError("too many accepted findings in one file")
        entry = {"code": code, "where": where, "reason": reason.strip(), "expires": expires.strip(), "added": self.today.isoformat()}
        self.entries = [e for e in self.entries if (e["code"].lower(), e["where"].lower()) != (code.lower(), where.lower())]
        self.entries.append(entry)
        return entry

    def remove(self, code: str, where: str = "*") -> bool:
        before = len(self.entries)
        self.entries = [e for e in self.entries if (e["code"].lower(), e["where"].lower()) != (code.strip().lower(), (where or "*").strip().lower())]
        return len(self.entries) != before

    # ------------------------------------------------------------------ asking
    def is_expired(self, entry: dict) -> bool:
        d = _day(entry.get("expires", ""))
        return d is not None and d < self.today

    def match(self, code: str, where: str) -> dict | None:
        """The active acceptance covering this finding, or None. An expired one does not count."""
        for e in self.entries:
            if _glob(e["code"], code) and _glob(e["where"], where) and not self.is_expired(e):
                return e
        return None

    def lapsed(self, code: str, where: str) -> dict | None:
        """An acceptance that would cover this finding but has expired (so it can say: accepted until 2026-06-30, look again)."""
        for e in self.entries:
            if _glob(e["code"], code) and _glob(e["where"], where) and self.is_expired(e):
                return e
        return None

    def __bool__(self) -> bool:
        return bool(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def split(self, findings: list[dict]) -> tuple[list[dict], list[dict]]:
        """(open, accepted) from finding dicts with `code` and `where`. Each accepted one gains `accepted_reason`."""
        open_, done = [], []
        for f in findings:
            e = self.match(f.get("code", ""), f.get("where", ""))
            if e is None:
                open_.append(f)
            else:
                done.append({**f, "accepted_reason": e.get("reason", ""), "accepted_until": e.get("expires", "")})
        return open_, done

    def unused(self, findings: list[dict]) -> list[dict]:
        """Acceptances that matched nothing in `findings`: the problem is gone (or the pattern is wrong), so the entry can be removed."""
        return [e for e in self.entries if not any(_glob(e["code"], f.get("code", "")) and _glob(e["where"], f.get("where", "")) for f in findings)]
