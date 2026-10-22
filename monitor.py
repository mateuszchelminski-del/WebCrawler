"""monitor.py: crawl a site on a schedule, compare with the last crawl, keep a history, and tell someone what got worse.

    python webcrawler.py https://example.com --quick --monitor ~/monitor/example --fail-on-regression

One folder holds everything:

    sessions/   one session per crawl (the newest N are kept); the newest one is what the next crawl is compared with
    latest/     the report, the changes, the trend chart and the exports of the most recent crawl
    history.json    a row of numbers per crawl, drawn as latest/trend.html
    accepted.json   (optional) findings you decided to live with; used automatically if it exists

Nothing here schedules itself: run the command from Task Scheduler, cron or a CI schedule (`--print-schedule 03:00` prints the exact
lines to use, and docs/examples/monitor.yml is a GitHub Actions workflow). The first run has nothing to compare with and just records
a baseline.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import notify

KEEP_DEFAULT = 30
EXIT_UNREACHABLE = 4
PATH_OPTIONS = ("--monitor", "--accepted", "--cookie-file")
SECRET_OPTIONS = {"--notify-webhook": "WEBCRAWLER_WEBHOOK", "--cookie": "WEBCRAWLER_COOKIE", "--header": "WEBCRAWLER_HEADERS"}
OUTPUTS = ("report.html", "sitemap.html", "graph.json", "links.json", "links.csv", "links.txt", "changes.html", "changes.json", "trend.html",
           "session.json", "results.sarif", "junit.xml")


@dataclass
class Plan:
    root: Path
    latest: Path
    sessions: Path
    history: Path
    accepted: str            # path of the accepted-findings file to use, or ""
    previous: "Path | None"  # the session to compare with
    save: Path               # where this crawl's session goes


def sessions_in(folder: Path) -> list[Path]:
    """Saved sessions, oldest first (the names carry a UTC timestamp)."""
    return sorted(folder.glob("session-*.json")) if folder.is_dir() else []


def prepare(args) -> Plan:
    """Decide the folders and point the crawl's own options (--out, --save, --compare, --history) at them. Raises ValueError for a bad setup."""
    clash = [f for f, v in (("--out", args.out), ("--save", args.save), ("--compare", args.compare), ("--history", args.history), ("--resume", args.resume)) if v]
    if clash:
        raise ValueError(f"--monitor chooses where results go and what to compare with, so {', '.join(clash)} cannot be used with it")
    if not args.target:
        raise ValueError("--monitor needs the site to crawl")
    root = Path(args.monitor).expanduser().resolve()
    if root.exists() and not root.is_dir():
        raise ValueError(f"{root} is not a folder")
    plan = Plan(root, root / "latest", root / "sessions", root / "history.json", args.accepted or "", None, root / "x")
    old = sessions_in(plan.sessions)
    plan.previous = old[-1] if old else None
    if not plan.accepted and (root / "accepted.json").exists():
        plan.accepted = str(root / "accepted.json")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    plan.save = plan.sessions / f"session-{stamp}.json"
    n = 2
    while plan.save.exists():
        plan.save = plan.sessions / f"session-{stamp}-{n}.json"
        n += 1
    plan.sessions.mkdir(parents=True, exist_ok=True)
    plan.latest.mkdir(parents=True, exist_ok=True)
    for name in OUTPUTS:                      # only files this tool writes; never anything else in the folder
        try:
            (plan.latest / name).unlink()
        except FileNotFoundError:
            pass
    args.out, args.save, args.history = str(plan.latest), str(plan.save), str(plan.history)
    args.format = [f for f in args.format if f != "session"] + [f for f in ("sarif",) if f not in args.format]     # the session is saved once, in sessions/
    args.compare = str(plan.previous) if plan.previous else None
    args.accepted = plan.accepted or None
    return plan


def prune(folder: Path, keep: int) -> int:
    """Delete all but the newest `keep` sessions (never fewer than two: the one just made and the one to compare with next time)."""
    old = sessions_in(folder)
    gone = old[:max(0, len(old) - max(2, keep))]
    for p in gone:
        try:
            p.unlink()
        except OSError:
            pass
    return len(gone)


def notifiers(args) -> tuple:
    """(webhook URL or "", SmtpConfig or None) from the options and environment. Raises ValueError if e-mail is half-configured."""
    hook = args.notify_webhook or os.environ.get("WEBCRAWLER_WEBHOOK", "")
    cfg = None
    to = [a.strip() for chunk in (args.notify_email or []) for a in chunk.split(",") if a.strip()]
    if to or args.smtp_host:
        cfg = notify.SmtpConfig(args.smtp_host or "", to, args.smtp_port or (465 if args.smtp_security == "ssl" else 587), args.smtp_from or "", args.smtp_user or "",
                                os.environ.get("WEBCRAWLER_SMTP_PASSWORD", ""), args.smtp_security)
        bad = cfg.check()
        if bad:
            raise ValueError(bad)
    return hook, cfg


def run(args, crawl) -> int:
    """Run `crawl()` (the normal crawl, now writing into the monitor folder), then compare, prune and notify. Returns the exit code."""
    import accepted as accepted_mod
    import snapshot
    plan = prepare(args)
    hook, smtp = notifiers(args)
    level = args.fail_on_regression or "medium"
    print(f"Monitoring {args.target}: " + (f"comparing with {plan.previous.name}" if plan.previous else "first run, recording a baseline") + f"  ({plan.root})")
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rc = crawl()
    site = args.target if "//" in args.target else "https://" + args.target

    failure = ""
    data = None
    if not plan.save.exists():
        failure = "No pages could be fetched (the site may be down, blocking this client, or unreachable from this network)."
    else:
        data = snapshot.load(str(plan.save))
        answered = [n.get("status") for n in snapshot._pages(data).values()]
        if not any(s is not None and 200 <= s < 400 for s in answered):
            worst = next((s for s in answered if s), 0)
            failure = ("The site did not answer (no response before the timeout, or the connection was refused)." if not worst
                       else f"The start page answered HTTP {worst}, so nothing could be checked (the site may be down, or blocking this client).")
            plan.save.unlink()              # a crawl that saw nothing must not become the baseline the next run is compared with...
            import history
            h = history.History.load(plan.history)
            if h.runs:
                h.runs.pop()                # ...nor a point on the trend chart
                h.save(plan.history)
    if failure:
        print(failure, file=sys.stderr)
        _send(hook, smtp, *notify.build_message(site, None, level, failure, when), [], args)
        return EXIT_UNREACHABLE

    note = ""
    if data.get("resume"):
        note = ("This crawl stopped at its limit (pages or time), so pages beyond it were not checked; a page missing from the comparison may only be out of reach. "
                "Raise --max-pages or --max-duration for a complete picture.")
        print("Note: " + note)
    removed = prune(plan.sessions, args.keep)
    if removed:
        print(f"Removed {removed} old session(s); the newest {max(2, args.keep)} are kept.")

    acc = accepted_mod.Accepted.load(plan.accepted) if plan.accepted else None
    diff = snapshot.diff(snapshot.load(str(plan.previous)), data, acc or None) if plan.previous else None
    regs = diff.regressions(level) if diff else []
    if diff is None:
        print("Baseline recorded: the next run will be compared with it.")
    if regs or args.notify_always:
        if diff is not None:
            subject, text = notify.build_message(site, diff, level, "", when)
        else:
            subject, text = f"WebCrawler: baseline crawl of {urlparse(site).netloc}", f"{site} ({when})\nFirst crawl recorded; later crawls are compared with it."
        if note:
            text += "\n\n" + note
        attach = []
        changes = plan.latest / "changes.html"
        if changes.exists():
            attach.append(("changes.html", changes.read_bytes(), "text/html"))
        _send(hook, smtp, subject, text, attach, args, regs=len(regs))
    return rc


def _send(hook: str, smtp, subject: str, text: str, attach: list, args, regs: int = 0) -> None:
    if hook:
        err = notify.send_webhook(hook, subject, text, {"regressions": regs, "site": args.target})
        print(f"Notified the webhook at {notify.describe_webhook(hook)}" if not err else f"Webhook notification failed: {err}", file=sys.stderr if err else sys.stdout)
    if smtp is not None:
        err = notify.send_email(smtp, subject, text, attach)
        print(f"E-mailed {', '.join(smtp.to)}" if not err else f"E-mail notification failed: {err}", file=sys.stderr if err else sys.stdout)


# ------------------------------------------------------------------------------------------------ scheduling

def schedule_commands(argv: list[str], at: str, python: str, script: str, cwd: str) -> dict:
    """The command lines that would run this same monitor every day at `at` (HH:MM). Printed for you to review and run; nothing is created."""
    if not re.fullmatch(r"([01]?\d|2[0-3]):[0-5]\d", at or ""):
        raise ValueError("--print-schedule takes a time of day such as 03:00")
    h, m = at.split(":")
    clean, skip, dropped = [], False, {}
    for a in argv:
        if skip:
            skip = False
            continue
        if a == "--print-schedule" or a in SECRET_OPTIONS:
            skip = True                     # the option and its value; a secret does not belong in a task definition
            if a in SECRET_OPTIONS:
                dropped[a] = SECRET_OPTIONS[a]
            continue
        if a.split("=", 1)[0] in ("--print-schedule", *SECRET_OPTIONS):
            if a.split("=", 1)[0] in SECRET_OPTIONS:
                dropped[a.split("=", 1)[0]] = SECRET_OPTIONS[a.split("=", 1)[0]]
            continue
        clean.append(a)
    # a scheduled task does not start in your folder: make every path absolute
    for i, a in enumerate(clean):
        if a in PATH_OPTIONS and i + 1 < len(clean):
            clean[i + 1] = str(Path(clean[i + 1]).expanduser().resolve())
        elif a.split("=", 1)[0] in PATH_OPTIONS and "=" in a:
            clean[i] = a.split("=", 1)[0] + "=" + str(Path(a.split("=", 1)[1]).expanduser().resolve())
    inner = subprocess.list2cmdline([python, script, *clean])
    win = f'schtasks /Create /SC DAILY /ST {int(h):02d}:{m} /TN "WebCrawler monitor" /TR "{inner.replace(chr(34), chr(92) + chr(34))}"'
    cron = f"{int(m)} {int(h)} * * * cd {shlex.quote(cwd)} && {shlex.join([python, script, *clean])}"
    return {"windows": win, "cron": cron, "args": clean, "dropped": dropped}
