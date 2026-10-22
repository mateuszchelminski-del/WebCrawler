"""notify.py: tell someone when a monitored site got worse.

Two ways, both optional and both off unless you configure them:

  * a webhook: one JSON POST, which Slack, Discord and Microsoft Teams incoming-webhook URLs (and any service that takes JSON) accept;
  * e-mail through an SMTP server you name, with the change report attached.

Nothing is sent unless a crawl found regressions (or you ask for every run), and what is sent is the summary and the first few changes,
never cookies or logins. The webhook URL and the SMTP password are secrets: they come from the environment (WEBCRAWLER_WEBHOOK,
WEBCRAWLER_SMTP_PASSWORD) so they stay out of your shell history, and they are never printed.
"""
from __future__ import annotations

import json
import smtplib
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from urllib.parse import urlparse

MAX_LINES = 12
MAX_TEXT = 3500


def build_message(site: str, diff, level: str = "medium", failure: str = "", when: str = "") -> tuple[str, str]:
    """(subject, body) for a notification: a failure to crawl, or the regressions between two crawls."""
    host = urlparse(site).netloc or site
    stamp = f" ({when})" if when else ""
    if failure:
        return f"WebCrawler: could not crawl {host}", f"The monitored crawl of {site}{stamp} did not complete.\n{failure}"
    regs = diff.regressions(level)
    subject = f"WebCrawler: {len(regs)} regression(s) on {host}" if regs else f"WebCrawler: {host} crawled, no regressions"
    lines = [f"{site}{stamp}", diff.summary(), ""]
    mark = {"high": "HIGH  ", "medium": "MEDIUM", "low": "LOW   ", "info": "info  "}
    for c in regs[:MAX_LINES]:
        lines.append(f"[{mark.get(c.severity, c.severity)}] {c.subject}" + (f" - {c.detail}" if c.detail else ""))
    if len(regs) > MAX_LINES:
        lines.append(f"... and {len(regs) - MAX_LINES} more (see the attached or saved changes report)")
    text = "\n".join(lines)
    return subject, text if len(text) <= MAX_TEXT else text[:MAX_TEXT - 20] + "\n... (shortened)"


# ------------------------------------------------------------------------------------------------ webhook

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def describe_webhook(url: str) -> str:
    """The webhook for display: its host only, because the path is usually the secret."""
    return urlparse(url).netloc or "webhook"


def send_webhook(url: str, subject: str, text: str, details: dict | None = None, timeout: float = 15.0) -> str:
    """POST the message as JSON. Returns "" on success, else a short description of what went wrong (the URL is never part of it)."""
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.netloc:
        return "the webhook URL must start with http:// or https://"
    body = json.dumps({"text": f"{subject}\n{text}", "content": f"{subject}\n{text}", "subject": subject, "message": text, **(details or {})}).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json", "User-Agent": "WebCrawler-monitor"})
    try:
        with urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout) as r:
            r.read(2048)
            return "" if 200 <= r.status < 300 else f"the webhook answered HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return f"the webhook answered HTTP {e.code}" + (" (a redirect: use the final URL)" if 300 <= e.code < 400 else "")
    except (urllib.error.URLError, OSError, ValueError) as e:
        return f"could not reach the webhook ({getattr(e, 'reason', e).__class__.__name__})"


# ------------------------------------------------------------------------------------------------ e-mail

@dataclass
class SmtpConfig:
    host: str
    to: list = field(default_factory=list)
    port: int = 587
    sender: str = ""
    user: str = ""
    password: str = ""
    security: str = "starttls"        # starttls | ssl | none

    def check(self) -> str:
        """"" if this can be used, else why not."""
        if not self.host or not self.to:
            return "e-mail needs --smtp-host and at least one --notify-email address"
        if self.security not in ("starttls", "ssl", "none"):
            return "--smtp-security must be starttls, ssl or none"
        local = self.host in ("localhost", "127.0.0.1", "::1")
        if self.password and self.security == "none" and not local:
            return "refusing to send an SMTP password without encryption: use --smtp-security starttls or ssl"
        return ""


def send_email(cfg: SmtpConfig, subject: str, text: str, attachments: list | None = None, timeout: float = 20.0) -> str:
    """Send the message (with attachments as (filename, bytes, 'type/subtype')). Returns "" on success, else what went wrong."""
    bad = cfg.check()
    if bad:
        return bad
    msg = EmailMessage()
    msg["Subject"] = subject.replace("\r", " ").replace("\n", " ")
    msg["From"] = cfg.sender or cfg.user or "webcrawler@localhost"
    msg["To"] = ", ".join(cfg.to)
    msg.set_content(text)
    for name, data, mime in attachments or []:
        main, _, sub = mime.partition("/")
        msg.add_attachment(data, maintype=main, subtype=sub or "octet-stream", filename=name)
    try:
        if cfg.security == "ssl":
            smtp = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=timeout, context=ssl.create_default_context())
        else:
            smtp = smtplib.SMTP(cfg.host, cfg.port, timeout=timeout)
        with smtp:
            if cfg.security == "starttls":
                smtp.starttls(context=ssl.create_default_context())
            if cfg.user:
                smtp.login(cfg.user, cfg.password)
            smtp.send_message(msg)
        return ""
    except smtplib.SMTPAuthenticationError:
        return "the mail server refused the user name or password"
    except (smtplib.SMTPException, OSError, ssl.SSLError) as e:
        return f"could not send the e-mail ({e.__class__.__name__}: {str(e)[:120]})"
