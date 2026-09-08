"""Sending mail over SMTP.

Deliberately stdlib-only. A digest is a handful of messages a day at most, so
an API-based provider would add a dependency and an account for no benefit, and
SMTP works with anything the user already has.

Configuration comes from the environment:

    SMTP_HOST       required to send
    SMTP_PORT       default 587
    SMTP_USER       optional; omit for a relay that doesn't authenticate
    SMTP_PASSWORD   optional
    SMTP_FROM       defaults to SMTP_USER
    SMTP_TLS        "false" to disable STARTTLS, default on
    DIGEST_TO       comma-separated recipients
"""
import os
import smtplib
from email.message import EmailMessage


class MailNotConfigured(Exception):
    """SMTP settings are absent or incomplete."""


def config():
    return {
        "host": os.getenv("SMTP_HOST", "").strip(),
        "port": int(os.getenv("SMTP_PORT", "587")),
        "user": os.getenv("SMTP_USER", "").strip(),
        "password": os.getenv("SMTP_PASSWORD", ""),
        "sender": (os.getenv("SMTP_FROM") or os.getenv("SMTP_USER", "")).strip(),
        "tls": os.getenv("SMTP_TLS", "true").lower() != "false",
        "recipients": [a.strip() for a in os.getenv("DIGEST_TO", "").split(",") if a.strip()],
    }


def is_configured():
    c = config()
    return bool(c["host"] and c["sender"] and c["recipients"])


def describe_config():
    """What is set, for diagnostics. Never returns the password."""
    c = config()
    return {
        "host": c["host"] or "(unset)",
        "port": c["port"],
        "user": c["user"] or "(unset)",
        "from": c["sender"] or "(unset)",
        "tls": c["tls"],
        "recipients": c["recipients"] or ["(unset)"],
        "password_set": bool(c["password"]),
    }


def build_message(subject, text_body, html_body, sender, recipients):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    # Plain text first so a text-only client shows something useful rather than
    # falling back to stripped markup.
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")
    return msg


def send(subject, text_body, html_body, recipients=None):
    """Send one message. Raises MailNotConfigured if SMTP isn't set up."""
    c = config()
    to = recipients or c["recipients"]

    missing = [k for k, v in (("SMTP_HOST", c["host"]),
                              ("SMTP_FROM or SMTP_USER", c["sender"]),
                              ("DIGEST_TO", to)) if not v]
    if missing:
        raise MailNotConfigured("Not configured: " + ", ".join(missing))

    msg = build_message(subject, text_body, html_body, c["sender"], to)

    with smtplib.SMTP(c["host"], c["port"], timeout=30) as smtp:
        if c["tls"]:
            smtp.starttls()
        if c["user"]:
            smtp.login(c["user"], c["password"])
        smtp.send_message(msg)

    return to
