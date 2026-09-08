"""Presentation helpers.

Internal identifiers were reaching the UI directly — report rows showed
"mail_security" and "conditional_access", and timestamps rendered as
"2026-09-08 03:10". Both are the kind of detail that makes an otherwise
competent interface read as unfinished, so the mapping lives here and is
registered as Jinja filters rather than repeated per template.
"""
from datetime import datetime, timedelta

from app.utils import utcnow

REPORT_TYPE_LABELS = {
    "full": "Full audit",
    "identity": "Identity & Access",
    "conditional_access": "Conditional Access",
    "mail_security": "Mail Security",
    "licensing": "Licensing",
    "users": "Users",
    "sharepoint": "SharePoint",
    "exchange": "Exchange",
    "groups": "Groups",
    "security": "Security",
}

# Categories get their own accent so a report list scans by colour rather than
# by reading every label. Security-scored categories share the blue family;
# inventory categories are deliberately quieter.
REPORT_TYPE_ACCENTS = {
    "full": "bg-blue-500/10 text-blue-300 border-blue-500/25",
    "identity": "bg-indigo-500/10 text-indigo-300 border-indigo-500/25",
    "conditional_access": "bg-indigo-500/10 text-indigo-300 border-indigo-500/25",
    "mail_security": "bg-indigo-500/10 text-indigo-300 border-indigo-500/25",
    "licensing": "bg-slate-500/10 text-slate-400 border-slate-500/25",
    "users": "bg-slate-500/10 text-slate-400 border-slate-500/25",
    "sharepoint": "bg-slate-500/10 text-slate-400 border-slate-500/25",
    "exchange": "bg-slate-500/10 text-slate-400 border-slate-500/25",
    "groups": "bg-slate-500/10 text-slate-400 border-slate-500/25",
}

DEFAULT_ACCENT = "bg-slate-500/10 text-slate-400 border-slate-500/25"


def report_type_label(value):
    """'mail_security' -> 'Mail Security'. Falls back to title-casing."""
    if not value:
        return "—"
    return REPORT_TYPE_LABELS.get(value, value.replace("_", " ").title())


def report_type_accent(value):
    return REPORT_TYPE_ACCENTS.get(value, DEFAULT_ACCENT)


def relative_time(value):
    """'2 hours ago'. Absolute dates past a week, where 'ago' stops helping."""
    if not value:
        return "—"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value

    delta = utcnow() - value
    seconds = delta.total_seconds()

    if seconds < 0:
        return "just now"
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        minutes = int(seconds // 60)
        return f"{minutes} min ago" if minutes > 1 else "1 min ago"
    if seconds < 86400:
        hours = int(seconds // 3600)
        return f"{hours} hours ago" if hours > 1 else "1 hour ago"
    if seconds < 172800:
        return "yesterday"
    if seconds < 604800:
        return f"{int(seconds // 86400)} days ago"
    return value.strftime("%d %b %Y")


def short_datetime(value):
    """'8 Sep, 15:04' — for tooltips and anywhere exactness matters."""
    if not value:
        return "—"
    return value.strftime("%-d %b %Y, %H:%M")


def score_tone(score):
    """Colour class for a score. Only genuinely poor scores get alarm colour.

    Painting every score red destroys the signal — the point of a colour is
    that it distinguishes.
    """
    if score is None:
        return "text-slate-500"
    if score >= 80:
        return "text-emerald-400"
    if score >= 60:
        return "text-amber-400"
    if score >= 40:
        return "text-orange-400"
    return "text-red-400"


def distinct_history(reports):
    """Collapse score history to one point per day, keeping the last.

    Category reports written seconds apart during one full audit otherwise
    produce several points sharing an axis label, drawing a flat line that
    looks like a rendering fault rather than a trend.
    """
    by_day = {}
    for r in reports:
        if r.created_at is None or r.score is None:
            continue
        by_day[r.created_at.date()] = r
    return [by_day[d] for d in sorted(by_day)]


def register(app):
    app.jinja_env.filters["report_type"] = report_type_label
    app.jinja_env.filters["type_accent"] = report_type_accent
    app.jinja_env.filters["relative_time"] = relative_time
    app.jinja_env.filters["short_datetime"] = short_datetime
    app.jinja_env.filters["score_tone"] = score_tone
