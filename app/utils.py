"""Small shared helpers."""
import re
from datetime import datetime, timezone
from html import unescape

_TAG = re.compile(r"<[^>]+>")
_WHITESPACE = re.compile(r"\s+")


def strip_html(value):
    """Plain text from a snippet of HTML.

    Microsoft returns Secure Score remediation guidance as markup, which we
    display as text — so without this the user reads "<ol><li>Go to Microsoft
    Entra ID &gt; ...". List items become sentence breaks rather than running
    together.
    """
    if not value:
        return ""
    text = re.sub(r"</(li|p|div|tr)>", ". ", value, flags=re.IGNORECASE)
    text = re.sub(r"<br\s*/?>", " ", text, flags=re.IGNORECASE)
    text = _TAG.sub("", text)
    text = unescape(text)
    text = _WHITESPACE.sub(" ", text).strip()
    # Collapse the punctuation the substitutions above can double up.
    text = re.sub(r"\s*\.\s*\.", ".", text)
    return re.sub(r"\s+([.,;:])", r"\1", text).strip(" .") or ""


def utcnow():
    """Current UTC time as a naive datetime.

    datetime.utcnow() is deprecated in Python 3.12+ and slated for removal, but
    its replacement returns an aware datetime. The DateTime columns in
    app/models/report.py are naive, and mixing the two raises TypeError on
    comparison, so the offset is stripped here to keep stored values identical
    to what utcnow() produced. Making the columns timezone-aware instead would
    need a migration against existing databases.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)
