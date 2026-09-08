"""Small shared helpers."""
from datetime import datetime, timezone


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
