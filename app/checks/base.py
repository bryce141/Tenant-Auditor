"""Shared plumbing for checks.

Every check used to open with the same guard::

    users = client.get_all("/users")
    if isinstance(users, dict):
        return {"check_name": ..., "status": "skip", ...20 lines...}

That pattern was copy-pasted about 25 times, because GraphClient signalled
failure by returning a dict where a list was expected. The client now raises
GraphError instead, and @check turns it into the same skip result, so the body
of each check only deals with the case where the data arrived.

A skip is not a failure: a missing permission or an unprovisioned workload
means the control was never measured. Scoring excludes skips from the
denominator, so points_possible is still reported for the UI to show what was
at stake.
"""
from functools import wraps

from app.services.graph_client import GraphError


def skip_result(meta, reason):
    """The standard 'could not run' result for a check."""
    return {
        "check_name": meta["check_name"],
        "display_name": meta["display_name"],
        "category": meta["category"],
        "status": "skip",
        "points_earned": None,
        "points_possible": meta.get("points_possible"),
        "summary": reason,
        "issues": [],
        "details": meta.get("empty_details", []),
        "cis_reference": meta.get("cis_reference"),
    }


def check(check_name, display_name, category, points_possible=None,
          cis_reference=None, empty_details=None, also=None):
    """Declare a check's identity and convert GraphError into a skip.

    `also` lists further checks derived from the same data — app registrations
    yields both credential expiry and permissions from one call. Naming them
    here means a failure produces a skip for each, instead of the extra checks
    quietly disappearing from the report and shrinking the visible check count.
    """
    def build(name, display, points, cis):
        return {
            "check_name": name,
            "display_name": display,
            "category": category,
            "points_possible": points,
            "cis_reference": cis,
            "empty_details": [] if empty_details is None else empty_details,
        }

    meta = build(check_name, display_name, points_possible, cis_reference)
    extra_meta = [build(e["check_name"], e["display_name"],
                        e.get("points_possible"), e.get("cis_reference"))
                  for e in (also or [])]

    def decorator(fn):
        @wraps(fn)
        def wrapper(client, *args, **kwargs):
            try:
                return fn(client, *args, **kwargs)
            except GraphError as e:
                reason = str(e)
                if extra_meta:
                    return [skip_result(m, reason) for m in [meta] + extra_meta]
                return skip_result(meta, reason)

        wrapper.check_meta = meta
        return wrapper

    return decorator
