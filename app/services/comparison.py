"""Comparing an audit against the one before it.

Every run has been stored since the beginning and nothing ever read two of
them together. "Four new findings since last week, MFA now covered" is the
thing that makes an audit worth opening on a schedule rather than once.

Checks are matched by check_name. A check that appears or disappears between
runs is handled explicitly: a control that has only just become measurable is
not the same event as one that regressed.
"""
FINDING_STATUSES = {"fail", "warn"}
RESOLVED_FROM = {"fail", "warn"}


def is_finding(status):
    return status in FINDING_STATUSES


def find_previous(report, Report):
    """The completed run immediately before this one, same tenant and type."""
    if report is None or report.created_at is None:
        return None
    return (Report.query
            .filter(Report.report_type == report.report_type,
                    Report.tenant_id == report.tenant_id,
                    Report.status == "complete",
                    Report.created_at < report.created_at)
            .order_by(Report.created_at.desc())
            .first())


def compare(current, previous):
    """Diff two reports.

    Returns None when there is nothing meaningful to compare against, so
    callers can omit the section entirely rather than render an empty one.
    """
    if current is None or previous is None:
        return None

    now = {c.check_name: c for c in current.checks}
    before = {c.check_name: c for c in previous.checks}
    if not now or not before:
        return None

    new_findings, resolved, regressed, improved = [], [], [], []

    for name, check in now.items():
        prior = before.get(name)

        if prior is None:
            # Newly present. Only interesting if it arrives as a problem.
            if is_finding(check.status):
                new_findings.append({"check": check, "previous_status": None})
            continue

        if is_finding(check.status) and not is_finding(prior.status):
            new_findings.append({"check": check, "previous_status": prior.status})
        elif is_finding(prior.status) and check.status == "pass":
            resolved.append({"check": check, "previous_status": prior.status})

        # A warn becoming a fail is a regression even though both are findings.
        if prior.status == "warn" and check.status == "fail":
            regressed.append({"check": check, "previous_status": prior.status})
        elif prior.status == "fail" and check.status == "warn":
            improved.append({"check": check, "previous_status": prior.status})

    # Checks that vanished — usually a permission was revoked, so the control
    # is no longer being measured at all. Worth surfacing, not silently dropping.
    no_longer_measured = [before[n] for n in before.keys() - now.keys()]

    score_delta = None
    if current.score is not None and previous.score is not None:
        score_delta = current.score - previous.score

    has_changes = any([new_findings, resolved, regressed, improved,
                       no_longer_measured, score_delta])
    if not has_changes:
        return {"unchanged": True, "previous": previous, "score_delta": 0,
                "new_findings": [], "resolved": [], "regressed": [],
                "improved": [], "no_longer_measured": []}

    return {
        "unchanged": False,
        "previous": previous,
        "score_delta": score_delta,
        "new_findings": new_findings,
        "resolved": resolved,
        "regressed": regressed,
        "improved": improved,
        "no_longer_measured": no_longer_measured,
    }


def headline(diff):
    """One sentence for the top of a report or panel."""
    if diff is None:
        return None
    if diff.get("unchanged"):
        return "No change since the previous audit."

    parts = []
    if diff["new_findings"]:
        n = len(diff["new_findings"])
        parts.append(f"{n} new finding{'s' if n != 1 else ''}")
    if diff["resolved"]:
        n = len(diff["resolved"])
        parts.append(f"{n} resolved")
    if diff["regressed"]:
        n = len(diff["regressed"])
        parts.append(f"{n} worsened")
    if diff["no_longer_measured"]:
        n = len(diff["no_longer_measured"])
        parts.append(f"{n} no longer measured")

    if not parts:
        delta = diff.get("score_delta") or 0
        if delta:
            return f"Score {'up' if delta > 0 else 'down'} {abs(delta)} points, no change to individual checks."
        return "No change since the previous audit."

    return ", ".join(parts).capitalize() + " since the previous audit."
