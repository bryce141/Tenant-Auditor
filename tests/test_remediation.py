"""Guards the guidance table against drifting away from the checks.

The original CHECK_INFO object had six keys written against check names that
no longer existed, so the help button silently did nothing on half the scored
checks. Nothing caught it because nothing compared the two lists. These tests
do, in both directions.
"""
import re
from pathlib import Path

import pytest

from app.services import remediation
from app.services.scoring import CIS_MAP

CHECKS_DIR = Path(__file__).resolve().parent.parent / "app" / "checks"


def actual_check_names():
    """Every check_name literal returned by the check modules."""
    names = set()
    for path in CHECKS_DIR.glob("*.py"):
        names.update(re.findall(r'"check_name":\s*"([a-z_]+)"', path.read_text()))
    return names


def test_check_modules_were_found():
    """Guard the guard — a bad glob would make every other test vacuously pass."""
    names = actual_check_names()
    assert len(names) > 20, f"only found {len(names)} check names; is the path right?"
    assert "mfa_registration" in names


def test_every_check_has_guidance():
    missing = actual_check_names() - set(remediation.GUIDANCE)
    assert not missing, f"checks with no guidance (help button will do nothing): {sorted(missing)}"


def test_no_orphaned_guidance():
    orphans = set(remediation.GUIDANCE) - actual_check_names()
    assert not orphans, f"guidance keyed to checks that don't exist: {sorted(orphans)}"


@pytest.mark.parametrize("check_name", sorted(remediation.GUIDANCE))
def test_entry_is_complete(check_name):
    entry = remediation.GUIDANCE[check_name]
    for field in ("title", "severity", "what", "why", "fix"):
        assert entry.get(field), f"{check_name} is missing '{field}'"
    assert entry["severity"] in remediation.SEVERITY_ORDER, \
        f"{check_name} has unknown severity {entry['severity']!r}"


@pytest.mark.parametrize("check_name", sorted(remediation.GUIDANCE))
def test_portal_links_are_plausible(check_name):
    portal = remediation.GUIDANCE[check_name].get("portal")
    if portal:
        assert portal.startswith("https://"), f"{check_name} portal link is not https"
        assert "microsoft.com" in portal, f"{check_name} portal link is off-domain"


def test_scored_checks_are_not_marked_info():
    """Anything carrying CIS-mapped points is a real finding, not an FYI."""
    for check_name in CIS_MAP:
        entry = remediation.GUIDANCE.get(check_name)
        assert entry, f"scored check {check_name} has no guidance"
        assert entry["severity"] != "info", \
            f"{check_name} is scored against {CIS_MAP[check_name]['id']} but marked info"


def test_severity_sorting_puts_worst_first():
    names = ["password_policy", "mfa_registration", "guest_users", "app_permissions"]
    assert sorted(names, key=remediation.sort_key) == [
        "mfa_registration",   # critical
        "app_permissions",    # high
        "password_policy",    # low
        "guest_users",        # info
    ]


def test_severity_of_unknown_check_defaults_to_info():
    assert remediation.severity_of("does_not_exist") == "info"
    assert remediation.get("does_not_exist") is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
