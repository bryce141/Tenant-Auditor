"""Tests for the scoring aggregate.

The dashboard and security page used to sum points by hand, which counted
skipped checks in the denominator. A tenant was penalised for a control that
was never measured, and the dashboard reported a different score (37) from the
report generated off the same run (41).
"""
from types import SimpleNamespace

import pytest

from app.services.scoring import calculate_security_score


def row(earned, possible):
    return SimpleNamespace(points_earned=earned, points_possible=possible)


def test_skipped_check_does_not_lower_the_score():
    """A control that couldn't run contributes to neither side of the ratio."""
    without_skip = calculate_security_score([row(41, 100)])
    with_skip = calculate_security_score([row(41, 100), row(None, 10)])

    assert with_skip["overall"] == without_skip["overall"] == 41
    assert with_skip["possible"] == 100, "skipped weight must stay out of the denominator"


def test_accepts_dicts_and_rows_identically():
    as_rows = calculate_security_score([row(8, 10), row(None, 5)])
    as_dicts = calculate_security_score([{"points_earned": 8, "points_possible": 10},
                                         {"points_earned": None, "points_possible": 5}])
    assert as_rows == as_dicts


def test_zero_earned_still_counts_against_you():
    """A failing check is measured — unlike a skip, it belongs in the denominator."""
    result = calculate_security_score([row(0, 20), row(10, 10)])
    assert result == {"overall": 33, "earned": 10, "possible": 30}


def test_all_skipped_yields_zero_not_a_crash():
    assert calculate_security_score([row(None, 10), row(None, 5)]) == {
        "overall": 0, "earned": 0, "possible": 0}


def test_empty_input():
    assert calculate_security_score([])["overall"] == 0


def test_informational_checks_are_ignored():
    """Checks with no weight at all must not affect the ratio."""
    assert calculate_security_score([row(5, 5), row(None, None)])["overall"] == 100


def test_matches_the_live_tenant_figures():
    """Reproduces the real run that surfaced the discrepancy."""
    checks = [row(0, 20), row(10, 10), row(4, 10), row(5, 5), row(5, 5),
              row(0, 15), row(0, 10), row(0, 4),
              row(8, 8), row(None, 10), row(4, 8), row(5, 5)]
    result = calculate_security_score(checks)
    assert result["earned"] == 41
    assert result["possible"] == 100, "the skipped 10-point check is excluded"
    assert result["overall"] == 41, "not 37, which is what summing by hand gave"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
