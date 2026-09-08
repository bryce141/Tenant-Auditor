"""Tests for the SSPR check.

allowedToUseSSPR is a boolean. It was compared against the string "none", and
`False != "none"` is True, so a tenant with SSPR switched off was reported as
passing with full marks. A false pass is the worst failure mode an audit tool
has, so both states are pinned here.
"""
import pytest

from app.checks.identity import check_sspr
from app.services.graph_client import GraphError


class Client:
    def __init__(self, payload):
        self.payload = payload

    def get_one(self, endpoint, params=None, beta=False):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


def test_sspr_disabled_fails():
    result = check_sspr(Client({"allowedToUseSSPR": False}))

    assert result["status"] == "fail", "SSPR off must not report as passing"
    assert result["points_earned"] == 0, "SSPR off must not be awarded points"
    assert result["issues"]


def test_sspr_enabled_passes():
    result = check_sspr(Client({"allowedToUseSSPR": True}))

    assert result["status"] == "pass"
    assert result["points_earned"] == 5
    assert result["issues"] == []


def test_summary_does_not_leak_the_raw_boolean():
    """The old summary rendered 'scope: True', which means nothing to a reader."""
    for value in (True, False):
        summary = check_sspr(Client({"allowedToUseSSPR": value}))["summary"]
        assert "True" not in summary and "False" not in summary


def test_missing_field_skips_rather_than_guessing():
    """Absent is unknown. Defaulting either way would be a fabricated result."""
    result = check_sspr(Client({}))

    assert result["status"] == "skip"
    assert result["points_earned"] is None


def test_graph_failure_skips():
    result = check_sspr(Client(GraphError("Insufficient permissions", status=403)))
    assert result["status"] == "skip"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
