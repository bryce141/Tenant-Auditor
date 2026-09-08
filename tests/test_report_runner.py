"""Tests for run orchestration.

Token acquisition happens before any Report row exists, so an auth failure
used to leave no trace at all — the UI showed nothing and a bad secret was
indistinguishable from a button that never fired.
"""
import os

import pytest

os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from app import create_app, db  # noqa: E402
from app.models.report import Report  # noqa: E402
from app.services import report_runner  # noqa: E402


@pytest.fixture
def app():
    application = create_app()
    application.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///:memory:", TESTING=True)
    with application.app_context():
        db.drop_all()
        db.create_all()
        yield application


def test_auth_failure_records_a_failed_report(app, monkeypatch):
    def boom(tenant=None):
        raise Exception("AADSTS7000222: client secret is expired")

    monkeypatch.setattr(report_runner, "get_headers", boom)
    report_runner.run_category("identity", app.app_context())

    reports = Report.query.all()
    assert len(reports) == 1, "auth failure must leave a record, not vanish"
    assert reports[0].status == "failed"
    assert reports[0].report_type == "identity"
    assert "AADSTS7000222" in reports[0].error
    assert reports[0].completed_at is not None


def test_failed_report_does_not_look_like_a_running_one(app, monkeypatch):
    """A failed run must not wedge the UI into a permanent 'running' state."""
    monkeypatch.setattr(report_runner, "get_headers",
                        lambda tenant=None: (_ for _ in ()).throw(Exception("nope")))
    report_runner.run_category("identity", app.app_context())

    assert report_runner.get_running_report("identity") is None
    assert report_runner.get_latest_report("identity") is None, \
        "a failed run is not a completed run"


def test_full_run_auth_failure_clears_the_progress_overlay(app, monkeypatch):
    monkeypatch.setattr(report_runner, "get_headers",
                        lambda tenant=None: (_ for _ in ()).throw(Exception("bad secret")))
    report_runner.run_full(app.app_context())

    progress = report_runner.get_run_progress()
    assert progress["running"] is False, "overlay would otherwise spin forever"
    assert "bad secret" in progress["message"]

    reports = Report.query.filter_by(report_type="full").all()
    assert len(reports) == 1
    assert reports[0].status == "failed"


def test_full_run_attaches_checks_to_the_full_report(app, monkeypatch):
    """A full report used to carry a score and no checks, so exports came out empty."""
    monkeypatch.setattr(report_runner, "get_headers", lambda tenant=None: ({}, "tenant-1"))
    monkeypatch.setattr(report_runner, "GraphClient", lambda headers: object())

    def fake_module(category):
        return type("M", (), {"run_all": staticmethod(lambda client: [{
            "category": category, "check_name": f"{category}_check",
            "display_name": f"{category} check", "status": "pass",
            "points_earned": 5, "points_possible": 5, "summary": "ok", "issues": [],
        }])})

    monkeypatch.setattr(report_runner, "CATEGORY_MAP",
                        {"identity": fake_module("identity"),
                         "licensing": fake_module("licensing")})

    report_runner.run_full(app.app_context())

    full = Report.query.filter_by(report_type="full").one()
    assert full.status == "complete"
    assert len(full.checks) == 2, "full report must carry its own checks, not just a score"

    # Category reports still exist independently, for the dashboard tiles.
    assert Report.query.filter_by(report_type="identity").count() == 1
    assert Report.query.filter_by(report_type="licensing").count() == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
