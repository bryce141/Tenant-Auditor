"""Tests for the scheduling entry points.

These are what cron invokes, so the exit code matters as much as the output —
a silently-zero exit on a failed audit means nobody finds out the security
tool stopped working.
"""
import os

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app import create_app, db  # noqa: E402
from app.models.report import Report  # noqa: E402
from app.models.tenant import Tenant  # noqa: E402
from app.services import report_runner  # noqa: E402


@pytest.fixture
def app():
    application = create_app()
    application.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
                              SECRET_KEY="test-key", TESTING=True)
    with application.app_context():
        db.drop_all()
        db.create_all()
        yield application


def make_tenant(app, name, directory_id):
    with app.app_context():
        t = Tenant(name=name, tenant_id=directory_id, client_id="c")
        t.client_secret = "s"
        db.session.add(t)
        db.session.commit()


def stub_checks(monkeypatch, status="pass"):
    """Make run_full succeed without touching the network."""
    monkeypatch.setattr(report_runner, "get_headers", lambda tenant=None: ({}, tenant.tenant_id))
    monkeypatch.setattr(report_runner, "GraphClient", lambda headers: object())
    module = type("M", (), {"run_all": staticmethod(lambda client: [{
        "category": "identity", "check_name": "mfa_registration",
        "display_name": "MFA Registration", "status": status,
        "points_earned": 20 if status == "pass" else 0, "points_possible": 20,
        "summary": "stub", "issues": [],
    }])})
    monkeypatch.setattr(report_runner, "CATEGORY_MAP", {"identity": module})


def test_audit_runs_every_tenant(app, monkeypatch):
    make_tenant(app, "Contoso", "dir-1")
    make_tenant(app, "Fabrikam", "dir-2")
    stub_checks(monkeypatch)

    result = app.test_cli_runner().invoke(args=["audit"])

    assert result.exit_code == 0, result.output
    assert "Contoso" in result.output and "Fabrikam" in result.output
    with app.app_context():
        assert Report.query.filter_by(report_type="full").count() == 2


def test_audit_can_target_one_tenant(app, monkeypatch):
    make_tenant(app, "Contoso", "dir-1")
    make_tenant(app, "Fabrikam", "dir-2")
    stub_checks(monkeypatch)

    result = app.test_cli_runner().invoke(args=["audit", "--tenant", "contoso"])

    assert result.exit_code == 0
    assert "Fabrikam" not in result.output
    with app.app_context():
        assert Report.query.filter_by(report_type="full").count() == 1


def test_unknown_tenant_is_an_error_not_a_silent_no_op(app):
    make_tenant(app, "Contoso", "dir-1")

    result = app.test_cli_runner().invoke(args=["audit", "--tenant", "nope"])

    assert result.exit_code != 0
    assert "No tenant matching" in result.output


def test_audit_exits_nonzero_when_a_tenant_fails(app, monkeypatch):
    """cron needs a failing status code or nobody learns the audit broke."""
    make_tenant(app, "Contoso", "dir-1")

    def boom(tenant=None):
        raise Exception("AADSTS7000222: secret expired")

    monkeypatch.setattr(report_runner, "get_headers", boom)

    result = app.test_cli_runner().invoke(args=["audit"])

    assert result.exit_code == 1


def test_digest_dry_run_prints_and_sends_nothing(app, monkeypatch):
    make_tenant(app, "Contoso", "dir-1")
    sent = []
    monkeypatch.setattr("app.services.mailer.send",
                        lambda *a, **k: sent.append(a))

    result = app.test_cli_runner().invoke(args=["digest", "--dry-run"])

    assert result.exit_code == 0
    assert "Contoso" in result.output
    assert "SMTP configuration" in result.output
    assert sent == [], "dry run must not send"


def test_digest_reports_missing_configuration_clearly(app, monkeypatch):
    make_tenant(app, "Contoso", "dir-1")
    for var in ("SMTP_HOST", "SMTP_FROM", "SMTP_USER", "DIGEST_TO"):
        monkeypatch.delenv(var, raising=False)

    result = app.test_cli_runner().invoke(args=["digest"])

    assert result.exit_code != 0
    assert "SMTP_HOST" in result.output
    assert "--dry-run" in result.output, "should point at the way to preview"


def test_digest_sends_when_configured(app, monkeypatch):
    make_tenant(app, "Contoso", "dir-1")
    captured = {}

    def fake_send(subject, text, html, recipients=None):
        captured.update(subject=subject, text=text, html=html)
        return ["ops@example.com"]

    monkeypatch.setattr("app.services.mailer.send", fake_send)

    result = app.test_cli_runner().invoke(args=["digest"])

    assert result.exit_code == 0
    assert "ops@example.com" in result.output
    assert "Contoso" in captured["text"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
