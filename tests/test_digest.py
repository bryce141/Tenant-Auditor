"""Tests for the scheduled digest and its delivery."""
import os
from datetime import timedelta

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app import create_app, db  # noqa: E402
from app.models.report import Report, ReportCheck  # noqa: E402
from app.models.tenant import Tenant  # noqa: E402
from app.services import mailer  # noqa: E402
from app.services.digest import build, collect, subject_line  # noqa: E402
from app.utils import utcnow  # noqa: E402


@pytest.fixture
def app():
    application = create_app()
    application.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
                              SECRET_KEY="test-key", TESTING=True)
    with application.app_context():
        db.drop_all()
        db.create_all()
        yield application


@pytest.fixture(autouse=True)
def clean_smtp_env(monkeypatch):
    for var in ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD",
                "SMTP_FROM", "SMTP_TLS", "DIGEST_TO"):
        monkeypatch.delenv(var, raising=False)


def make_tenant(name, directory_id):
    t = Tenant(name=name, tenant_id=directory_id, client_id="c")
    t.client_secret = "s"
    db.session.add(t)
    db.session.commit()
    return t


def make_report(directory_id, checks, score, days_ago=0):
    r = Report(tenant_id=directory_id, report_type="full", status="complete",
               score=score, created_at=utcnow() - timedelta(days=days_ago))
    db.session.add(r)
    db.session.commit()
    for name, status in checks.items():
        db.session.add(ReportCheck(report_id=r.id, category="identity", check_name=name,
                                   display_name=name.replace("_", " ").title(),
                                   status=status, summary=f"{name} summary"))
    db.session.commit()
    return r


# ---------------------------------------------------------------- ordering

def test_worst_scoring_tenant_comes_first(app):
    a = make_tenant("Healthy", "dir-1")
    b = make_tenant("Struggling", "dir-2")
    make_report("dir-1", {"mfa_registration": "pass"}, score=90)
    make_report("dir-2", {"mfa_registration": "fail"}, score=20)

    names = [e["tenant"].name for e in collect([a, b])]
    assert names == ["Struggling", "Healthy"]


def test_unaudited_tenants_sort_last(app):
    a = make_tenant("Never audited", "dir-1")
    b = make_tenant("Audited", "dir-2")
    make_report("dir-2", {"mfa_registration": "fail"}, score=10)

    entries = collect([a, b])
    assert entries[-1]["tenant"].name == "Never audited"
    assert entries[-1]["report"] is None
    assert "No audit has run yet" in entries[-1]["headline"]


def test_findings_within_a_tenant_are_severity_ranked(app):
    t = make_tenant("Contoso", "dir-1")
    make_report("dir-1", {"password_policy": "warn",     # low
                          "mfa_registration": "fail",    # critical
                          "app_permissions": "fail"},    # high
                score=40)

    findings = collect([t])[0]["findings"]
    assert [c.check_name for c in findings] == [
        "mfa_registration", "app_permissions", "password_policy"]


# ---------------------------------------------------------------- subject

def test_subject_leads_with_new_findings(app):
    t = make_tenant("Contoso", "dir-1")
    make_report("dir-1", {"mfa_registration": "pass"}, score=80, days_ago=7)
    make_report("dir-1", {"mfa_registration": "fail"}, score=60)

    assert "1 new finding" in subject_line(collect([t]))


def test_subject_says_no_change_when_nothing_moved(app):
    t = make_tenant("Contoso", "dir-1")
    make_report("dir-1", {"mfa_registration": "pass"}, score=80, days_ago=7)
    make_report("dir-1", {"mfa_registration": "pass"}, score=80)

    subject = subject_line(collect([t]))
    assert "no change" in subject.lower()
    assert "80/100" in subject


def test_subject_aggregates_across_tenants(app):
    a = make_tenant("A", "dir-1")
    b = make_tenant("B", "dir-2")
    for d in ("dir-1", "dir-2"):
        make_report(d, {"mfa_registration": "pass"}, score=80, days_ago=7)
        make_report(d, {"mfa_registration": "fail"}, score=60)

    subject = subject_line(collect([a, b]))
    assert "2 new findings" in subject
    assert "2 tenants" in subject


def test_subject_when_nothing_has_been_audited(app):
    t = make_tenant("Contoso", "dir-1")
    assert "no audits have run" in subject_line(collect([t])).lower()


# ---------------------------------------------------------------- rendering

def test_both_bodies_are_produced(app):
    t = make_tenant("Contoso", "dir-1")
    make_report("dir-1", {"mfa_registration": "fail"}, score=40)

    subject, text, html = build([t])

    assert "Contoso" in text and "Contoso" in html
    assert "40/100" in text
    assert "<html" in html.lower()
    assert "<html" not in text.lower(), "the text part must not contain markup"


def test_tenant_names_are_escaped_in_html(app):
    """Tenant names are user-supplied and must not inject into the email."""
    t = make_tenant("<script>alert(1)</script>", "dir-1")
    make_report("dir-1", {"mfa_registration": "fail"}, score=40)

    _, _, html = build([t])

    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_clean_tenant_says_so(app):
    t = make_tenant("Contoso", "dir-1")
    make_report("dir-1", {"mfa_registration": "pass"}, score=100)

    _, text, html = build([t])
    assert "No open findings" in text
    assert "No open findings" in html


# ---------------------------------------------------------------- delivery

def test_send_without_configuration_explains_what_is_missing():
    with pytest.raises(mailer.MailNotConfigured) as exc:
        mailer.send("subject", "text", "<p>html</p>")
    message = str(exc.value)
    assert "SMTP_HOST" in message and "DIGEST_TO" in message


def test_is_configured_requires_host_sender_and_recipients(monkeypatch):
    assert not mailer.is_configured()
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    assert not mailer.is_configured(), "host alone is not enough"
    monkeypatch.setenv("SMTP_FROM", "audit@example.com")
    assert not mailer.is_configured(), "still no recipients"
    monkeypatch.setenv("DIGEST_TO", "me@example.com")
    assert mailer.is_configured()


def test_describe_config_never_reveals_the_password(monkeypatch):
    monkeypatch.setenv("SMTP_PASSWORD", "hunter2")
    described = mailer.describe_config()
    assert "hunter2" not in str(described)
    assert described["password_set"] is True


def test_message_carries_text_and_html_alternatives():
    msg = mailer.build_message("Subject", "plain body", "<p>rich body</p>",
                               "from@example.com", ["a@example.com", "b@example.com"])

    assert msg["Subject"] == "Subject"
    assert msg["To"] == "a@example.com, b@example.com"
    types = {part.get_content_type() for part in msg.walk()}
    assert "text/plain" in types and "text/html" in types


def test_recipients_are_split_and_trimmed(monkeypatch):
    monkeypatch.setenv("DIGEST_TO", " a@example.com , b@example.com ,, ")
    assert mailer.config()["recipients"] == ["a@example.com", "b@example.com"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
