"""Tests for the standalone HTML report."""
import os
import re

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app import create_app, db  # noqa: E402
from app.models.report import Report, ReportCheck  # noqa: E402
from app.services.report_export import _findings, _summary_sentence, render_html  # noqa: E402


@pytest.fixture
def app():
    application = create_app()
    application.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///:memory:", TESTING=True)
    with application.app_context():
        db.drop_all()
        db.create_all()
        yield application


def make_report(**checks_kwargs):
    report = Report(tenant_id="tenant-abc", report_type="full", status="complete")
    db.session.add(report)
    db.session.commit()
    return report


def add_check(report, check_name, status, **kw):
    c = ReportCheck(
        report_id=report.id,
        category=kw.get("category", "identity"),
        check_name=check_name,
        display_name=kw.get("display_name", check_name),
        status=status,
        points_earned=kw.get("points_earned"),
        points_possible=kw.get("points_possible"),
        summary=kw.get("summary", ""),
        issues=kw.get("issues", []),
        cis_reference=kw.get("cis_reference"),
    )
    db.session.add(c)
    db.session.commit()
    return c


def test_findings_ranked_by_severity_worst_first(app):
    r = make_report()
    add_check(r, "password_policy", "warn")        # low
    add_check(r, "mfa_registration", "fail")       # critical
    add_check(r, "app_permissions", "fail")        # high
    add_check(r, "sspr_enabled", "warn")           # medium

    order = [c.check_name for c in _findings(r.checks)]
    assert order == ["mfa_registration", "app_permissions", "sspr_enabled", "password_policy"]


def test_passing_checks_are_not_findings(app):
    r = make_report()
    add_check(r, "mfa_registration", "pass")
    add_check(r, "sspr_enabled", "skip")
    assert _findings(r.checks) == []


def test_report_includes_remediation_text_for_findings(app):
    r = make_report()
    add_check(r, "mfa_registration", "fail", points_earned=0, points_possible=20,
              summary="0/3 users have MFA registered",
              issues=["Alice (a@x.com) has no MFA registered"],
              cis_reference="CIS 1.1.1")

    html = render_html(r)

    assert "Conditional Access policy requiring MFA" in html, "remediation guidance missing"
    assert "Alice (a@x.com) has no MFA registered" in html, "affected users missing"
    assert "CIS 1.1.1" in html
    assert "critical" in html.lower()


def test_html_is_self_contained(app):
    """No external requests — the file must render offline, years later."""
    r = make_report()
    add_check(r, "mfa_registration", "fail", points_possible=20, points_earned=0)
    html = render_html(r)

    external = re.findall(r'(?:src|href)="(https?://[^"]+)"', html)
    non_portal = [u for u in external if "microsoft.com" not in u]
    assert not non_portal, f"external resources would break offline: {non_portal}"
    assert "<script" not in html.lower(), "report should not depend on JavaScript"


def test_issue_lists_are_truncated(app):
    r = make_report()
    add_check(r, "mfa_registration", "fail", points_possible=20, points_earned=0,
              issues=[f"user{i}@x.com has no MFA" for i in range(30)])

    html = render_html(r)

    assert "and 20 more" in html
    assert "user9@x.com" in html
    assert "user25@x.com" not in html


def test_user_content_is_escaped(app):
    """Display names come from the tenant and must not be able to inject markup."""
    r = make_report()
    add_check(r, "mfa_registration", "fail", points_possible=20, points_earned=0,
              issues=["<script>alert('xss')</script> has no MFA"])

    html = render_html(r)

    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_summary_sentence_leads_with_urgent_count():
    counts = {"critical": 1, "high": 2, "low": 3}
    sentence = _summary_sentence(45, [object()] * 6, counts)
    assert "3 findings rated high or critical" in sentence
    assert "45/100" in sentence


def test_summary_sentence_when_clean():
    assert "No failing checks" in _summary_sentence(100, [], {})


def test_clean_report_renders_without_findings_section(app):
    r = make_report()
    add_check(r, "mfa_registration", "pass", points_earned=20, points_possible=20)
    html = render_html(r)
    assert "No failing checks in this audit." in html


def test_export_route_serves_html(app):
    r = make_report()
    add_check(r, "mfa_registration", "fail", points_possible=20, points_earned=0)

    resp = app.test_client().get(f"/reports/api/export/{r.id}/html")

    assert resp.status_code == 200
    assert resp.mimetype == "text/html"
    assert b"Microsoft 365 Tenant Security Audit" in resp.data


def test_export_route_404s_for_unknown_report(app):
    assert app.test_client().get("/reports/api/export/nope/html").status_code == 404


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
