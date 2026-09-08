"""Tests for run-to-run comparison."""
import os
from datetime import timedelta

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app import create_app, db  # noqa: E402
from app.models.report import Report, ReportCheck  # noqa: E402
from app.services.comparison import compare, find_previous, headline  # noqa: E402
from app.utils import utcnow  # noqa: E402


@pytest.fixture
def app():
    application = create_app()
    application.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///:memory:", TESTING=True)
    with application.app_context():
        db.drop_all()
        db.create_all()
        yield application


def make_report(checks, score=None, days_ago=0, tenant="dir-1", rtype="full"):
    r = Report(tenant_id=tenant, report_type=rtype, status="complete", score=score,
               created_at=utcnow() - timedelta(days=days_ago))
    db.session.add(r)
    db.session.commit()
    for name, status in checks.items():
        db.session.add(ReportCheck(report_id=r.id, category="identity", check_name=name,
                                   display_name=name, status=status))
    db.session.commit()
    return r


# ------------------------------------------------------------------ finding previous

def test_finds_the_immediately_preceding_run(app):
    make_report({"a": "pass"}, days_ago=10)
    middle = make_report({"a": "pass"}, days_ago=5)
    current = make_report({"a": "pass"}, days_ago=0)

    assert find_previous(current, Report).id == middle.id


def test_previous_is_scoped_to_the_same_tenant(app):
    make_report({"a": "pass"}, days_ago=5, tenant="dir-2")
    current = make_report({"a": "pass"}, days_ago=0, tenant="dir-1")

    assert find_previous(current, Report) is None, "must not compare across tenants"


def test_previous_is_scoped_to_the_same_report_type(app):
    make_report({"a": "pass"}, days_ago=5, rtype="identity")
    current = make_report({"a": "pass"}, days_ago=0, rtype="full")

    assert find_previous(current, Report) is None


def test_first_ever_run_has_no_previous(app):
    assert find_previous(make_report({"a": "pass"}), Report) is None


# ------------------------------------------------------------------ diffing

def test_detects_new_findings(app):
    previous = make_report({"mfa": "pass", "sspr": "pass"}, days_ago=7)
    current = make_report({"mfa": "fail", "sspr": "pass"})

    diff = compare(current, previous)

    assert [f["check"].check_name for f in diff["new_findings"]] == ["mfa"]
    assert diff["new_findings"][0]["previous_status"] == "pass"
    assert diff["resolved"] == []


def test_detects_resolved_findings(app):
    previous = make_report({"mfa": "fail"}, days_ago=7)
    current = make_report({"mfa": "pass"})

    diff = compare(current, previous)

    assert [f["check"].check_name for f in diff["resolved"]] == ["mfa"]
    assert diff["new_findings"] == []


def test_warn_to_fail_is_a_regression_not_a_new_finding(app):
    """Both are findings, so it isn't 'new' — but it did get worse."""
    previous = make_report({"pim": "warn"}, days_ago=7)
    current = make_report({"pim": "fail"})

    diff = compare(current, previous)

    assert diff["new_findings"] == []
    assert [f["check"].check_name for f in diff["regressed"]] == ["pim"]


def test_fail_to_warn_is_an_improvement(app):
    previous = make_report({"pim": "fail"}, days_ago=7)
    current = make_report({"pim": "warn"})

    diff = compare(current, previous)

    assert [f["check"].check_name for f in diff["improved"]] == ["pim"]
    assert diff["resolved"] == [], "still a finding, so not resolved"


def test_check_appearing_as_a_pass_is_not_reported_as_news(app):
    """Granting a permission shouldn't read as a change in posture."""
    previous = make_report({"mfa": "pass"}, days_ago=7)
    current = make_report({"mfa": "pass", "secure_score": "pass"})

    diff = compare(current, previous)

    assert diff["new_findings"] == []
    assert diff["unchanged"] is True


def test_check_appearing_as_a_failure_is_a_new_finding(app):
    previous = make_report({"mfa": "pass"}, days_ago=7)
    current = make_report({"mfa": "pass", "external_sharing": "fail"})

    diff = compare(current, previous)

    assert [f["check"].check_name for f in diff["new_findings"]] == ["external_sharing"]
    assert diff["new_findings"][0]["previous_status"] is None


def test_check_disappearing_is_surfaced_not_swallowed(app):
    """A revoked permission means a control stopped being measured."""
    previous = make_report({"mfa": "pass", "risky_users": "pass"}, days_ago=7)
    current = make_report({"mfa": "pass"})

    diff = compare(current, previous)

    assert [c.check_name for c in diff["no_longer_measured"]] == ["risky_users"]


def test_score_delta(app):
    previous = make_report({"mfa": "fail"}, score=40, days_ago=7)
    current = make_report({"mfa": "pass"}, score=61)

    assert compare(current, previous)["score_delta"] == 21


def test_identical_runs_report_unchanged(app):
    previous = make_report({"mfa": "pass", "sspr": "pass"}, score=50, days_ago=7)
    current = make_report({"mfa": "pass", "sspr": "pass"}, score=50)

    diff = compare(current, previous)

    assert diff["unchanged"] is True
    assert headline(diff) == "No change since the previous audit."


def test_no_previous_report_yields_no_comparison(app):
    current = make_report({"mfa": "pass"})
    assert compare(current, None) is None


def test_report_with_no_checks_is_not_compared(app):
    """An empty run would otherwise read as every check disappearing."""
    previous = make_report({"mfa": "pass"}, days_ago=7)
    current = make_report({})

    assert compare(current, previous) is None


# ------------------------------------------------------------------ headline

def test_headline_summarises_the_mix(app):
    previous = make_report({"a": "pass", "b": "fail", "c": "warn"}, days_ago=7)
    current = make_report({"a": "fail", "b": "pass", "c": "fail"})

    text = headline(compare(current, previous))

    assert "1 new finding" in text
    assert "1 resolved" in text
    assert "1 worsened" in text


def test_headline_uses_singular_for_one(app):
    previous = make_report({"a": "pass"}, days_ago=7)
    current = make_report({"a": "fail"})

    assert "1 new finding since" in headline(compare(current, previous))


def test_headline_handles_score_only_movement(app):
    previous = make_report({"a": "warn"}, score=40, days_ago=7)
    current = make_report({"a": "warn"}, score=45)

    text = headline(compare(current, previous))
    assert "up 5 points" in text


def test_headline_of_nothing_is_none():
    assert headline(None) is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
