"""Route tests for the simulator.

These exist mostly to prove the templates render. A Jinja error in a page that
is only reachable after a slow Graph call is expensive to find by hand, and the
impact report has enough conditional branches — incomplete, report-only,
blocked, unchanged — that several of them would otherwise never be exercised
until a demo.
"""
import os

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app import create_app, db  # noqa: E402
from app.models.tenant import Tenant  # noqa: E402
from app.services import ca_workspace  # noqa: E402
from app.services.ca_memberships import Membership, MembershipSet  # noqa: E402
from app.services.signin_corpus import reduce_to_tuples  # noqa: E402
from tests.conftest import signed_in_client  # noqa: E402
from tests.test_signin_corpus import signin  # noqa: E402

TENANT_ID = "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def app():
    application = create_app()
    application.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
                              SECRET_KEY="test-key", TESTING=True)
    with application.app_context():
        db.drop_all()
        db.create_all()
        tenant = Tenant(name="Contoso", tenant_id=TENANT_ID, client_id="client")
        tenant.client_secret = "secret"
        db.session.add(tenant)
        db.session.commit()
        yield application
    ca_workspace.clear()


def policy(name="Existing MFA", controls=("mfa",)):
    return {"id": name, "displayName": name, "state": "enabled",
            "conditions": {"users": {"includeUsers": ["All"]},
                           "applications": {"includeApplications": ["All"]},
                           "clientAppTypes": ["all"], "signInRiskLevels": [],
                           "userRiskLevels": []},
            "grantControls": {"operator": "OR", "builtInControls": list(controls)},
            "sessionControls": None}


def seed_workspace(days=30, records=None, policies=None):
    """Put a ready-made workspace in the cache, so no Graph call is needed."""
    corpus = reduce_to_tuples(records or [signin(userId="u1")] * 5,
                              window_days=days)
    memberships = MembershipSet()
    for observation in corpus.observations:
        user_id = observation.conditions.user_id
        memberships.by_user[user_id] = Membership(user_id=user_id,
                                                  user_type="Member",
                                                  resolved=True)
    workspace = ca_workspace.Workspace(
        tenant_id=TENANT_ID, days=days, corpus=corpus, memberships=memberships,
        policies=policies if policies is not None else [policy()],
        named_locations=[], app_group_coverage=(0, 0))
    return ca_workspace.put(workspace)


def simulate(client, **overrides):
    data = {"displayName": "Draft", "allUsers": "on", "allApplications": "on",
            "grantControls": ["compliantDevice"], "grantOperator": "OR",
            "state": "enabled"}
    data.update(overrides)
    return client.post("/simulator/simulate", data=data)


# ---------------------------------------------------------------------------

def test_simulator_requires_a_session(app):
    resp = app.test_client().get("/simulator/")
    assert resp.status_code == 302


def test_index_offers_to_load_traffic_when_nothing_is_cached(app):
    client = signed_in_client(app)
    resp = client.get("/simulator/")
    assert resp.status_code == 200
    assert b"Load sign-in traffic" in resp.data


def test_index_shows_the_corpus_once_loaded(app):
    seed_workspace()
    resp = signed_in_client(app).get("/simulator/")
    assert resp.status_code == 200
    assert b"Distinct condition sets" in resp.data


def test_simulating_renders_the_impact_report(app):
    seed_workspace()
    resp = simulate(signed_in_client(app))
    assert resp.status_code == 200
    assert b"would be affected" in resp.data
    assert b"compliantDevice" in resp.data


def test_a_draft_requiring_nothing_new_reports_no_change(app):
    # The existing policy already requires MFA, so a draft requiring MFA is a
    # no-op and must not be dressed up as impact.
    seed_workspace()
    resp = simulate(signed_in_client(app), grantControls=["mfa"])
    assert b"No sign-ins in the window would be affected" in resp.data


def test_an_incomplete_report_says_so_prominently(app):
    # Location conditions cannot be evaluated without a resolver, so this
    # exercises the incomplete banner.
    seed_workspace()
    resp = simulate(signed_in_client(app), includeLocations=["loc1"])
    assert b"Incomplete" in resp.data
    assert b"lower bounds" in resp.data


def test_a_report_only_draft_is_flagged_in_the_page(app):
    seed_workspace()
    resp = simulate(signed_in_client(app),
                    state="enabledForReportingButNotEnforced")
    assert b"enforces nothing" in resp.data


def test_a_blocking_draft_renders_the_blocked_panel(app):
    seed_workspace()
    resp = simulate(signed_in_client(app), grantControls=["block"])
    assert b"Blocked outright" in resp.data


def test_a_builder_error_is_shown_rather_than_raised(app):
    seed_workspace()
    resp = simulate(signed_in_client(app), grantControls=[])
    assert resp.status_code == 200
    assert b"at least one access control" in resp.data


def test_simulating_without_a_workspace_asks_for_one(app):
    ca_workspace.clear()
    resp = simulate(signed_in_client(app))
    assert b"Load this tenant" in resp.data


def test_the_draft_json_is_shown_for_manual_deployment(app):
    seed_workspace()
    resp = simulate(signed_in_client(app))
    assert b"Graph JSON" in resp.data
    # The read-only promise has to be visible on the page that hands over the
    # policy, not just in the docs.
    assert b"Apply this yourself" in resp.data


def test_export_returns_a_json_attachment(app):
    seed_workspace()
    client = signed_in_client(app)
    resp = client.post("/simulator/export", data={
        "displayName": "My draft", "allUsers": "on", "allApplications": "on",
        "grantControls": ["mfa"], "state": "enabled"})
    assert resp.status_code == 200
    assert resp.mimetype == "application/json"
    assert "attachment" in resp.headers["Content-Disposition"]
    assert b'"displayName": "My draft"' in resp.data


def test_export_rejects_an_invalid_draft(app):
    resp = signed_in_client(app).post("/simulator/export", data={"allUsers": "on"})
    assert resp.status_code == 400


def test_agreement_page_renders_and_asks_for_traffic(app):
    ca_workspace.clear()
    resp = signed_in_client(app).get("/simulator/agreement")
    assert resp.status_code == 200
    assert b"Why trust these numbers" in resp.data


def test_agreement_page_offers_the_check_once_traffic_is_loaded(app):
    seed_workspace()
    resp = signed_in_client(app).get("/simulator/agreement")
    assert b"Check against Microsoft" in resp.data


def test_gaps_are_listed_in_the_builder(app):
    seed_workspace()
    resp = signed_in_client(app).get("/simulator/")
    assert b"Not simulated" in resp.data
    assert b"Device filters" in resp.data


def test_simulator_appears_in_the_navigation(app):
    resp = signed_in_client(app).get("/simulator/")
    assert b"CA Simulator" in resp.data
