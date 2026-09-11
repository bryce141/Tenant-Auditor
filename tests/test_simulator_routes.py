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


# ---------------------------------------------------------------------------
# Making the page legible
# ---------------------------------------------------------------------------

def test_presets_are_offered_as_starting_points(app):
    # An empty form asks you to know what policy you want before it shows you
    # anything. The first person to look at this page said they did not know
    # what they were looking for.
    seed_workspace()
    resp = signed_in_client(app).get("/simulator/")
    assert b"Start from a common policy" in resp.data
    assert b"Block legacy authentication" in resp.data


def test_a_preset_prefills_the_form(app):
    seed_workspace()
    resp = signed_in_client(app).get("/simulator/?preset=block-legacy")
    assert resp.status_code == 200
    assert b"Block legacy authentication" in resp.data
    # The client app types the preset selects must come back ticked.
    assert b'value="exchangeActiveSync" checked' in resp.data


def test_an_unknown_preset_falls_back_to_an_empty_form(app):
    seed_workspace()
    resp = signed_in_client(app).get("/simulator/?preset=nonsense")
    assert resp.status_code == 200


def test_multiselects_say_when_nothing_is_selected(app):
    # An empty listbox looks identical to a full one — the rows are options,
    # not selections, and without this nothing says so.
    seed_workspace()
    resp = signed_in_client(app).get("/simulator/")
    assert b"None selected" in resp.data


def test_a_draft_affecting_everything_is_flagged_as_too_broad(app):
    # A correct answer that reads as the tool being broken. All users, all
    # resources, a control nothing currently requires.
    seed_workspace()
    resp = simulate(signed_in_client(app), grantControls=["approvedApplication"])
    assert b"affects essentially all observed traffic" in resp.data


def test_a_narrow_draft_is_not_flagged(app):
    graph = "00000003-0000-0000-c000-000000000000"
    exchange = "00000002-0000-0ff1-ce00-000000000000"
    seed_workspace(records=[signin(userId="u1", resourceId=graph)] * 5
                           + [signin(userId="u2", resourceId=exchange)] * 5)
    resp = simulate(signed_in_client(app), allApplications=None,
                    includeApplications=[exchange],
                    grantControls=["approvedApplication"])
    assert b"affects essentially all observed traffic" not in resp.data
    # Half the corpus, so the draft is doing something without doing everything.
    assert b"5 sign-ins across 1 user would be affected" in resp.data


def test_loading_overlay_is_present_on_the_slow_forms(app):
    # Loading traffic makes a dozen Graph calls; without feedback the page
    # reads as a hang and the natural response is to click again, which starts
    # the whole fetch over.
    client = signed_in_client(app)
    resp = client.get("/simulator/")
    assert b'data-loading="Loading sign-in traffic"' in resp.data
    assert b"loading-overlay" in resp.data


def test_agreement_page_has_a_loading_overlay(app):
    seed_workspace()
    resp = signed_in_client(app).get("/simulator/agreement")
    assert b'data-loading="Checking against Microsoft"' in resp.data


def test_loading_messages_reach_the_page(app):
    from app.routes.simulator import LOADING_MESSAGES

    resp = signed_in_client(app).get("/simulator/")
    assert b"reticulating splines" in resp.data
    assert len(LOADING_MESSAGES) == len(set(LOADING_MESSAGES))


def test_loading_messages_survive_json_escaping(app):
    # Several contain apostrophes and parentheses; a broken escape takes the
    # whole script block down and the overlay silently never appears.
    import json

    from app.routes.simulator import LOADING_MESSAGES

    resp = signed_in_client(app).get("/simulator/")
    for message in ["rm -rf'ing doubts",
                    "warming up the cloud (it's chilly up there)",
                    "consulting the ancient scrolls (man pages)"]:
        assert message in LOADING_MESSAGES
    # The template renders them with |tojson, so this must round-trip.
    assert json.loads(json.dumps(LOADING_MESSAGES)) == LOADING_MESSAGES
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# What's missing
# ---------------------------------------------------------------------------

class FakeCheck:
    def __init__(self, check_name, status="fail", display_name=None, summary="x"):
        self.check_name = check_name
        self.status = status
        self.display_name = display_name or check_name
        self.summary = summary


def _with_audit(monkeypatch, checks):
    """Stand in for the latest audit, so the page needs no real report rows."""
    import app.routes.simulator as sim

    class FakeReport:
        def __init__(self, rows):
            self.checks = rows

    monkeypatch.setattr(
        "app.services.report_runner.get_latest_report",
        lambda category, scope=None: FakeReport(checks) if category == "identity" else None)
    return sim


def test_recommendations_needs_traffic_loaded(app):
    ca_workspace.clear()
    resp = signed_in_client(app).get("/simulator/recommendations")
    assert resp.status_code == 200
    assert b"Load this tenant" in resp.data


def test_recommendations_needs_an_audit(app):
    # Without findings there is nothing to recommend from, and inventing
    # recommendations would be advice with no evidence behind it.
    seed_workspace()
    resp = signed_in_client(app).get("/simulator/recommendations")
    assert b"No audit has run for this tenant yet" in resp.data


def test_recommendations_render_from_audit_findings(app, monkeypatch):
    seed_workspace()
    _with_audit(monkeypatch, [FakeCheck("legacy_auth_blocked",
                                        display_name="Legacy Auth Blocked")])
    resp = signed_in_client(app).get("/simulator/recommendations")
    assert resp.status_code == 200
    assert b"Block legacy authentication" in resp.data
    assert b"Legacy Auth Blocked" in resp.data


def test_a_partial_remedy_is_labelled_partial_in_the_page(app, monkeypatch):
    seed_workspace()
    _with_audit(monkeypatch, [FakeCheck("pim_standing_roles",
                                        display_name="PIM / Standing Roles")])
    resp = signed_in_client(app).get("/simulator/recommendations")
    assert b"Partial fix" in resp.data
    assert b"PIM" in resp.data


def test_out_of_scope_findings_appear_with_where_the_fix_lives(app, monkeypatch):
    seed_workspace()
    _with_audit(monkeypatch, [FakeCheck("email_authentication",
                                        display_name="Email Authentication")])
    resp = signed_in_client(app).get("/simulator/recommendations")
    assert b"Not fixable with Conditional Access" in resp.data
    assert b"DNS records" in resp.data


def test_the_policy_is_shown_for_manual_deployment(app, monkeypatch):
    seed_workspace()
    _with_audit(monkeypatch, [FakeCheck("legacy_auth_blocked")])
    resp = signed_in_client(app).get("/simulator/recommendations")
    assert b"Show the policy" in resp.data
    assert b"never writes to a tenant" in resp.data


def test_a_clean_tenant_says_there_is_nothing_to_recommend(app, monkeypatch):
    seed_workspace()
    _with_audit(monkeypatch, [FakeCheck("legacy_auth_blocked", status="pass")])
    resp = signed_in_client(app).get("/simulator/recommendations")
    assert b"Nothing to recommend" in resp.data


def test_simulator_links_to_whats_missing(app):
    seed_workspace()
    resp = signed_in_client(app).get("/simulator/")
    assert b"What&#39;s missing?" in resp.data or b"What's missing?" in resp.data
