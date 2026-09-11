"""Tests for the policy builder and the simulator routes.

The load-bearing one is test_builder_cannot_emit_a_condition_the_engine_cannot
_evaluate. The brief requires the builder and engine capability sets to stay in
lockstep, and a form offering a condition the engine ignores produces drafts
whose impact report is mostly UNSUPPORTED — which teaches people the tool does
not work.
"""
import pytest

from app.services.ca_builder import (APP_GROUP_CHOICES, CLIENT_APP_CHOICES,
                                     GRANT_CHOICES, PLATFORM_CHOICES,
                                     RISK_CHOICES, STATE_CHOICES, BuilderError,
                                     build_policy, export)
from app.services.ca_engine import (CLIENT_APP_TYPES_SUPPORTED, DEVICE_PLATFORMS_SUPPORTED,
                                    RISK_LEVELS_SUPPORTED, evaluate)
from app.services.ca_memberships import Membership
from app.services.signin_corpus import ConditionTuple

EXCHANGE = "00000002-0000-0ff1-ce00-000000000000"


def conditions(**overrides):
    base = dict(user_id="u1", resource_id=EXCHANGE, client_app_type="browser",
                device_platform="windows", country="US", is_compliant=None,
                join_type=None, sign_in_risk_level="none", user_risk_level="none",
                named_location_ids=frozenset(), in_trusted_location=False,
                app_group_tokens=frozenset())
    base.update(overrides)
    return ConditionTuple(**base)


def member(**overrides):
    base = dict(user_id="u1", group_ids=frozenset(), role_ids=frozenset(),
                role_template_ids=frozenset(), user_type="Member", resolved=True)
    base.update(overrides)
    return Membership(**base)


def form(**overrides):
    base = {"displayName": "Draft", "allUsers": "on", "allApplications": "on",
            "grantControls": ["mfa"], "grantOperator": "OR", "state": "enabled"}
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Lockstep with the engine
# ---------------------------------------------------------------------------

def test_builder_client_apps_match_the_engine_vocabulary():
    assert set(CLIENT_APP_CHOICES) <= set(CLIENT_APP_TYPES_SUPPORTED)


def test_builder_risk_levels_are_all_understood_by_the_engine():
    assert set(RISK_CHOICES) <= set(RISK_LEVELS_SUPPORTED)


def test_builder_platforms_are_all_understood_by_the_engine():
    assert set(PLATFORM_CHOICES) <= set(DEVICE_PLATFORMS_SUPPORTED)


def test_every_offered_condition_produces_an_evaluable_policy():
    # The lockstep check that matters: build a policy using every condition the
    # form can express, and assert the engine returns a verdict rather than
    # UNSUPPORTED. A form field the engine ignores fails here.
    draft = build_policy(form(
        allUsers=None, includeGroups=["g1"], excludeGroups=["g2"],
        includeRoles=["r1"], allApplications=None,
        includeApplications=[EXCHANGE], appGroups=["Office365"],
        clientAppTypes=list(CLIENT_APP_CHOICES),
        includePlatforms=["windows"], excludePlatforms=["linux"],
        includeLocations=["loc1"], excludeLocations=["loc2"],
        signInRiskLevels=["high"], userRiskLevels=["high"],
        grantControls=["mfa", "compliantDevice"], grantOperator="AND",
    ))
    verdict = evaluate(draft, conditions(
        named_location_ids=frozenset({"loc1"}),
        sign_in_risk_level="high", user_risk_level="high"),
        member(group_ids=frozenset({"g1"})))
    assert verdict.applies is not None, verdict.unsupported_conditions
    assert verdict.unsupported_conditions == ()


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------

def test_all_users_and_all_apps_is_the_simplest_valid_policy():
    draft = build_policy(form())
    assert draft["conditions"]["users"]["includeUsers"] == ["All"]
    assert draft["conditions"]["applications"]["includeApplications"] == ["All"]
    assert draft["grantControls"]["builtInControls"] == ["mfa"]


def test_group_targeting_writes_none_into_include_users():
    # How the portal represents an empty user list on a group-scoped policy.
    # It does not mean "nobody" — the engine had a bug on exactly this.
    draft = build_policy(form(allUsers=None, includeGroups=["g1"]))
    users = draft["conditions"]["users"]
    assert users["includeUsers"] == ["None"]
    assert users["includeGroups"] == ["g1"]


def test_a_group_scoped_draft_actually_applies_to_a_member():
    draft = build_policy(form(allUsers=None, includeGroups=["g1"]))
    assert evaluate(draft, conditions(),
                    member(group_ids=frozenset({"g1"}))).applies is True


def test_guests_are_added_to_include_users():
    draft = build_policy(form(allUsers=None, includeGuests="on"))
    assert "GuestsOrExternalUsers" in draft["conditions"]["users"]["includeUsers"]


def test_no_audience_is_refused_rather_than_built():
    with pytest.raises(BuilderError, match="who the policy applies to"):
        build_policy(form(allUsers=None))


def test_no_resource_is_refused():
    with pytest.raises(BuilderError, match="which resources"):
        build_policy(form(allApplications=None))


def test_no_control_is_refused():
    with pytest.raises(BuilderError, match="at least one access control"):
        build_policy(form(grantControls=[]))


def test_block_cannot_be_combined_with_a_grant():
    # Entra treats block as absolute; the pairing reads as two contradictory
    # instructions and is rejected here rather than by Graph later.
    with pytest.raises(BuilderError, match="cannot be combined"):
        build_policy(form(grantControls=["block", "mfa"]))


def test_empty_client_app_selection_means_all_not_none():
    # "all" is Entra's default and covers every client type, legacy included.
    # Emitting an empty list would be a policy that matches nothing.
    assert build_policy(form())["conditions"]["clientAppTypes"] == ["all"]


def test_unknown_values_are_dropped_rather_than_passed_through():
    draft = build_policy(form(clientAppTypes=["browser", "notAClientApp"],
                              includePlatforms=["windows", "solaris"],
                              grantControls=["mfa", "teleport"]))
    assert draft["conditions"]["clientAppTypes"] == ["browser"]
    assert draft["conditions"]["platforms"]["includePlatforms"] == ["windows"]
    assert draft["grantControls"]["builtInControls"] == ["mfa"]


def test_unknown_state_is_refused():
    with pytest.raises(BuilderError, match="policy state"):
        build_policy(form(state="somethingElse"))


def test_locations_are_only_emitted_when_selected():
    assert "locations" not in build_policy(form())["conditions"]
    draft = build_policy(form(excludeLocations=["loc1"]))
    assert draft["conditions"]["locations"]["excludeLocations"] == ["loc1"]


def test_export_is_valid_graph_json():
    import json

    draft = build_policy(form())
    parsed = json.loads(export(draft))
    assert parsed["displayName"] == "Draft"
    assert set(parsed) == {"displayName", "state", "conditions", "grantControls"}


def test_every_state_choice_builds():
    for state in STATE_CHOICES:
        assert build_policy(form(state=state))["state"] == state


def test_every_app_group_choice_is_accepted():
    for group in APP_GROUP_CHOICES:
        draft = build_policy(form(allApplications=None, appGroups=[group]))
        assert group in draft["conditions"]["applications"]["includeApplications"]


def test_every_grant_choice_builds_alone():
    for control in GRANT_CHOICES:
        draft = build_policy(form(grantControls=[control]))
        assert draft["grantControls"]["builtInControls"] == [control]
