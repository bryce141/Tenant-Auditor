"""Tests for the CA evaluation engine.

The engine's whole claim is that it either gets a policy right or says it
cannot evaluate it. So these tests care less about the happy path than about
two failure shapes:

  - a condition the engine doesn't implement must produce UNSUPPORTED, never a
    quiet "doesn't apply" (which reports a policy as breaking nobody), and
  - where a policy can fail open or closed, both directions are asserted.
"""
import pytest

from app.services.ca_engine import (
    BLOCK,
    GRANT,
    NOT_APPLICABLE,
    NO_CONTROLS,
    SESSION_ONLY,
    UNSUPPORTED,
    combine,
    evaluate,
    evaluate_all,
)
from app.services.ca_memberships import Membership
from app.services.signin_corpus import ConditionTuple

GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"
GLOBAL_ADMIN_OBJECT = "f8512e77-ffb7-4951-8e1b-234806bc8a3f"
EXCHANGE_ONLINE = "00000002-0000-0ff1-ce00-000000000000"


def conditions(**overrides):
    base = dict(user_id="u1", resource_id=EXCHANGE_ONLINE, client_app_type="browser",
                device_platform="windows", country="US", is_compliant=None,
                join_type=None, sign_in_risk_level="none", user_risk_level="none")
    base.update(overrides)
    return ConditionTuple(**base)


def member(**overrides):
    base = dict(user_id="u1", group_ids=frozenset(), role_ids=frozenset(),
                role_template_ids=frozenset(), user_type="Member", resolved=True)
    base.update(overrides)
    return Membership(**base)


def policy(users=None, applications=None, state="enabled", grant=None,
           session=None, **condition_overrides):
    block = {
        "users": users if users is not None else {"includeUsers": ["All"]},
        "applications": (applications if applications is not None
                         else {"includeApplications": ["All"]}),
        "clientAppTypes": ["all"],
        "signInRiskLevels": [],
        "userRiskLevels": [],
    }
    block.update(condition_overrides)
    return {"id": "p1", "displayName": "Test policy", "state": state,
            "conditions": block, "grantControls": grant,
            "sessionControls": session}


BLOCK_CONTROL = {"operator": "OR", "builtInControls": ["block"]}
MFA_CONTROL = {"operator": "OR", "builtInControls": ["mfa"]}


# ---------------------------------------------------------------------------
# Policy state
# ---------------------------------------------------------------------------

def test_disabled_policy_never_applies():
    e = evaluate(policy(state="disabled", grant=BLOCK_CONTROL), conditions(), member())
    assert e.applies is False
    assert e.result == NOT_APPLICABLE
    assert e.blocks is False


def test_report_only_policy_applies_but_does_not_block():
    # Counting a report-only policy as breakage is how a simulator cries wolf:
    # the admin put it in report-only precisely so it wouldn't break anyone.
    e = evaluate(policy(state="enabledForReportingButNotEnforced",
                        grant=BLOCK_CONTROL), conditions(), member())
    assert e.applies is True
    assert e.enforced is False
    assert e.blocks is False
    assert "report-only" in e.reason


def test_enabled_block_policy_blocks():
    e = evaluate(policy(grant=BLOCK_CONTROL), conditions(), member())
    assert e.applies is True and e.enforced is True
    assert e.result == BLOCK
    assert e.blocks is True


def test_unrecognised_state_is_unsupported_not_inapplicable():
    e = evaluate(policy(state="somethingNew", grant=BLOCK_CONTROL),
                 conditions(), member())
    assert e.applies is None
    assert e.result == UNSUPPORTED


# ---------------------------------------------------------------------------
# Users, groups, roles
# ---------------------------------------------------------------------------

def test_all_users_matches():
    assert evaluate(policy(users={"includeUsers": ["All"]}),
                    conditions(), member()).applies is True


def test_none_targets_nobody():
    e = evaluate(policy(users={"includeUsers": ["None"]}), conditions(), member())
    assert e.applies is False


def test_specific_user_matches_case_insensitively():
    users = {"includeUsers": ["U1"]}
    assert evaluate(policy(users=users), conditions(user_id="u1"),
                    member()).applies is True


def test_user_exclusion_beats_inclusion():
    users = {"includeUsers": ["All"], "excludeUsers": ["u1"]}
    e = evaluate(policy(users=users), conditions(), member())
    assert e.applies is False
    assert "excluded" in e.reason


def test_group_membership_brings_a_user_into_scope():
    users = {"includeUsers": [], "includeGroups": ["g1"]}
    assert evaluate(policy(users=users), conditions(),
                    member(group_ids=frozenset({"g1"}))).applies is True
    assert evaluate(policy(users=users), conditions(),
                    member(group_ids=frozenset({"g2"}))).applies is False


def test_group_exclusion_beats_group_inclusion():
    users = {"includeUsers": ["All"], "excludeGroups": ["breakglass"]}
    e = evaluate(policy(users=users), conditions(),
                 member(group_ids=frozenset({"breakglass"})))
    assert e.applies is False


def test_role_matches_by_template_id_or_object_id():
    # The policy may carry either; the docs don't say which, so both work.
    m = member(role_ids=frozenset({GLOBAL_ADMIN_OBJECT}),
               role_template_ids=frozenset({GLOBAL_ADMIN_TEMPLATE}))
    for role_ref in (GLOBAL_ADMIN_TEMPLATE, GLOBAL_ADMIN_OBJECT):
        users = {"includeUsers": [], "includeRoles": [role_ref]}
        assert evaluate(policy(users=users), conditions(), m).applies is True


def test_role_exclusion_beats_inclusion():
    users = {"includeUsers": ["All"], "excludeRoles": [GLOBAL_ADMIN_TEMPLATE]}
    m = member(role_template_ids=frozenset({GLOBAL_ADMIN_TEMPLATE}))
    assert evaluate(policy(users=users), conditions(), m).applies is False


def test_guests_token_matches_only_guests():
    users = {"includeUsers": ["GuestsOrExternalUsers"]}
    assert evaluate(policy(users=users), conditions(),
                    member(user_type="Guest")).applies is True
    assert evaluate(policy(users=users), conditions(),
                    member(user_type="Member")).applies is False


def test_unresolved_membership_is_unsupported_when_groups_are_targeted():
    # The failure this prevents: treating a deleted user as belonging to no
    # groups, so a group-targeted policy reports as breaking nobody.
    users = {"includeUsers": [], "includeGroups": ["g1"]}
    e = evaluate(policy(users=users), conditions(),
                 member(resolved=False, group_ids=frozenset()))
    assert e.applies is None
    assert e.result == UNSUPPORTED
    assert any("membership unresolved" in c for c in e.unsupported_conditions)


def test_unresolved_membership_still_answers_an_all_users_policy():
    # No directory lookup is needed to know that "All" includes them.
    e = evaluate(policy(users={"includeUsers": ["All"]}), conditions(),
                 member(resolved=False))
    assert e.applies is True


def test_structured_guest_conditions_are_unsupported():
    # includeGuestsOrExternalUsers carries external tenant membership the
    # sign-in log does not report.
    users = {"includeUsers": ["All"],
             "includeGuestsOrExternalUsers": {"guestOrExternalUserTypes": "b2bCollaborationGuest"}}
    e = evaluate(policy(users=users), conditions(), member())
    assert e.applies is None
    assert "guestsOrExternalUsers" in " ".join(e.unsupported_conditions)


# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------

def test_all_applications_matches_any_app():
    assert evaluate(policy(applications={"includeApplications": ["All"]}),
                    conditions(), member()).applies is True


def test_application_condition_matches_the_resource_not_the_client():
    # "Conditional Access applies to resources not clients… Conditional Access
    # policies don't apply to public clients themselves but are based on the
    # resources they request." A policy listing Exchange must match a sign-in
    # whose resource is Exchange, whatever client was used to get there.
    apps = {"includeApplications": [EXCHANGE_ONLINE]}
    assert evaluate(policy(applications=apps),
                    conditions(resource_id=EXCHANGE_ONLINE, client_app_type="mobileAppsAndDesktopClients"),
                    member()).applies is True
    assert evaluate(policy(applications=apps),
                    conditions(resource_id=EXCHANGE_ONLINE, client_app_type="browser"),
                    member()).applies is True


def test_missing_resource_is_unsupported_not_a_non_match():
    e = evaluate(policy(applications={"includeApplications": [EXCHANGE_ONLINE]}),
                 conditions(resource_id=None), member())
    assert e.applies is None
    assert "resourceId" in " ".join(e.unsupported_conditions)


def test_specific_application_matches_and_misses():
    apps = {"includeApplications": [EXCHANGE_ONLINE]}
    assert evaluate(policy(applications=apps),
                    conditions(resource_id=EXCHANGE_ONLINE), member()).applies is True
    assert evaluate(policy(applications=apps),
                    conditions(resource_id="some-other-app"), member()).applies is False


def test_application_exclusion_beats_inclusion():
    apps = {"includeApplications": ["All"], "excludeApplications": [EXCHANGE_ONLINE]}
    e = evaluate(policy(applications=apps), conditions(resource_id=EXCHANGE_ONLINE),
                 member())
    assert e.applies is False


def test_office365_app_group_is_unsupported_not_a_literal_app_id():
    # Treating "Office365" as an app id would never match, silently
    # under-reporting a policy that covers most of the tenant.
    e = evaluate(policy(applications={"includeApplications": ["Office365"]}),
                 conditions(), member())
    assert e.applies is None
    assert "Office365" in " ".join(e.unsupported_conditions)


def test_user_actions_are_unsupported():
    apps = {"includeApplications": [],
            "includeUserActions": ["urn:user:registersecurityinfo"]}
    e = evaluate(policy(applications=apps), conditions(), member())
    assert e.applies is None
    assert "includeUserActions" in " ".join(e.unsupported_conditions)


def test_application_filter_is_unsupported():
    apps = {"includeApplications": ["All"],
            "applicationFilter": {"mode": "include", "rule": "x"}}
    assert evaluate(policy(applications=apps), conditions(), member()).applies is None


# ---------------------------------------------------------------------------
# Client app types
# ---------------------------------------------------------------------------

def test_all_client_app_types_matches():
    assert evaluate(policy(clientAppTypes=["all"]), conditions(),
                    member()).applies is True


def test_legacy_client_policy_matches_only_legacy_traffic():
    p = policy(clientAppTypes=["exchangeActiveSync", "other"], grant=BLOCK_CONTROL)
    assert evaluate(p, conditions(client_app_type="other"), member()).blocks is True
    assert evaluate(p, conditions(client_app_type="browser"),
                    member()).applies is False


def test_deprecated_eas_spellings_match_exchange_activesync_traffic():
    # easUnsupported is deprecated in favour of exchangeActiveSync but still
    # appears on policies created years ago. The sign-in log only ever produces
    # exchangeActiveSync, so the old spellings must fold onto it rather than
    # silently never matching.
    for spelling in ("easSupported", "easUnsupported", "exchangeActiveSync"):
        p = policy(clientAppTypes=[spelling])
        assert evaluate(p, conditions(client_app_type="exchangeActiveSync"),
                        member()).applies is True, spelling


def test_unrecognised_client_app_is_unsupported():
    # The corpus reports an unmapped client app as None rather than guessing;
    # the engine must not then guess either.
    p = policy(clientAppTypes=["browser"])
    e = evaluate(p, conditions(client_app_type=None), member())
    assert e.applies is None
    assert "clientAppTypes" in " ".join(e.unsupported_conditions)


def test_unrecognised_client_app_is_fine_when_the_policy_takes_all():
    p = policy(clientAppTypes=["all"])
    assert evaluate(p, conditions(client_app_type=None), member()).applies is True


# ---------------------------------------------------------------------------
# Platforms and risk
# ---------------------------------------------------------------------------

def test_platform_include_and_exclude():
    p = policy(platforms={"includePlatforms": ["windows"]})
    assert evaluate(p, conditions(device_platform="windows"), member()).applies is True
    assert evaluate(p, conditions(device_platform="iOS"), member()).applies is False

    p = policy(platforms={"includePlatforms": ["all"],
                          "excludePlatforms": ["windows"]})
    assert evaluate(p, conditions(device_platform="windows"), member()).applies is False


def test_missing_platform_is_unsupported_when_a_platform_condition_exists():
    p = policy(platforms={"includePlatforms": ["windows"]})
    e = evaluate(p, conditions(device_platform=None), member())
    assert e.applies is None


def test_no_platform_condition_ignores_a_missing_platform():
    assert evaluate(policy(), conditions(device_platform=None),
                    member()).applies is True


def test_risk_levels_match():
    p = policy(signInRiskLevels=["high", "medium"])
    assert evaluate(p, conditions(sign_in_risk_level="high"), member()).applies is True
    assert evaluate(p, conditions(sign_in_risk_level="low"), member()).applies is False


def test_hidden_risk_is_unsupported_not_no_risk():
    # 'hidden' means the tenant isn't licensed for Identity Protection. Reading
    # it as 'none' would report every risk policy as applying to nobody.
    p = policy(signInRiskLevels=["high"])
    e = evaluate(p, conditions(sign_in_risk_level="hidden"), member())
    assert e.applies is None
    assert "not licensed" in " ".join(e.unsupported_conditions)


def test_hidden_risk_is_irrelevant_without_a_risk_condition():
    assert evaluate(policy(), conditions(sign_in_risk_level="hidden"),
                    member()).applies is True


# ---------------------------------------------------------------------------
# Conditions the engine does not implement
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("condition,value", [
    ("locations", {"includeLocations": ["All"]}),
    ("devices", {"deviceFilter": {"mode": "include", "rule": "device.isCompliant -eq True"}}),
    ("clientApplications", {"includeServicePrincipals": ["All"]}),
    ("authenticationFlows", {"transferMethods": "deviceCodeFlow"}),
    ("insiderRiskLevels", "elevated"),
    ("servicePrincipalRiskLevels", ["high"]),
])
def test_unimplemented_conditions_are_named_not_ignored(condition, value):
    e = evaluate(policy(**{condition: value}), conditions(), member())
    assert e.applies is None, f"{condition} was silently ignored"
    assert e.result == UNSUPPORTED
    assert any(condition in c for c in e.unsupported_conditions)


def test_a_definite_non_match_beats_an_unsupported_condition():
    # Conditions are ANDed, so a policy that definitely doesn't cover this app
    # cannot be rescued by a location condition we can't read. Answering here
    # rather than giving up is what keeps coverage high without guessing.
    p = policy(applications={"includeApplications": ["some-other-app"]},
               locations={"includeLocations": ["All"]})
    e = evaluate(p, conditions(resource_id=EXCHANGE_ONLINE), member())
    assert e.applies is False
    assert e.result == NOT_APPLICABLE


def test_an_unsupported_condition_wins_when_everything_else_matches():
    p = policy(locations={"includeLocations": ["All"]})
    e = evaluate(p, conditions(), member())
    assert e.applies is None


# ---------------------------------------------------------------------------
# Grant and session controls
# ---------------------------------------------------------------------------

def test_block_is_absolute_and_not_combined():
    p = policy(grant={"operator": "OR", "builtInControls": ["block", "mfa"]})
    e = evaluate(p, conditions(), member())
    assert e.result == BLOCK
    assert e.grant_controls == (BLOCK,)


def test_grant_controls_and_operator_are_reported():
    p = policy(grant={"operator": "AND",
                      "builtInControls": ["mfa", "compliantDevice"]})
    e = evaluate(p, conditions(), member())
    assert e.result == GRANT
    assert e.grant_operator == "AND"
    assert e.grant_controls == ("mfa", "compliantDevice")
    assert e.requires_grant is True


def test_authentication_strength_counts_as_a_grant_control():
    # A policy can require authentication strength with no builtInControls at
    # all; reading only builtInControls would call it a no-op policy.
    p = policy(grant={"operator": "OR", "builtInControls": [],
                      "authenticationStrength": {"id": "s1",
                                                 "displayName": "Phishing-resistant MFA"}})
    e = evaluate(p, conditions(), member())
    assert e.result == GRANT
    assert e.grant_controls == ("authenticationStrength:Phishing-resistant MFA",)


def test_terms_of_use_counts_as_a_grant_control():
    p = policy(grant={"operator": "AND", "builtInControls": ["mfa"],
                      "termsOfUse": ["tou-1"]})
    e = evaluate(p, conditions(), member())
    assert e.grant_controls == ("mfa", "termsOfUse:tou-1")


def test_policy_with_no_controls_at_all():
    e = evaluate(policy(grant=None), conditions(), member())
    assert e.result == NO_CONTROLS
    assert e.requires_grant is False


def test_session_only_policy_is_reported_as_such():
    p = policy(grant=None, session={"signInFrequency": {"isEnabled": True,
                                                        "value": 4,
                                                        "type": "hours"}})
    e = evaluate(p, conditions(), member())
    assert e.result == SESSION_ONLY
    assert e.session_controls == ("signInFrequency",)


def test_disabled_session_controls_are_not_reported():
    p = policy(grant=None,
               session={"persistentBrowser": {"isEnabled": False, "mode": "never"}})
    assert evaluate(p, conditions(), member()).session_controls == ()


# ---------------------------------------------------------------------------
# Combining a whole policy set
# ---------------------------------------------------------------------------

def test_a_block_beats_every_grant_control():
    policies = [policy(grant=MFA_CONTROL),
                {**policy(grant=BLOCK_CONTROL), "id": "p2",
                 "displayName": "Block legacy"}]
    outcome = combine(evaluate_all(policies, conditions(), member()))
    assert outcome.blocked is True
    assert outcome.blocking_policies == ("Block legacy",)


def test_grant_controls_from_several_policies_are_unioned():
    policies = [
        policy(grant=MFA_CONTROL),
        {**policy(grant={"operator": "OR",
                         "builtInControls": ["mfa", "compliantDevice"]}),
         "id": "p2", "displayName": "Require compliant"},
    ]
    outcome = combine(evaluate_all(policies, conditions(), member()))
    assert outcome.blocked is False
    assert outcome.required_controls == ("mfa", "compliantDevice")
    assert len(outcome.requiring_policies) == 2


def test_report_only_policies_are_tracked_separately_from_impact():
    policies = [{**policy(state="enabledForReportingButNotEnforced",
                          grant=BLOCK_CONTROL),
                 "displayName": "Pilot block"}]
    outcome = combine(evaluate_all(policies, conditions(), member()))
    assert outcome.blocked is False
    assert outcome.report_only_policies == ("Pilot block",)


def test_an_unsupported_policy_makes_the_outcome_indeterminate():
    # The report has to be able to say the answer is partial rather than
    # presenting a confident number built on a policy it couldn't read.
    policies = [{**policy(locations={"includeLocations": ["All"]}),
                 "displayName": "Trusted locations"}]
    outcome = combine(evaluate_all(policies, conditions(), member()))
    assert outcome.determinate is False
    assert outcome.unsupported_policies == ("Trusted locations",)


def test_a_fully_evaluated_outcome_is_determinate():
    outcome = combine(evaluate_all([policy(grant=MFA_CONTROL)], conditions(),
                                   member()))
    assert outcome.determinate is True


def test_inapplicable_policies_contribute_nothing():
    policies = [policy(users={"includeUsers": ["None"]}, grant=BLOCK_CONTROL)]
    outcome = combine(evaluate_all(policies, conditions(), member()))
    assert outcome.blocked is False
    assert outcome.required_controls == ()
    assert outcome.determinate is True


def test_evaluation_is_json_serialisable():
    import json

    e = evaluate(policy(grant=MFA_CONTROL), conditions(), member())
    json.dumps(e.as_dict())
    json.dumps(combine([e]).as_dict())


def test_evaluate_does_no_io():
    # The engine is a pure function of (policy, tuple, membership). If it ever
    # needs a Graph call, the validation harness stops being cheap to run over
    # thousands of tuples.
    import app.services.ca_engine as engine

    assert not hasattr(engine, "requests")
    assert "GraphClient" not in dir(engine)
