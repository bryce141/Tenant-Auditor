"""Tests for app-group expansion.

The Office 365 membership list is an approximation by Microsoft's own account —
the reference gives display names, says the list changes, and warns that a
tenant's service principals only approximate the suite. So the guarantee these
tests can offer is structural; the empirical check is the agreement harness,
which compares the expansion against Microsoft on real traffic.
"""
from app.services.ca_app_groups import (
    ADMIN_PORTAL_APP_IDS,
    MICROSOFT_ADMIN_PORTALS,
    OFFICE365,
    AppGroupResolver,
)
from app.services.ca_engine import evaluate
from app.services.ca_memberships import Membership
from app.services.signin_corpus import ConditionTuple, reduce_to_tuples
from tests.test_signin_corpus import signin

EXCHANGE = "00000002-0000-0ff1-ce00-000000000000"
GRAPH = "00000003-0000-0000-c000-000000000000"
EXCHANGE_ADMIN = "497effe9-df71-4043-a8bb-14cf78c4b63b"


def service_principals():
    return [
        {"id": "sp1", "appId": EXCHANGE, "displayName": "Office 365 Exchange Online"},
        {"id": "sp2", "appId": GRAPH, "displayName": "Microsoft Graph"},
        {"id": "sp3", "appId": "teams-app-id", "displayName": "Microsoft Teams"},
        {"id": "sp4", "appId": EXCHANGE_ADMIN, "displayName": "Exchange Admin Center"},
    ]


def conditions(**overrides):
    base = dict(user_id="u1", resource_id=EXCHANGE, client_app_type="browser",
                device_platform="windows", country="US", is_compliant=None,
                join_type=None, sign_in_risk_level="none", user_risk_level="none",
                named_location_ids=frozenset(), in_trusted_location=False,
                app_group_tokens=frozenset())
    base.update(overrides)
    return ConditionTuple(**base)


def member():
    return Membership(user_id="u1", user_type="Member", resolved=True)


def policy(applications):
    return {"id": "p1", "displayName": "App group policy", "state": "enabled",
            "conditions": {"users": {"includeUsers": ["All"]},
                           "applications": applications,
                           "clientAppTypes": ["all"], "signInRiskLevels": [],
                           "userRiskLevels": []},
            "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
            "sessionControls": None}


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

def test_suite_members_are_recognised_by_display_name():
    r = AppGroupResolver(service_principals())
    assert r.resolve(EXCHANGE).contains(OFFICE365) is True
    assert r.resolve("teams-app-id").contains(OFFICE365) is True


def test_microsoft_graph_is_not_in_the_office365_suite():
    # Graph is an umbrella resource and is explicitly not targetable as part of
    # the suite. Including it would over-report every Office365-scoped policy.
    r = AppGroupResolver(service_principals())
    assert r.resolve(GRAPH, "Microsoft Graph").contains(OFFICE365) is False


def test_admin_portals_are_matched_by_documented_id_not_by_name():
    # This grouping is enumerated with ids in the reference, so membership is
    # exact rather than approximate.
    r = AppGroupResolver(service_principals())
    assert r.resolve(EXCHANGE_ADMIN).contains(MICROSOFT_ADMIN_PORTALS) is True
    assert r.resolve(EXCHANGE, "Office 365 Exchange Online").contains(MICROSOFT_ADMIN_PORTALS) is False


def test_every_documented_admin_portal_id_resolves():
    r = AppGroupResolver([])
    for app_id in ADMIN_PORTAL_APP_IDS:
        assert r.resolve(app_id).contains(MICROSOFT_ADMIN_PORTALS) is True


def test_matching_is_case_insensitive_on_both_sides():
    r = AppGroupResolver([{"appId": EXCHANGE.upper(),
                           "displayName": "OFFICE 365 EXCHANGE ONLINE"}])
    assert r.resolve(EXCHANGE).contains(OFFICE365) is True


def test_a_resource_with_no_id_is_unresolved_not_absent():
    assert AppGroupResolver([]).resolve(None).contains(OFFICE365) is None


def test_a_suite_member_with_no_service_principal_is_matched_by_name():
    # OfficeHome is in Microsoft's published list, is targeted by Office365
    # scoped policies, and has no service principal in the tenant whose
    # traffic it appears in. Matching only via service principals called it
    # "outside the suite" — a false negative, caught by the agreement harness.
    r = AppGroupResolver([])  # no service principals at all
    assert r.resolve("4765445b-32c6-49b0-83e6-1d93765276ca",
                     "OfficeHome").contains(OFFICE365) is True


def test_a_named_resource_absent_from_the_list_is_definitely_outside():
    # The published list is Microsoft's statement of membership by name, so a
    # name we can check and do not find is a real answer, not a gap.
    r = AppGroupResolver(service_principals())
    assert r.resolve(GRAPH, "Microsoft Graph").contains(OFFICE365) is False


def test_a_resource_with_no_name_and_no_match_stays_unknown():
    # Without a name there is nothing to check against, so "not in the suite"
    # would be a guess.
    r = AppGroupResolver([])
    assert r.resolve("some-unknown-app-id").contains(OFFICE365) is None


def test_coverage_reports_how_much_of_the_suite_is_provisioned():
    matched, total = AppGroupResolver(service_principals()).coverage
    assert matched == 2  # Exchange Online and Teams
    assert total > 100


def test_an_empty_directory_still_matches_by_name():
    r = AppGroupResolver([])
    assert r.resolve(EXCHANGE, "Office 365 Exchange Online").contains(OFFICE365) is True


# ---------------------------------------------------------------------------
# Corpus and engine
# ---------------------------------------------------------------------------

def test_corpus_records_group_membership_per_resource():
    resolver = AppGroupResolver(service_principals())
    corpus = reduce_to_tuples([signin(resourceId=EXCHANGE),
                               signin(resourceId=GRAPH)],
                              app_groups=resolver)
    tokens = {frozenset(o.conditions.app_group_tokens)
              for o in corpus.observations}
    assert frozenset({OFFICE365}) in tokens
    assert frozenset() in tokens


def test_without_a_resolver_membership_is_unknown_not_empty():
    corpus = reduce_to_tuples([signin(resourceId=EXCHANGE)])
    assert corpus.observations[0].conditions.app_group_tokens is None


def test_engine_answers_an_office365_policy_once_membership_is_known():
    p = policy({"includeApplications": ["Office365"]})
    inside = conditions(app_group_tokens=frozenset({OFFICE365}))
    outside = conditions(resource_id=GRAPH, app_group_tokens=frozenset())
    assert evaluate(p, inside, member()).applies is True
    assert evaluate(p, outside, member()).applies is False


def test_engine_refuses_to_answer_when_membership_was_never_resolved():
    p = policy({"includeApplications": ["Office365"]})
    e = evaluate(p, conditions(app_group_tokens=None), member())
    assert e.applies is None


def test_a_policy_without_group_tokens_is_unaffected_by_unresolved_membership():
    p = policy({"includeApplications": ["All"]})
    assert evaluate(p, conditions(app_group_tokens=None), member()).applies is True
