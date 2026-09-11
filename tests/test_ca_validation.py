"""Tests for the agreement harness.

The harness is the project's evidence, so the thing these tests care about most
is that it cannot flatter the engine: a declared gap must not be counted as
agreement, a real mismatch must not be swallowed, and a run that compared
nothing must not report 100%.
"""
import pytest

from app.services.ca_memberships import Membership
from app.services.ca_validation import (
    DEFAULT_BACKOFF_SECONDS,
    AgreementReport,
    build_evaluate_request,
    call_evaluate,
    compare,
    crosscheck_applied,
    validate,
)
from app.services.graph_client import GraphError
from app.services.signin_corpus import ConditionTuple, reduce_to_tuples
from tests.test_signin_corpus import signin

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


class Memberships:
    def __init__(self, membership=None):
        self.membership = membership or member()
        self.unresolved = []

    def get(self, user_id):
        return self.membership


def policy(policy_id="p1", name="Test policy", state="enabled", grant=None,
           **condition_overrides):
    block = {"users": {"includeUsers": ["All"]},
             "applications": {"includeApplications": ["All"]},
             "clientAppTypes": ["all"], "signInRiskLevels": [],
             "userRiskLevels": []}
    block.update(condition_overrides)
    return {"id": policy_id, "displayName": name, "state": state,
            "conditions": block, "grantControls": grant, "sessionControls": None}


def what_if(policy_id="p1", name="Test policy", applies=True,
            reason="notSet", state="enabled"):
    return {"id": policy_id, "displayName": name, "state": state,
            "policyApplies": applies, "analysisReasons": reason}


class FakeClient:
    def __init__(self, responses=None, raises=None):
        self.responses = responses if responses is not None else []
        self.raises = raises or []
        self.calls = []

    def post_one(self, endpoint, payload, beta=False):
        self.calls.append((endpoint, payload))
        if self.raises:
            error = self.raises.pop(0)
            if error is not None:
                raise error
        if isinstance(self.responses, list):
            if not self.responses:
                return {"value": []}
            return self.responses.pop(0)
        return self.responses


# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------

def test_request_carries_the_observed_conditions():
    body = build_evaluate_request(conditions(), ip_address="203.0.113.9")
    assert body["signInIdentity"] == {
        "@odata.type": "#microsoft.graph.userSignIn", "userId": "u1"}
    assert body["signInContext"]["includeApplications"] == [EXCHANGE_ONLINE]
    c = body["signInConditions"]
    assert c["devicePlatform"] == "windows"
    assert c["clientAppType"] == "browser"
    assert c["country"] == "US"
    assert c["ipAddress"] == "203.0.113.9"


def test_unreported_fields_are_omitted_not_defaulted():
    # signInConditions defaults devicePlatform and clientAppType to 'all', so
    # sending a guess would have Microsoft evaluate a different sign-in than
    # the one observed and manufacture a disagreement.
    body = build_evaluate_request(
        conditions(device_platform=None, client_app_type=None, country=None))
    c = body["signInConditions"]
    assert "devicePlatform" not in c
    assert "clientAppType" not in c
    assert "country" not in c


def test_compliance_is_sent_only_when_the_log_reported_it():
    assert "deviceInfo" not in build_evaluate_request(
        conditions(is_compliant=None))["signInConditions"]
    for state in (True, False):
        body = build_evaluate_request(conditions(is_compliant=state))
        assert body["signInConditions"]["deviceInfo"] == {"isCompliant": state}


def test_request_sends_the_resource_not_the_client_app():
    # signInContext.includeApplications is the resource CA targets. Sending the
    # client appId would ask Microsoft about a different sign-in than the one
    # observed, and every app-scoped policy would come back as non-applicable.
    body = build_evaluate_request(conditions(resource_id=EXCHANGE_ONLINE))
    assert body["signInContext"]["includeApplications"] == [EXCHANGE_ONLINE]


def test_all_policies_are_requested_not_only_applicable_ones():
    # appliedPoliciesOnly=True would hide exactly the policies we most need to
    # diff: the ones Microsoft says do not apply.
    assert build_evaluate_request(conditions())["appliedPoliciesOnly"] is False


# ---------------------------------------------------------------------------
# Throttling
# ---------------------------------------------------------------------------

def test_throttling_respects_retry_after():
    slept = []
    client = FakeClient(
        responses=[{"value": []}],
        raises=[GraphError("throttled", status=429, retry_after=7)])
    call_evaluate(client, {}, sleep=slept.append)
    assert slept == [7]


def test_throttling_without_a_header_backs_off_exponentially():
    slept = []
    client = FakeClient(
        responses=[{"value": []}],
        raises=[GraphError("throttled", status=429, retry_after=None)])
    call_evaluate(client, {}, sleep=slept.append)
    assert slept == [DEFAULT_BACKOFF_SECONDS]


def test_non_throttle_errors_are_not_retried():
    client = FakeClient(raises=[GraphError("forbidden", status=403)])
    with pytest.raises(GraphError):
        call_evaluate(client, {}, sleep=lambda _: None)
    assert len(client.calls) == 1


def test_persistent_throttling_eventually_raises():
    client = FakeClient(
        raises=[GraphError("throttled", status=429, retry_after=1)] * 10)
    with pytest.raises(GraphError):
        call_evaluate(client, {}, sleep=lambda _: None)


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def run_compare(policies, what_if_results, membership=None):
    from app.services.ca_engine import evaluate as ev

    report = AgreementReport()
    ours = [ev(p, conditions(), membership or member()) for p in policies]
    compare(ours, what_if_results, conditions(), 100, report)
    return report


def test_matching_verdicts_agree():
    report = run_compare([policy()], [what_if(applies=True)])
    assert report.comparisons == 1
    assert report.agreements == 1
    assert report.disagreements == []
    assert report.agreement_rate == 1.0


def test_mismatched_verdicts_are_recorded_with_both_reasons():
    report = run_compare(
        [policy(applications={"includeApplications": [EXCHANGE_ONLINE]})],
        [what_if(applies=False, reason="application")])
    assert report.agreements == 0
    assert len(report.disagreements) == 1
    d = report.disagreements[0]
    assert d.ours is True and d.theirs is False
    # The condition Microsoft blames is what points at the bug.
    assert d.their_reason == "application"
    assert d.sign_ins == 100


def test_unsupported_is_a_declared_gap_not_an_agreement():
    # Counting our own gaps as agreement would let the headline rate climb
    # while the engine understood less and less.
    report = run_compare([policy(locations={"includeLocations": ["All"]})],
                         [what_if(applies=True)])
    assert report.comparisons == 0
    assert report.agreements == 0
    assert report.disagreements == []
    assert sum(report.unsupported.values()) == 1


def test_microsoft_uncertainty_is_not_a_disagreement():
    # Both sides declining to decide is agreement about uncertainty.
    report = run_compare([policy()],
                         [what_if(applies=False, reason="notEnoughInformation")])
    assert report.comparisons == 0
    assert report.microsoft_uncertain == 1
    assert report.disagreements == []


def test_a_policy_microsoft_did_not_return_is_counted_separately():
    report = run_compare([policy(policy_id="p1")], [what_if(policy_id="p2")])
    assert report.missing_from_theirs == 1
    assert report.comparisons == 0


def test_disabled_policy_agreement():
    # Microsoft reports policyApplies false with policyNotEnabled; so do we.
    report = run_compare([policy(state="disabled")],
                         [what_if(applies=False, reason="policyNotEnabled")])
    assert report.agreements == 1


def test_report_only_policy_counts_as_applying_on_both_sides():
    report = run_compare(
        [policy(state="enabledForReportingButNotEnforced")],
        [what_if(applies=True, state="enabledForReportingButNotEnforced")])
    assert report.agreements == 1


def test_an_empty_run_reports_no_rate_rather_than_perfect():
    # A harness that compared nothing must not read as 100% agreement.
    report = AgreementReport()
    assert report.agreement_rate is None
    assert report.perfect is False
    assert report.summary()["agreement_rate"] is None


# ---------------------------------------------------------------------------
# The full sweep
# ---------------------------------------------------------------------------

def corpus_of(*records):
    return reduce_to_tuples(list(records))


def test_validate_walks_the_corpus_and_reports_coverage():
    corpus = corpus_of(signin(userId="u1"), signin(userId="u1"),
                       signin(userId="u2"))
    client = FakeClient(responses=[{"value": [what_if()]},
                                   {"value": [what_if()]}])
    report = validate(client, corpus, [policy()], Memberships())
    assert report.tuples_compared == 2
    assert report.sign_ins_covered == 3
    assert report.corpus_sign_ins == 3
    assert report.coverage == 1.0
    assert report.agreements == 2


def test_busiest_tuples_are_compared_first():
    # A capped run should cover as much real traffic as possible per call.
    corpus = corpus_of(*([signin(userId="busy")] * 5), signin(userId="quiet"))
    client = FakeClient(responses=[{"value": [what_if()]}])
    report = validate(client, corpus, [policy()], Memberships(), max_tuples=1)
    assert report.tuples_compared == 1
    assert report.sign_ins_covered == 5
    assert report.coverage == 5 / 6
    assert client.calls[0][1]["signInIdentity"]["userId"] == "busy"


def test_a_failed_evaluate_call_is_recorded_not_silently_dropped():
    corpus = corpus_of(signin(userId="u1"))
    client = FakeClient(responses=[], raises=[GraphError("boom", status=403)])
    report = validate(client, corpus, [policy()], Memberships())
    assert report.errors and "boom" in report.errors[0]
    assert report.tuples_compared == 0


def test_validate_hits_the_evaluate_endpoint():
    corpus = corpus_of(signin(userId="u1"))
    client = FakeClient(responses=[{"value": [what_if()]}])
    validate(client, corpus, [policy()], Memberships())
    assert client.calls[0][0] == "/identity/conditionalAccess/evaluate"


# ---------------------------------------------------------------------------
# Cross-check against the sign-in log
# ---------------------------------------------------------------------------

def applied(policy_id="p1", name="Test policy", result="success"):
    return {"id": policy_id, "displayName": name, "result": result,
            "enforcedGrantControls": [], "enforcedSessionControls": []}


def test_crosscheck_agrees_when_the_log_says_the_policy_applied():
    corpus = corpus_of(signin(appliedConditionalAccessPolicies=[applied()]))
    check = crosscheck_applied(corpus, [policy()], Memberships())
    assert check.comparisons == 1
    assert check.agreements == 1


def test_crosscheck_catches_a_policy_we_wrongly_think_applies():
    corpus = corpus_of(signin(
        appliedConditionalAccessPolicies=[applied(result="notApplied")]))
    check = crosscheck_applied(corpus, [policy()], Memberships())
    assert check.agreements == 0
    assert len(check.disagreements) == 1
    assert check.disagreements[0].ours is True


@pytest.mark.parametrize("result", ["reportOnlySuccess", "reportOnlyFailure",
                                    "reportOnlyInterrupted"])
def test_report_only_results_count_as_the_policy_having_applied(result):
    # The policy applied; it just wasn't enforced. That is what our engine says
    # about a report-only policy too.
    corpus = corpus_of(signin(
        appliedConditionalAccessPolicies=[applied(result=result)]))
    check = crosscheck_applied(corpus, [policy()], Memberships())
    assert check.agreements == 1


def test_unknown_results_are_skipped():
    corpus = corpus_of(signin(
        appliedConditionalAccessPolicies=[applied(result="unknown")]))
    check = crosscheck_applied(corpus, [policy()], Memberships())
    assert check.comparisons == 0
    assert check.skipped_unknown == 1


def test_unsupported_policies_are_skipped_not_counted_wrong():
    corpus = corpus_of(signin(appliedConditionalAccessPolicies=[applied()]))
    check = crosscheck_applied(
        corpus, [policy(locations={"includeLocations": ["All"]})], Memberships())
    assert check.comparisons == 0
    assert check.skipped_unsupported == 1


def test_a_tuple_whose_sign_ins_disagree_is_flagged_as_ambiguous():
    # Same conditions, different real outcomes: some condition that decides the
    # policy is missing from the tuple key, so impact numbers built on this
    # aggregation would be wrong. That is a finding about the corpus.
    corpus = corpus_of(
        signin(appliedConditionalAccessPolicies=[applied(result="success")]),
        signin(appliedConditionalAccessPolicies=[applied(result="notApplied")]),
    )
    check = crosscheck_applied(corpus, [policy()], Memberships())
    assert len(check.ambiguous) == 1
    assert check.comparisons == 0
    assert check.ambiguous[0]["results"] == {"success": 1, "notApplied": 1}


def test_policies_deleted_since_the_sign_in_are_ignored():
    corpus = corpus_of(signin(
        appliedConditionalAccessPolicies=[applied(policy_id="gone")]))
    check = crosscheck_applied(corpus, [policy(policy_id="p1")], Memberships())
    assert check.comparisons == 0
    assert check.disagreements == []


def test_crosscheck_makes_no_graph_calls():
    # It runs on data already captured into the corpus, so it works on a tenant
    # that would throttle a full evaluate sweep.
    class Boom:
        def post_one(self, *a, **k):
            raise AssertionError("crosscheck called Graph")

    corpus = corpus_of(signin(appliedConditionalAccessPolicies=[applied()]))
    crosscheck_applied(corpus, [policy()], Memberships())


def test_reports_are_json_serialisable():
    import json

    corpus = corpus_of(signin(appliedConditionalAccessPolicies=[applied()]))
    client = FakeClient(responses=[{"value": [what_if()]}])
    report = validate(client, corpus, [policy()], Memberships())
    json.dumps(report.summary())
    json.dumps(crosscheck_applied(corpus, [policy()], Memberships()).summary())


# ---------------------------------------------------------------------------
# Configuration that changed after the sign-in
# ---------------------------------------------------------------------------

def dated_policy(created="2026-01-01T00:00:00Z", modified=None, **overrides):
    p = policy(**overrides)
    p["createdDateTime"] = created
    if modified:
        p["modifiedDateTime"] = modified
    return p


def test_a_sign_in_predating_the_policy_is_skipped_not_disagreed():
    # Entra evaluated that sign-in under a configuration that no longer exists.
    # Counting it as a disagreement blames the engine for the passage of time.
    corpus = corpus_of(signin(createdDateTime="2026-01-01T00:00:00Z",
                              appliedConditionalAccessPolicies=[
                                  applied(result="notApplied")]))
    later = dated_policy(created="2026-06-01T00:00:00Z")
    check = crosscheck_applied(corpus, [later], Memberships())
    assert check.comparisons == 0
    assert check.disagreements == []
    assert check.skipped_config_changed == 1


def test_a_sign_in_after_the_policy_is_still_compared():
    corpus = corpus_of(signin(createdDateTime="2026-09-01T00:00:00Z",
                              appliedConditionalAccessPolicies=[applied()]))
    check = crosscheck_applied(corpus, [dated_policy()], Memberships())
    assert check.comparisons == 1
    assert check.agreements == 1


def test_a_named_location_created_after_the_sign_in_also_skips():
    # Changing a location silently changes what a policy does without touching
    # the policy — so the policy's own timestamp is not enough.
    corpus = corpus_of(signin(createdDateTime="2026-06-15T00:00:00Z",
                              appliedConditionalAccessPolicies=[applied()]))
    scoped = dated_policy(created="2026-01-01T00:00:00Z",
                          locations={"includeLocations": ["All"],
                                     "excludeLocations": ["loc-1"]})
    locations = [{"id": "loc-1", "displayName": "HQ", "isTrusted": True,
                  "createdDateTime": "2026-09-01T00:00:00Z"}]
    check = crosscheck_applied(corpus, [scoped], Memberships(),
                               named_locations=locations)
    assert check.skipped_config_changed == 1
    assert check.comparisons == 0


def test_all_trusted_depends_on_every_trusted_location():
    # AllTrusted is not an id, so the policy depends on any trusted location
    # in the tenant appearing at all.
    corpus = corpus_of(signin(createdDateTime="2026-06-15T00:00:00Z",
                              appliedConditionalAccessPolicies=[applied()]))
    scoped = dated_policy(created="2026-01-01T00:00:00Z",
                          locations={"includeLocations": ["All"],
                                     "excludeLocations": ["AllTrusted"]})
    locations = [{"id": "loc-9", "displayName": "New HQ", "isTrusted": True,
                  "createdDateTime": "2026-09-01T00:00:00Z"}]
    check = crosscheck_applied(corpus, [scoped], Memberships(),
                               named_locations=locations)
    assert check.skipped_config_changed == 1


def test_an_undated_policy_is_compared_rather_than_skipped():
    # Skipping on a guess would quietly shrink the check to nothing.
    corpus = corpus_of(signin(appliedConditionalAccessPolicies=[applied()]))
    check = crosscheck_applied(corpus, [policy()], Memberships())
    assert check.comparisons == 1
    assert check.skipped_config_changed == 0
