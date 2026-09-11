"""Tests for the impact report.

Every number here is a delta against what the tenant already does, and the ways
it can go wrong all inflate it — which is the direction that flatters the tool,
so that is where these tests concentrate.
"""
from app.services.ca_impact import assess
from app.services.ca_memberships import Membership
from app.services.signin_corpus import reduce_to_tuples
from tests.test_signin_corpus import signin

EXCHANGE = "00000002-0000-0ff1-ce00-000000000000"
GRAPH = "00000003-0000-0000-c000-000000000000"


def member(**overrides):
    base = dict(user_id="u1", group_ids=frozenset(), role_ids=frozenset(),
                role_template_ids=frozenset(), user_type="Member", resolved=True)
    base.update(overrides)
    return Membership(**base)


class Memberships:
    def __init__(self):
        self.unresolved = []

    def get(self, user_id):
        return member(user_id=user_id)


def policy(name="Policy", state="enabled", controls=("mfa",), operator="OR",
           applications=None, **condition_overrides):
    block = {"users": {"includeUsers": ["All"]},
             "applications": applications or {"includeApplications": ["All"]},
             "clientAppTypes": ["all"], "signInRiskLevels": [],
             "userRiskLevels": []}
    block.update(condition_overrides)
    return {"id": name, "displayName": name, "state": state,
            "conditions": block,
            "grantControls": {"operator": operator,
                              "builtInControls": list(controls)},
            "sessionControls": None}


def corpus_of(*records):
    return reduce_to_tuples(list(records), window_days=30)


# ---------------------------------------------------------------------------
# The headline number
# ---------------------------------------------------------------------------

def test_affected_sign_ins_never_exceeds_the_corpus():
    # A sign-in that newly needs both MFA and a compliant device is ONE
    # affected sign-in, not two. Summing the per-control counts produced a
    # headline larger than the corpus itself.
    corpus = corpus_of(*[signin(userId="u1", resourceId=GRAPH)] * 10)
    draft = policy(controls=("mfa", "compliantDevice"), operator="AND")
    impact = assess(draft, corpus, Memberships())

    assert impact.affected_sign_ins == 10
    assert impact.affected_sign_ins <= impact.corpus_sign_ins
    assert impact.summary()["new_controls"]["mfa"]["sign_ins"] == 10
    assert impact.summary()["new_controls"]["compliantDevice"]["sign_ins"] == 10


def test_headline_counts_distinct_users():
    corpus = corpus_of(signin(userId="u1"), signin(userId="u1"),
                       signin(userId="u2"))
    impact = assess(policy(), corpus, Memberships())
    assert impact.affected_sign_ins == 3
    assert len(impact.affected_users) == 2
    assert "3 sign-ins across 2 users" in impact.headline()


def test_a_draft_that_affects_nothing_says_so():
    corpus = corpus_of(signin(userId="u1"))
    draft = policy(applications={"includeApplications": ["some-other-app"]})
    impact = assess(draft, corpus, Memberships())
    assert impact.affected_sign_ins == 0
    assert "No sign-ins" in impact.headline()


# ---------------------------------------------------------------------------
# Impact is a delta
# ---------------------------------------------------------------------------

def test_a_control_already_required_is_not_counted_as_new():
    # The users notice nothing, so reporting them as impacted is noise that
    # makes every draft look more disruptive than it is.
    corpus = corpus_of(*[signin(userId="u1")] * 5)
    existing = [policy(name="Existing MFA", controls=("mfa",))]
    impact = assess(policy(name="Draft MFA", controls=("mfa",)), corpus,
                    Memberships(), existing_policies=existing)

    assert impact.affected_sign_ins == 0
    assert impact.unchanged_sign_ins == 5


def test_only_the_genuinely_new_control_is_counted():
    corpus = corpus_of(*[signin(userId="u1")] * 5)
    existing = [policy(name="Existing MFA", controls=("mfa",))]
    draft = policy(name="Draft", controls=("mfa", "compliantDevice"), operator="AND")
    impact = assess(draft, corpus, Memberships(), existing_policies=existing)

    controls = impact.summary()["new_controls"]
    assert "mfa" not in controls
    assert controls["compliantDevice"]["sign_ins"] == 5


def test_traffic_already_blocked_is_not_counted_as_newly_blocked():
    corpus = corpus_of(*[signin(userId="u1")] * 4)
    existing = [policy(name="Existing block", controls=("block",))]
    impact = assess(policy(name="Draft block", controls=("block",)), corpus,
                    Memberships(), existing_policies=existing)
    assert impact.blocked_sign_ins == 0
    assert impact.unchanged_sign_ins == 4


def test_a_block_is_reported_when_nothing_blocked_before():
    corpus = corpus_of(*[signin(userId="u1")] * 4)
    impact = assess(policy(controls=("block",)), corpus, Memberships())
    assert impact.blocked_sign_ins == 4
    assert len(impact.blocked_users) == 1


def test_the_draft_does_not_count_as_its_own_baseline():
    # Re-simulating a policy that is already in the tenant must still report
    # its impact, or editing an existing policy would always read as harmless.
    corpus = corpus_of(*[signin(userId="u1")] * 3)
    draft = policy(name="Same", controls=("mfa",))
    impact = assess(draft, corpus, Memberships(), existing_policies=[draft])
    assert impact.affected_sign_ins == 3


# ---------------------------------------------------------------------------
# Unevaluable traffic
# ---------------------------------------------------------------------------

def test_unevaluable_traffic_is_quarantined_not_counted_as_unaffected():
    # A tuple we could not evaluate might be the one that breaks someone
    # important, so it must not silently join the "unaffected" majority.
    corpus = corpus_of(*[signin(userId="u1")] * 6)
    draft = policy(locations={"includeLocations": ["All"]})
    impact = assess(draft, corpus, Memberships())

    assert impact.unsupported_sign_ins == 6
    assert impact.affected_sign_ins == 0
    assert impact.complete is False
    assert impact.summary()["unsupported_reasons"]


def test_a_fully_evaluated_report_is_complete():
    corpus = corpus_of(*[signin(userId="u1")] * 3)
    assert assess(policy(), corpus, Memberships()).complete is True


def test_unsupported_reasons_are_weighted_by_sign_ins():
    corpus = corpus_of(*[signin(userId="u1")] * 9)
    draft = policy(locations={"includeLocations": ["All"]})
    reasons = assess(draft, corpus, Memberships()).unsupported_reasons
    assert sum(reasons.values()) == 9


# ---------------------------------------------------------------------------
# Draft state
# ---------------------------------------------------------------------------

def test_a_report_only_draft_is_simulated_as_if_enabled_but_flagged():
    # Evaluating a report-only draft in its declared state would report that it
    # changes nothing — true, and useless, since the question is what happens
    # when it is switched on.
    corpus = corpus_of(*[signin(userId="u1")] * 5)
    draft = policy(state="enabledForReportingButNotEnforced", controls=("block",))
    impact = assess(draft, corpus, Memberships())

    assert impact.blocked_sign_ins == 5
    assert impact.enforces is False
    assert impact.summary()["declared_state"] == "enabledForReportingButNotEnforced"


def test_an_enabled_draft_reports_that_it_enforces():
    corpus = corpus_of(signin(userId="u1"))
    assert assess(policy(state="enabled"), corpus, Memberships()).enforces is True


# ---------------------------------------------------------------------------
# Breakdowns
# ---------------------------------------------------------------------------

def test_breakdowns_sum_to_the_affected_total():
    corpus = corpus_of(
        *[signin(userId="u1", resourceId=GRAPH)] * 3,
        *[signin(userId="u2", resourceId=EXCHANGE)] * 2,
    )
    impact = assess(policy(), corpus, Memberships())
    report = impact.summary()
    assert sum(report["by_resource"].values()) == impact.affected_sign_ins
    assert sum(report["by_platform"].values()) == impact.affected_sign_ins


def test_unreported_platform_is_labelled_not_dropped():
    corpus = corpus_of(signin(userId="u1", deviceDetail={"operatingSystem": None}))
    report = assess(policy(), corpus, Memberships()).summary()
    assert "(not reported)" in report["by_platform"]


def test_affected_users_are_ordered_by_volume():
    corpus = corpus_of(*[signin(userId="busy")] * 7, signin(userId="quiet"))
    report = assess(policy(), corpus, Memberships()).summary()
    assert report["affected"][0]["user_id"] == "busy"
    assert report["affected"][0]["sign_ins"] == 7


def test_report_is_json_serialisable():
    import json

    corpus = corpus_of(signin(userId="u1"))
    json.dumps(assess(policy(), corpus, Memberships()).summary())
