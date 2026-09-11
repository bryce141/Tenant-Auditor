"""Tests for the 'what's missing' recommendations.

This page gives advice, so the tests care most about the ways advice can
mislead: recommending something already in place, claiming a partial fix is a
complete one, implying the list is exhaustive, or calling a policy safe when
its impact could not actually be evaluated.
"""
import os

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app.services.ca_recommendations import (  # noqa: E402
    OUT_OF_SCOPE, REMEDIES, SAFE, SIGNIFICANT, UNKNOWN, out_of_scope, recommend,
    unaddressed)
from app.services.ca_memberships import Membership, MembershipSet  # noqa: E402
from app.services.signin_corpus import reduce_to_tuples  # noqa: E402
from tests.test_signin_corpus import signin  # noqa: E402

EXCHANGE = "00000002-0000-0ff1-ce00-000000000000"


class Check:
    """Stands in for a ReportCheck row."""

    def __init__(self, check_name, status="fail", display_name=None, summary="x"):
        self.check_name = check_name
        self.status = status
        self.display_name = display_name or check_name
        self.summary = summary


class Memberships(MembershipSet):
    def get(self, user_id):
        return Membership(user_id=user_id, user_type="Member", resolved=True)


def corpus_of(*records):
    return reduce_to_tuples(list(records) or [signin(userId="u1")], window_days=30)


def policy(name="Existing", controls=("mfa",), **conditions):
    block = {"users": {"includeUsers": ["All"]},
             "applications": {"includeApplications": ["All"]},
             "clientAppTypes": ["all"], "signInRiskLevels": [],
             "userRiskLevels": []}
    block.update(conditions)
    return {"id": name, "displayName": name, "state": "enabled",
            "conditions": block,
            "grantControls": {"operator": "OR", "builtInControls": list(controls)},
            "sessionControls": None}


# ---------------------------------------------------------------------------

def test_only_failing_findings_produce_recommendations():
    # This is a list of what is missing, not a catalogue of everything possible.
    passing = [Check("legacy_auth_blocked", status="pass")]
    assert recommend(passing, corpus_of(), Memberships()) == []


def test_a_failing_finding_produces_its_remedy():
    found = recommend([Check("legacy_auth_blocked")], corpus_of(), Memberships())
    assert len(found) == 1
    assert found[0].remedy_id == "block-legacy"
    assert found[0].draft["grantControls"]["builtInControls"] == ["block"]


def test_one_policy_answering_several_findings_appears_once():
    # Recommending "require MFA" three times because three checks failed pads
    # the list and implies more work than there is.
    found = recommend([Check("conditional_access"), Check("mfa_registration")],
                      corpus_of(), Memberships())
    assert len(found) == 1
    assert {f["check_name"] for f in found[0].findings} == {
        "conditional_access", "mfa_registration"}


def test_impact_is_a_delta_against_existing_policies():
    # A recommendation duplicating a policy already in force costs nothing, and
    # saying otherwise would overstate every recommendation.
    checks = [Check("conditional_access")]
    corpus = corpus_of(*[signin(userId="u1")] * 5)
    found = recommend(checks, corpus, Memberships(),
                      existing_policies=[policy(controls=("mfa",))])
    assert found[0].impact.affected_sign_ins == 0
    assert found[0].verdict == SAFE
    assert "safe to enable" in found[0].headline.lower()


def test_a_policy_affecting_everyone_is_not_called_safe():
    checks = [Check("conditional_access")]
    corpus = corpus_of(*[signin(userId=f"u{i}") for i in range(10)])
    found = recommend(checks, corpus, Memberships())
    assert found[0].verdict == SIGNIFICANT


def test_unevaluable_impact_is_never_reported_as_safe():
    # Indistinguishable from genuinely safe otherwise, which is the worst
    # possible confusion on a page answering "is this safe to turn on".
    checks = [Check("legacy_auth_blocked")]
    # No client app type on the sign-in makes the legacy-auth policy unevaluable.
    corpus = corpus_of(signin(userId="u1", clientAppUsed="Some New Client"))
    found = recommend(checks, corpus, Memberships())
    assert found[0].verdict == UNKNOWN
    assert "cannot be fully assessed" in found[0].headline.lower()


def test_partial_remedies_say_they_are_partial():
    # Standing privileged access is fixed by PIM. Claiming a CA policy clears
    # it would be a sales pitch rather than advice.
    found = recommend([Check("pim_standing_roles")], corpus_of(), Memberships())
    assert found[0].partial
    assert "PIM" in found[0].partial


def test_remedies_without_a_caveat_have_none():
    found = recommend([Check("legacy_auth_blocked")], corpus_of(), Memberships())
    assert found[0].partial is None


def test_easiest_decisions_are_listed_first():
    corpus = corpus_of(*[signin(userId=f"u{i}") for i in range(10)])
    checks = [Check("conditional_access"), Check("legacy_auth_blocked")]
    found = recommend(checks, corpus, Memberships())
    verdicts = [r.verdict for r in found]
    # Block-legacy affects nobody here (all browser traffic); baseline MFA hits
    # everyone. The safe one must come first.
    assert verdicts[0] == SAFE


def test_out_of_scope_findings_are_reported_with_where_the_fix_lives():
    rows = out_of_scope([Check("email_authentication", display_name="Email Auth")])
    assert len(rows) == 1
    assert "DNS" in rows[0]["where"]


def test_out_of_scope_ignores_passing_checks():
    assert out_of_scope([Check("email_authentication", status="pass")]) == []


def test_findings_with_no_recommendation_are_still_surfaced():
    # A page that silently skipped a third of the audit would read as a
    # complete answer when it is not.
    rows = unaddressed([Check("some_future_check", display_name="Future")])
    assert [r["check_name"] for r in rows] == ["some_future_check"]


def test_a_covered_finding_is_not_also_listed_as_unaddressed():
    assert unaddressed([Check("legacy_auth_blocked")]) == []


def test_out_of_scope_findings_are_not_listed_as_unaddressed():
    assert unaddressed([Check("email_authentication")]) == []


def test_every_remedy_builds_a_valid_policy():
    # The forms go through the same builder the UI uses, so a malformed remedy
    # fails here rather than at render time.
    from app.services.ca_builder import build_policy

    for remedy_id, remedy in REMEDIES.items():
        draft = build_policy(dict(remedy["form"]))
        assert draft["displayName"], remedy_id
        assert draft["grantControls"]["builtInControls"], remedy_id


def test_every_remedy_and_scope_entry_names_a_real_check():
    from app.services.scoring import CIS_MAP

    known = set(CIS_MAP)
    for remedy_id, remedy in REMEDIES.items():
        unknown = remedy["addresses"] - known
        assert not unknown, f"{remedy_id} addresses unknown checks: {unknown}"
    assert not set(OUT_OF_SCOPE) - known


def test_recommendations_are_json_serialisable():
    import json

    found = recommend([Check("legacy_auth_blocked")], corpus_of(), Memberships())
    json.dumps([r.as_dict() for r in found])
