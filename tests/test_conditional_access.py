"""Tests for the Conditional Access checks.

CA requires an Entra ID P1/P2 licence, so the dev tenant this was built against
returns zero policies and these paths had never executed against real data.
The fixtures below follow the documented conditionalAccessPolicy schema
(learn.microsoft.com/graph/api/resources/conditionalaccesspolicy), including
the shapes the Entra portal actually produces.
"""
import pytest

from app.checks.conditional_access import check_conditional_access, check_legacy_auth
from app.services.graph_client import GraphError


class Client:
    def __init__(self, policies):
        self.policies = policies

    def get_all(self, endpoint, params=None, beta=False):
        if isinstance(self.policies, Exception):
            raise self.policies
        return self.policies


def policy(name="Policy", state="enabled", client_app_types=None,
           controls=None, users=None):
    """A policy in the shape Graph returns."""
    return {
        "id": f"id-{name}",
        "displayName": name,
        "state": state,
        "conditions": {
            "clientAppTypes": client_app_types if client_app_types is not None else ["all"],
            "users": users if users is not None else {
                "includeUsers": ["All"], "excludeUsers": [],
                "excludeGroups": [], "excludeRoles": [],
            },
            "applications": {"includeApplications": ["All"]},
        },
        "grantControls": {"operator": "OR", "builtInControls": controls or []} if controls is not None else None,
    }


LEGACY_BLOCK = ["exchangeActiveSync", "other"]


# ----------------------------------------------------------- legacy auth

def test_no_policies_fails():
    result = check_legacy_auth(Client([]))
    assert result["status"] == "fail"
    assert result["points_earned"] == 0


def test_explicit_legacy_block_passes():
    """The shape the portal produces for 'Block legacy authentication'."""
    result = check_legacy_auth(Client([
        policy("Block legacy auth", client_app_types=LEGACY_BLOCK, controls=["block"])]))

    assert result["status"] == "pass"
    assert result["points_earned"] == 10
    assert result["details"]["blocking_policies"] == ["Block legacy auth"]


def test_all_client_types_counts_as_blocking_legacy():
    """'all' includes legacy clients — this used to be reported as unprotected."""
    result = check_legacy_auth(Client([
        policy("Block everything from bad places", client_app_types=["all"], controls=["block"])]))

    assert result["status"] == "pass", "clientAppTypes 'all' does cover legacy auth"
    assert result["points_earned"] == 10


@pytest.mark.parametrize("legacy_type", ["exchangeActiveSync", "other",
                                         "easSupported", "easUnsupported"])
def test_every_legacy_spelling_is_recognised(legacy_type):
    """Older policies carry older enum spellings; Graph still returns them."""
    result = check_legacy_auth(Client([
        policy(client_app_types=[legacy_type], controls=["block"])]))
    assert result["status"] == "pass", f"{legacy_type} should count as legacy"


def test_report_only_policy_does_not_count():
    """Report-only logs what it would have done and blocks nothing."""
    result = check_legacy_auth(Client([
        policy("Block legacy", state="enabledForReportingButNotEnforced",
               client_app_types=LEGACY_BLOCK, controls=["block"])]))

    assert result["status"] == "fail"
    assert result["points_earned"] == 0


def test_disabled_policy_does_not_count():
    result = check_legacy_auth(Client([
        policy("Block legacy", state="disabled",
               client_app_types=LEGACY_BLOCK, controls=["block"])]))
    assert result["status"] == "fail"


def test_browser_only_block_does_not_count():
    """Blocking browsers says nothing about legacy protocols."""
    result = check_legacy_auth(Client([
        policy("Block browser", client_app_types=["browser"], controls=["block"])]))
    assert result["status"] == "fail"


def test_mfa_requirement_on_legacy_is_not_a_block():
    """Legacy protocols can't do MFA; requiring it is not the same as blocking."""
    result = check_legacy_auth(Client([
        policy("Require MFA", client_app_types=LEGACY_BLOCK, controls=["mfa"])]))
    assert result["status"] == "fail"


def test_policy_with_no_grant_controls_does_not_crash():
    """Session-only policies have grantControls: null."""
    result = check_legacy_auth(Client([
        policy("Session only", client_app_types=LEGACY_BLOCK, controls=None)]))
    assert result["status"] == "fail"


def test_block_with_user_exclusions_warns_rather_than_passing():
    """An excluded account is exactly what an attacker would look for."""
    result = check_legacy_auth(Client([
        policy("Block legacy", client_app_types=LEGACY_BLOCK, controls=["block"],
               users={"includeUsers": ["All"], "excludeUsers": ["break-glass-id"],
                      "excludeGroups": [], "excludeRoles": []})]))

    assert result["status"] == "warn", "a block with carve-outs is not a full block"
    assert result["points_earned"] == 7
    assert any("excludes 1" in i for i in result["issues"])


def test_block_scoped_to_specific_users_warns():
    result = check_legacy_auth(Client([
        policy("Pilot block", client_app_types=LEGACY_BLOCK, controls=["block"],
               users={"includeUsers": ["user-1", "user-2"], "excludeUsers": [],
                      "excludeGroups": [], "excludeRoles": []})]))

    assert result["status"] == "warn"
    assert any("specific principal" in i for i in result["issues"])


def test_several_blocking_policies_are_all_listed():
    result = check_legacy_auth(Client([
        policy("Block A", client_app_types=LEGACY_BLOCK, controls=["block"]),
        policy("Block B", client_app_types=["all"], controls=["block"]),
    ]))
    assert result["details"]["blocking_policies"] == ["Block A", "Block B"]
    assert "2 policies" in result["summary"]


def test_unnamed_policy_does_not_render_as_none():
    p = policy(client_app_types=LEGACY_BLOCK, controls=["block"])
    p["displayName"] = None
    result = check_legacy_auth(Client([p]))
    assert "None" not in str(result["details"]["blocking_policies"])


def test_graph_failure_skips():
    result = check_legacy_auth(Client(GraphError("Insufficient permissions", status=403)))
    assert result["status"] == "skip"
    assert result["points_earned"] is None


# ----------------------------------------------------- policy inventory

def test_no_policies_at_all_is_a_failure():
    result = check_conditional_access(Client([]))
    assert result["status"] == "fail"
    assert result["points_earned"] == 0
    assert "No Conditional Access policies configured" in result["issues"]


def test_one_enabled_policy_scores_full():
    result = check_conditional_access(Client([policy("Require MFA", controls=["mfa"])]))
    assert result["status"] == "pass"
    assert result["points_earned"] == 15


def test_policies_all_report_only_warns_rather_than_passing():
    """Report-only enforces nothing, so this must not read as protected."""
    result = check_conditional_access(Client([
        policy("A", state="enabledForReportingButNotEnforced"),
        policy("B", state="enabledForReportingButNotEnforced"),
    ]))

    assert result["status"] == "warn"
    assert result["points_earned"] < 15
    assert result["details"]["report_only"] == 2
    assert result["details"]["enabled"] == 0


def test_state_counts_are_reported_accurately():
    result = check_conditional_access(Client([
        policy("A", state="enabled"),
        policy("B", state="disabled"),
        policy("C", state="enabledForReportingButNotEnforced"),
        policy("D", state="enabled"),
    ]))

    d = result["details"]
    assert (d["total"], d["enabled"], d["disabled"], d["report_only"]) == (4, 2, 1, 1)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
