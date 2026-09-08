"""Contract tests every check module must satisfy.

These run each category's run_all() against two hostile clients — one where
every Graph call fails, one where every call returns nothing — and assert the
results are still well-formed. That covers all 28 checks without needing a
tenant, and it is what makes the GraphError refactor verifiable: a check that
forgets to handle a failure shows up here rather than in production as a
500 in a background thread.
"""
import pytest

from app.services.graph_client import GraphError
import app.checks.conditional_access as ca
import app.checks.exchange as exchange
import app.checks.groups as groups
import app.checks.identity as identity
import app.checks.licensing as licensing
import app.checks.mail_security as mail_security
import app.checks.sharepoint as sharepoint
import app.checks.users as users

MODULES = {
    "identity": identity,
    "conditional_access": ca,
    "mail_security": mail_security,
    "licensing": licensing,
    "users": users,
    "sharepoint": sharepoint,
    "exchange": exchange,
    "groups": groups,
}

VALID_STATUSES = {"pass", "warn", "fail", "skip", "info"}
REQUIRED_KEYS = {"check_name", "display_name", "category", "status",
                 "points_earned", "points_possible", "summary", "issues"}


class FailingClient:
    """Every Graph call fails, as with an unconsented app registration."""

    def get_all(self, endpoint, params=None, beta=False):
        raise GraphError(f"Insufficient permissions ({endpoint})", status=403, endpoint=endpoint)

    def get_one(self, endpoint, params=None, beta=False):
        raise GraphError(f"Insufficient permissions ({endpoint})", status=403, endpoint=endpoint)

    def get_count(self, endpoint):
        return 0

    def get_report_csv(self, endpoint):
        raise GraphError(f"Reports.Read.All permission required ({endpoint})",
                         status=403, endpoint=endpoint)

    def batch_get(self, endpoints, beta=False):
        raise GraphError("Batch request failed: HTTP 403", status=403, endpoint="/$batch")


class EmptyClient:
    """Every call succeeds and returns nothing — a brand-new empty tenant."""

    def get_all(self, endpoint, params=None, beta=False):
        return []

    def get_one(self, endpoint, params=None, beta=False):
        return {}

    def get_count(self, endpoint):
        return 0

    def get_report_csv(self, endpoint):
        return []

    def batch_get(self, endpoints, beta=False):
        return {ep: None for ep in endpoints}


def flatten(results):
    out = []
    for r in results:
        out.extend(r) if isinstance(r, list) else out.append(r)
    return out


@pytest.mark.parametrize("name,module", sorted(MODULES.items()))
def test_all_calls_failing_yields_wellformed_skips(name, module):
    results = flatten(module.run_all(FailingClient()))

    assert results, f"{name}.run_all() returned nothing"
    for r in results:
        assert isinstance(r, dict), f"{name} returned a non-dict: {type(r)}"
        missing = REQUIRED_KEYS - set(r)
        assert not missing, f"{name}/{r.get('check_name')} missing keys: {missing}"
        assert r["status"] == "skip", \
            f"{name}/{r['check_name']} returned {r['status']!r} when every call failed"
        assert r["points_earned"] is None, \
            f"{name}/{r['check_name']} awarded points despite failing to run"
        assert r["summary"], f"{name}/{r['check_name']} skipped with no reason given"


@pytest.mark.parametrize("name,module", sorted(MODULES.items()))
def test_empty_tenant_does_not_crash(name, module):
    results = flatten(module.run_all(EmptyClient()))

    assert results, f"{name}.run_all() returned nothing"
    for r in results:
        assert isinstance(r, dict)
        assert r["status"] in VALID_STATUSES, \
            f"{name}/{r.get('check_name')} has invalid status {r['status']!r}"
        missing = REQUIRED_KEYS - set(r)
        assert not missing, f"{name}/{r.get('check_name')} missing keys: {missing}"


@pytest.mark.parametrize("name,module", sorted(MODULES.items()))
def test_scored_checks_never_exceed_their_weight(name, module):
    for r in flatten(module.run_all(EmptyClient())):
        earned, possible = r["points_earned"], r["points_possible"]
        if earned is not None and possible:
            assert 0 <= earned <= possible, \
                f"{name}/{r['check_name']} scored {earned}/{possible}"


@pytest.mark.parametrize("name,module", sorted(MODULES.items()))
def test_failure_does_not_shrink_the_check_count(name, module):
    """A tenant that denies everything must still report every check as skipped.

    Checks derived from a shared call — app permissions rides along with app
    credential expiry — used to vanish on failure, quietly making the audit look
    smaller than it is rather than showing the control was never measured.
    """
    failing = {r["check_name"] for r in flatten(module.run_all(FailingClient()))}
    working = {r["check_name"] for r in flatten(module.run_all(EmptyClient()))}

    missing = working - failing
    assert not missing, f"{name}: {sorted(missing)} disappear when Graph calls fail"


@pytest.mark.parametrize("name,module", sorted(MODULES.items()))
def test_category_is_reported_correctly(name, module):
    for r in flatten(module.run_all(EmptyClient())):
        assert r["category"] == name, \
            f"{r['check_name']} reports category {r['category']!r} but lives in {name}"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
