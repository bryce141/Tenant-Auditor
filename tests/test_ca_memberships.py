"""Tests for CA membership resolution.

Two of these exist because live Graph disagreed with the first implementation:
`userType` is absent from what `directoryObjects/getByIds` returns, and an empty
MembershipCache was falsy so nothing was ever cached. Both are guarded below.
"""
import pytest

from app.services.ca_memberships import (
    Membership,
    MembershipCache,
    _split_memberships,
    resolve_for_corpus,
    resolve_memberships,
)
from app.services.signin_corpus import reduce_to_tuples

GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"
GLOBAL_ADMIN_OBJECT = "f8512e77-ffb7-4951-8e1b-234806bc8a3f"


def group(object_id, name="Engineering"):
    return {"@odata.type": "#microsoft.graph.group", "id": object_id,
            "displayName": name}


def directory_role(object_id=GLOBAL_ADMIN_OBJECT,
                   template_id=GLOBAL_ADMIN_TEMPLATE,
                   name="Global Administrator"):
    return {"@odata.type": "#microsoft.graph.directoryRole", "id": object_id,
            "roleTemplateId": template_id, "displayName": name}


class FakeClient:
    """Answers batch_get from a map of endpoint -> body, recording what was asked."""

    def __init__(self, bodies=None, pages=None):
        self.bodies = bodies or {}
        self.pages = pages or {}
        self.batched = []
        self.followed = []

    def batch_get(self, endpoints, beta=False):
        self.batched.extend(endpoints)
        return {ep: self.bodies.get(ep) for ep in endpoints}

    def get_one(self, endpoint, params=None, beta=False):
        self.followed.append(endpoint)
        return self.pages.get(endpoint)

    def post_one(self, endpoint, payload, beta=False):
        raise AssertionError(
            "getByIds omits userType and takes no $select — do not use it here")


def bodies_for(user_id, member_of=(), user_type="Member", next_link=None):
    body = {"value": list(member_of)}
    if next_link:
        body["@odata.nextLink"] = next_link
    return {
        f"/users/{user_id}/transitiveMemberOf?$top=999": body,
        f"/users/{user_id}?$select=id,userType": {"id": user_id,
                                                  "userType": user_type},
    }


# ---------------------------------------------------------------------------
# Partitioning what transitiveMemberOf returns
# ---------------------------------------------------------------------------

def test_groups_and_roles_are_separated_by_odata_type():
    groups, roles, templates = _split_memberships(
        [group("g1"), group("g2"), directory_role()])
    assert groups == {"g1", "g2"}
    assert roles == {GLOBAL_ADMIN_OBJECT}
    assert templates == {GLOBAL_ADMIN_TEMPLATE}


def test_administrative_units_are_not_counted_as_groups():
    # transitiveMemberOf returns these too. CA policies don't target them, and
    # counting one as a group would make a group-scoped policy appear to apply.
    groups, roles, templates = _split_memberships([
        {"@odata.type": "#microsoft.graph.administrativeUnit", "id": "au1"},
        group("g1"),
    ])
    assert groups == {"g1"}
    assert roles == set() and templates == set()


def test_role_object_id_and_template_id_are_different_and_both_kept():
    # The directoryRole object id is not the roleTemplateId, and the
    # conditionalAccessUsers reference says only "Role IDs" without saying
    # which one policies carry. Keeping both removes the guess.
    m = Membership(user_id="u1", role_ids=frozenset({GLOBAL_ADMIN_OBJECT}),
                   role_template_ids=frozenset({GLOBAL_ADMIN_TEMPLATE}))
    assert GLOBAL_ADMIN_OBJECT != GLOBAL_ADMIN_TEMPLATE
    assert m.in_role(GLOBAL_ADMIN_TEMPLATE)
    assert m.in_role(GLOBAL_ADMIN_OBJECT)
    assert not m.in_role("some-other-role")


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

def test_resolves_groups_roles_and_user_type():
    client = FakeClient(bodies_for("u1", [group("g1"), directory_role()]))
    result = resolve_memberships(client, ["u1"])
    m = result.get("u1")
    assert m.group_ids == {"g1"}
    assert m.role_template_ids == {GLOBAL_ADMIN_TEMPLATE}
    assert m.user_type == "Member"
    assert m.resolved is True


def test_uses_transitive_member_of_not_direct():
    # CA evaluates nested group membership. Resolving only direct membership
    # would report a policy as breaking nobody when it breaks users who are
    # members through a nested group.
    client = FakeClient(bodies_for("u1"))
    resolve_memberships(client, ["u1"])
    assert any("transitiveMemberOf" in ep for ep in client.batched)
    assert not any(ep.endswith("/memberOf") for ep in client.batched)


def test_user_type_is_selected_explicitly():
    # It is not in the default property set, so an unqualified /users/{id}
    # returns no userType at all and every user silently reads as non-guest.
    client = FakeClient(bodies_for("u1"))
    resolve_memberships(client, ["u1"])
    assert "/users/u1?$select=id,userType" in client.batched


def test_guest_is_detected_from_user_type():
    client = FakeClient(bodies_for("u1", user_type="Guest"))
    assert resolve_memberships(client, ["u1"]).get("u1").is_guest is True


def test_guest_is_not_inferred_from_the_upn():
    # The account this was first tested against has '#EXT#' in its UPN and a
    # userType of 'Member'. Inferring from the UPN would have been wrong.
    client = FakeClient(bodies_for("u1", user_type="Member"))
    assert resolve_memberships(client, ["u1"]).get("u1").is_guest is False


def test_unreadable_user_is_unresolved_not_memberless():
    # A user deleted inside the 30-day sign-in window is the ordinary case.
    # Reading that as 'belongs to no groups' would make every group-targeted
    # policy look inapplicable to them — a false 'no impact'.
    client = FakeClient({
        "/users/gone/transitiveMemberOf?$top=999": None,
        "/users/gone?$select=id,userType": None,
    })
    m = resolve_memberships(client, ["gone"]).get("gone")
    assert m.resolved is False
    assert m.group_ids == frozenset()
    assert "deleted" in m.reason


def test_unresolved_users_are_listed():
    client = FakeClient({
        **bodies_for("u1", [group("g1")]),
        "/users/gone/transitiveMemberOf?$top=999": None,
        "/users/gone?$select=id,userType": None,
    })
    result = resolve_memberships(client, ["u1", "gone"])
    assert [m.user_id for m in result.unresolved] == ["gone"]
    assert result.summary() == {"users": 2, "resolved": 1, "unresolved": 1,
                                "guests": 0, "distinct_groups": 1,
                                "distinct_roles": 0}


def test_paged_membership_is_followed_not_truncated():
    # A user in more than 999 groups pages. Dropping the overflow would lose
    # real memberships and under-report impact.
    next_link = "https://graph.microsoft.com/v1.0/users/u1/transitiveMemberOf?$skiptoken=x"
    client = FakeClient(
        bodies_for("u1", [group("g1")], next_link=next_link),
        pages={next_link: {"value": [group("g2")]}},
    )
    m = resolve_memberships(client, ["u1"]).get("u1")
    assert m.group_ids == {"g1", "g2"}
    assert client.followed == [next_link]


def test_duplicate_user_ids_are_resolved_once():
    client = FakeClient(bodies_for("u1"))
    resolve_memberships(client, ["u1", "u1", "u1"])
    assert len([ep for ep in client.batched if "transitiveMemberOf" in ep]) == 1


def test_empty_input_makes_no_requests():
    client = FakeClient()
    assert resolve_memberships(client, []).by_user == {}
    assert client.batched == []


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------

def test_an_empty_cache_is_truthy():
    # __len__ made a fresh cache falsy, so `if cache: cache.put(...)` never
    # fired on the first pass and nothing was ever stored — silently, forever.
    assert bool(MembershipCache("tenant-1")) is True
    assert len(MembershipCache("tenant-1")) == 0


def test_resolution_populates_the_cache():
    cache = MembershipCache("tenant-1")
    client = FakeClient(bodies_for("u1", [group("g1")]))
    resolve_memberships(client, ["u1"], cache=cache)
    assert len(cache) == 1
    assert cache.get("u1").group_ids == {"g1"}


def test_a_cached_user_costs_no_graph_calls():
    cache = MembershipCache("tenant-1")
    client = FakeClient(bodies_for("u1", [group("g1")]))
    resolve_memberships(client, ["u1"], cache=cache)

    class Boom:
        def batch_get(self, *a, **k):
            raise AssertionError("resolved a cached user against Graph")

        def get_one(self, *a, **k):
            raise AssertionError("resolved a cached user against Graph")

    again = resolve_memberships(Boom(), ["u1"], cache=cache)
    assert again.get("u1").group_ids == {"g1"}


def test_unresolved_users_are_cached_too():
    # Otherwise a deleted user is re-requested once per call for the life of
    # the run, and always fails.
    cache = MembershipCache("tenant-1")
    client = FakeClient({"/users/gone/transitiveMemberOf?$top=999": None,
                         "/users/gone?$select=id,userType": None})
    resolve_memberships(client, ["gone"], cache=cache)
    assert cache.get("gone").resolved is False


def test_cache_records_its_tenant():
    # Group and role ids are tenant-local; serving one tenant's membership for
    # another would be a confident wrong answer.
    assert MembershipCache("tenant-1").tenant_id == "tenant-1"


# ---------------------------------------------------------------------------
# Corpus integration
# ---------------------------------------------------------------------------

def test_resolves_every_distinct_user_in_a_corpus():
    from tests.test_signin_corpus import signin

    corpus = reduce_to_tuples([
        signin(userId="u1"),
        signin(userId="u1", location={"countryOrRegion": "GB"}),
        signin(userId="u2"),
    ])
    client = FakeClient({**bodies_for("u1", [group("g1")]),
                         **bodies_for("u2")})
    result = resolve_for_corpus(client, corpus)
    assert set(result.by_user) == {"u1", "u2"}


def test_membership_is_json_serialisable():
    import json

    client = FakeClient(bodies_for("u1", [group("g1"), directory_role()]))
    m = resolve_memberships(client, ["u1"]).get("u1")
    json.dumps(m.as_dict())


@pytest.mark.parametrize("field_name", ["group_ids", "role_ids",
                                        "role_template_ids"])
def test_membership_collections_are_frozen(field_name):
    # Memberships are cached and shared between callers; a mutable default
    # would let one caller's edit leak into another's answer.
    assert isinstance(getattr(Membership(user_id="u1"), field_name), frozenset)


def test_membership_cannot_be_mutated_after_caching():
    with pytest.raises(AttributeError):
        Membership(user_id="u1").user_id = "u2"
