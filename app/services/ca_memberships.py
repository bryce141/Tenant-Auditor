"""Resolve the directory facts a CA policy targets users by.

The sign-in log gives a `userId` and nothing else about who that user is. A
Conditional Access policy targets users by group, by directory role, and by
whether they are a guest — none of which appear on a sign-in record. This module
fills that gap once per distinct user and caches it, so the evaluation engine
can stay a pure function over (policy, tuple, membership).

## Transitive, not direct

Group membership is resolved through `transitiveMemberOf`, which flattens nested
groups. CA evaluates nested membership, so resolving only direct membership
would quietly under-report: a user in "All Staff" via "Engineering" would look
untargeted by a policy scoped to "All Staff", and the impact report would say a
policy breaks nothing when it breaks them.

## Roles are identified two ways and the docs don't say which one policies use

`transitiveMemberOf` returns a directoryRole with both an object `id` and a
`roleTemplateId`, and those are different GUIDs. The conditionalAccessUsers
reference calls `includeRoles`/`excludeRoles` only "Role IDs" without saying
which. Rather than guess — and silently never match role-targeted policies if
the guess is wrong — both sets are kept and `Membership.in_role()` accepts
either. It costs nothing and removes the question.

Note that `transitiveMemberOf` reports **active** role assignments only. A user
who is PIM-eligible for a role but hasn't activated it is not in that role, which
is also how CA sees them at sign-in time, so this is correct rather than merely
convenient.

## An unresolved user is not a user with no groups

A sign-in log covers 30 days and users get deleted inside that window, so some
`userId` values no longer resolve. Treating that as "member of nothing" would
make every group-targeted policy look inapplicable to them — a false "no
impact", which is the failure this whole tool exists to avoid. Such users are
marked `resolved=False` and the engine is expected to return UNSUPPORTED for
them rather than an answer.
"""
from dataclasses import dataclass, field

# Graph caps a directory object collection page at 999. Asking for the maximum
# means the overflow path below is exercised only by genuinely extreme users.
PAGE_SIZE = 999


@dataclass(frozen=True)
class Membership:
    """What a CA policy needs to know about a user, beyond their id."""
    user_id: str
    group_ids: frozenset = frozenset()
    role_ids: frozenset = frozenset()            # directoryRole object ids
    role_template_ids: frozenset = frozenset()   # roleTemplateId values
    user_type: str = None                        # "Member" | "Guest" | None
    resolved: bool = True
    reason: str = None                           # why not, when resolved is False

    @property
    def is_guest(self):
        return (self.user_type or "").lower() == "guest"

    def in_group(self, group_id):
        return group_id in self.group_ids

    def in_role(self, role_ref):
        """True if `role_ref` names a role this user holds, by either identifier."""
        return role_ref in self.role_ids or role_ref in self.role_template_ids

    def as_dict(self):
        return {
            "user_id": self.user_id,
            "group_ids": sorted(self.group_ids),
            "role_ids": sorted(self.role_ids),
            "role_template_ids": sorted(self.role_template_ids),
            "user_type": self.user_type,
            "resolved": self.resolved,
            "reason": self.reason,
        }


@dataclass
class MembershipSet:
    """Resolved memberships for a set of users, plus what couldn't be resolved."""
    by_user: dict = field(default_factory=dict)

    def get(self, user_id):
        return self.by_user.get(user_id)

    @property
    def unresolved(self):
        return [m for m in self.by_user.values() if not m.resolved]

    def summary(self):
        groups = {g for m in self.by_user.values() for g in m.group_ids}
        roles = {r for m in self.by_user.values() for r in m.role_template_ids}
        return {
            "users": len(self.by_user),
            "resolved": sum(1 for m in self.by_user.values() if m.resolved),
            "unresolved": len(self.unresolved),
            "guests": sum(1 for m in self.by_user.values() if m.is_guest),
            "distinct_groups": len(groups),
            "distinct_roles": len(roles),
        }


class MembershipCache:
    """Per-tenant memo of resolved users.

    Scoped to a tenant id because group and role ids are tenant-local: serving
    one tenant's membership for another would silently produce a confident wrong
    answer. Deliberately in-memory and per-run — directory membership changes,
    and a stale cache would simulate against a directory that no longer exists.
    """

    def __init__(self, tenant_id):
        self.tenant_id = tenant_id
        self._by_user = {}

    def get(self, user_id):
        return self._by_user.get(user_id)

    def put(self, membership):
        self._by_user[membership.user_id] = membership

    def known(self, user_ids):
        return {uid for uid in user_ids if uid in self._by_user}

    def __len__(self):
        return len(self._by_user)

    def __bool__(self):
        """A cache is a cache even when empty.

        Without this, `__len__` makes a fresh cache falsy, and the natural
        `if cache: cache.put(...)` guard never fires on the first pass — so
        nothing is ever stored and the cache stays empty forever, silently.
        Call sites use `is not None` as well; this is the belt to that braces.
        """
        return True


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

def _split_memberships(objects):
    """Partition a transitiveMemberOf collection into groups and roles."""
    group_ids, role_ids, role_template_ids = set(), set(), set()
    for obj in objects:
        odata_type = (obj.get("@odata.type") or "").lower()
        object_id = obj.get("id")
        if odata_type.endswith("group"):
            if object_id:
                group_ids.add(object_id)
        elif odata_type.endswith("directoryrole"):
            if object_id:
                role_ids.add(object_id)
            template_id = obj.get("roleTemplateId")
            if template_id:
                role_template_ids.add(template_id)
        # Administrative units and other directory objects also appear here.
        # CA policies don't target them, so they are ignored rather than
        # miscounted as groups.
    return group_ids, role_ids, role_template_ids


def resolve_memberships(client, user_ids, cache=None):
    """Resolve group and role membership for each user id. Returns a MembershipSet.

    Batched 20 requests per round trip, because `transitiveMemberOf` has no bulk
    form — the same reason mailboxSettings is batched in GraphClient. The user
    lookup rides in the same batch rather than in a second pass.

    `userType` has to be asked for explicitly. `directoryObjects/getByIds` looks
    like the efficient way to fetch many users at once, but it returns only the
    default property set — **userType is not in it** — and being a POST action it
    takes no `$select`, so it cannot be made to return it. Do not switch back.

    Nor can guest status be inferred from the user principal name: the account
    this was first tested against has `#EXT#` in its UPN and a `userType` of
    `Member`.
    """
    wanted = [uid for uid in dict.fromkeys(user_ids) if uid]
    result = MembershipSet()

    outstanding = []
    for user_id in wanted:
        cached = cache.get(user_id) if cache is not None else None
        if cached is not None:
            result.by_user[user_id] = cached
        else:
            outstanding.append(user_id)

    if not outstanding:
        return result

    endpoints = {uid: f"/users/{uid}/transitiveMemberOf?$top={PAGE_SIZE}"
                 for uid in outstanding}
    user_endpoints = {uid: f"/users/{uid}?$select=id,userType"
                      for uid in outstanding}
    bodies = client.batch_get(list(endpoints.values())
                              + list(user_endpoints.values()))

    for user_id in outstanding:
        user_body = bodies.get(user_endpoints[user_id]) or {}
        user_type = user_body.get("userType")
        body = bodies.get(endpoints[user_id])
        if body is None:
            # The per-request failure batch_get reports as None. The usual cause
            # is a user deleted since the sign-in, which is expected on a 30-day
            # window and must not read as "belongs to no groups".
            membership = Membership(user_id=user_id, resolved=False,
                                    user_type=user_type,
                                    reason="user could not be read — deleted, or "
                                           "the directory refused the request")
            result.by_user[user_id] = membership
            if cache is not None:
                cache.put(membership)
            continue

        objects = list(body.get("value", []))

        # A user in more than 999 groups pages. Rare, but truncating here would
        # drop real memberships and under-report impact, so the overflow is
        # followed rather than ignored.
        next_link = body.get("@odata.nextLink")
        while next_link:
            page = client.get_one(next_link) or {}
            objects.extend(page.get("value", []))
            next_link = page.get("@odata.nextLink")

        group_ids, role_ids, role_template_ids = _split_memberships(objects)
        membership = Membership(
            user_id=user_id,
            group_ids=frozenset(group_ids),
            role_ids=frozenset(role_ids),
            role_template_ids=frozenset(role_template_ids),
            user_type=user_type,
            resolved=True,
        )
        result.by_user[user_id] = membership
        if cache is not None:
            cache.put(membership)

    return result


def resolve_for_corpus(client, corpus, cache=None):
    """Resolve every distinct user appearing in a sign-in corpus."""
    user_ids = {o.conditions.user_id for o in corpus.observations
                if o.conditions.user_id}
    return resolve_memberships(client, user_ids, cache=cache)
