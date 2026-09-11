"""The expensive half of a simulation, built once and reused.

Everything a simulation needs except the draft — the sign-in corpus, resolved
memberships, and the tenant's existing policies — depends only on the tenant and
the window. Rebuilding it per draft would make the builder unusable: a corpus
costs a sign-in log pull, a service principal enumeration, a named location
fetch, and one batched membership lookup per distinct user.

So it is built once and cached, and composing a policy becomes instant. That is
also the interaction the tool is for: the point is to try a condition, look at
who breaks, adjust, and look again.

The cache is a module-level dict, which is why gunicorn runs `--workers 1
--threads 4` — a second worker process would get its own copy and a rebuild
would appear to do nothing. Same constraint, and the same reason, as the run
progress dict in `report_runner`.

Entries carry the age of the data rather than expiring on a timer. A corpus an
hour old is still a perfectly good answer to "what would this break", and
silently rebuilding underneath someone mid-edit would be worse than showing
them how old it is and letting them decide.
"""
import threading

from app.services.ca_app_groups import AppGroupResolver, fetch_service_principals
from app.services.ca_locations import LocationResolver, fetch_named_locations
from app.services.ca_memberships import MembershipCache, resolve_for_corpus
from app.services.graph_client import GraphError
from app.services.signin_corpus import fetch_signins, reduce_to_tuples
from app.utils import utcnow

_workspaces = {}
_lock = threading.Lock()


class Workspace:
    """A tenant's observed traffic, ready to evaluate drafts against."""

    def __init__(self, tenant_id, days, corpus, memberships, policies,
                 named_locations, app_group_coverage):
        self.tenant_id = tenant_id
        self.days = days
        self.corpus = corpus
        self.memberships = memberships
        self.policies = policies
        self.named_locations = named_locations
        self.app_group_coverage = app_group_coverage
        self.built_at = utcnow()

    @property
    def age_minutes(self):
        return int((utcnow() - self.built_at).total_seconds() // 60)

    def summary(self):
        corpus = self.corpus.summary()
        return {
            "tenant_id": self.tenant_id,
            "days": self.days,
            "built_at": self.built_at.isoformat(),
            "age_minutes": self.age_minutes,
            "sign_ins": corpus["sign_ins"],
            "tuples": corpus["tuples"],
            "distinct_users": corpus["distinct_users"],
            "reduction_ratio": corpus["reduction_ratio"],
            "truncated": corpus["truncated"],
            "unmapped": corpus["unmapped"],
            "policies": len(self.policies),
            "named_locations": len(self.named_locations),
            "unresolved_users": len(self.memberships.unresolved),
        }


def build(client, tenant_id, days=30, max_records=None):
    """Pull everything a simulation needs. Raises GraphError on a hard failure."""
    policies = client.get_all("/identity/conditionalAccess/policies")

    # Neither resolver is fatal: without them the engine reports the matching
    # conditions as unevaluable, which is a worse answer but an honest one.
    try:
        named_locations = fetch_named_locations(client)
        locations = LocationResolver(named_locations)
    except GraphError:
        named_locations, locations = [], None

    try:
        app_groups = AppGroupResolver(fetch_service_principals(client))
    except GraphError:
        app_groups = None

    signins, truncated = fetch_signins(client, days=days, max_records=max_records)
    corpus = reduce_to_tuples(signins, window_days=days, truncated=truncated,
                              locations=locations, app_groups=app_groups)
    memberships = resolve_for_corpus(client, corpus,
                                     cache=MembershipCache(tenant_id))

    return Workspace(tenant_id=tenant_id, days=days, corpus=corpus,
                     memberships=memberships, policies=policies,
                     named_locations=named_locations,
                     app_group_coverage=app_groups.coverage if app_groups else (0, 0))


def get(tenant_id, days=None):
    """The cached workspace for a tenant, or None. Window must match if given."""
    with _lock:
        workspace = _workspaces.get(tenant_id)
    if workspace is None:
        return None
    if days is not None and workspace.days != days:
        return None
    return workspace


def put(workspace):
    with _lock:
        _workspaces[workspace.tenant_id] = workspace
    return workspace


def clear(tenant_id=None):
    with _lock:
        if tenant_id is None:
            _workspaces.clear()
        else:
            _workspaces.pop(tenant_id, None)


def get_or_build(client, tenant_id, days=30, force=False, max_records=None):
    if not force:
        cached = get(tenant_id, days)
        if cached is not None:
            return cached
    return put(build(client, tenant_id, days=days, max_records=max_records))
