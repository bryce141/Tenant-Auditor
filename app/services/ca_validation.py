"""Prove the evaluation engine right against Microsoft, on the tenant's own policies.

This is the load-bearing idea of the whole simulator. Our engine can evaluate a
*draft* policy, which Microsoft's API cannot — but that is only worth anything
if the engine is right, and nothing about writing it carefully makes it right.

So: for every condition tuple in the sign-in corpus, evaluate the tenant's
**existing** policies twice — once through `ca_engine`, once through
`POST /identity/conditionalAccess/evaluate` — and diff the verdicts. The
agreement report that comes out is evidence, and it is a product feature rather
than a test fixture: it is the answer to "why should I believe your impact
numbers", and it is the strongest thing in the demo.

`analysisReasons` makes the report genuinely diagnostic. When Microsoft says a
policy doesn't apply it names the condition that decided it — `users`,
`devicePlatform`, `clientApps`, `location` — so a disagreement points straight
at the part of the engine that is wrong, rather than leaving a bare mismatch to
go hunting through.

## What is and isn't counted as disagreement

A policy our engine reports UNSUPPORTED is **not** a disagreement. It is a
declared gap, counted separately, and it is the honest state for a condition we
haven't implemented. Inflating the disagreement count with them would hide real
bugs among known gaps.

Microsoft has its own "can't tell": `analysisReasons` of `notEnoughInformation`.
Those aren't disagreements either — both sides are declining to answer, which is
agreement about uncertainty rather than a conflict.

## The second, independent check

`appliedConditionalAccessPolicies` on each sign-in records what the tenant
*actually did* at sign-in time. That is a stronger signal than any What If
evaluation, because it is production. `crosscheck_applied` compares our verdicts
against it.

It also detects something the evaluate diff cannot: if one tuple's sign-ins
disagree *with each other* about whether a policy applied, then some condition
that matters is missing from the tuple key — the aggregation is lossy and impact
numbers built on it will be wrong. That shows up as `ambiguous` below, and it is
a finding about the corpus rather than about the engine.

## Two reasons this check has a ceiling below 100%, both legitimate

**Configuration moves, sign-ins do not.** A policy created today did not exist
for yesterday's traffic; a named location added today changes what an untouched
policy does; a user made an admin today was not one when they signed in last
week. Entra evaluated those sign-ins under a configuration that is gone.
`skipped_config_changed` counts them, using policy timestamps, named location
timestamps, and membership changes from the directory audit log — the last
because a role assignment leaves the policy itself untouched, so nothing else
can detect it.

**A sign-in can touch more resources than it records.** `resourceId` names one
resource, but Entra evaluates Conditional Access against service dependencies
too, so a policy scoped to Exchange can apply to a sign-in the log files under
Microsoft Graph. Our engine reports those as not applying — and so does
Microsoft's What If endpoint, asked the same question. The disagreement is
between the What If model, which evaluates one resource, and production, which
does not. These are deliberately left visible as disagreements rather than
explained away: suppressing a mismatch because we have a story for it is how a
harness stops being evidence.
"""
import time
from collections import Counter
from dataclasses import dataclass, field

from app.services.ca_engine import evaluate
from app.services.graph_client import GraphError
from app.services.signin_corpus import _parse_dt

EVALUATE_ENDPOINT = "/identity/conditionalAccess/evaluate"

# appliedConditionalAccessPolicyResult values that mean the policy was evaluated
# and found to apply. reportOnly* are included: the policy applied, it simply
# wasn't enforced, which is exactly what our engine reports for report-only.
APPLIED_RESULTS = {"success", "failure", "reportonlysuccess",
                   "reportonlyfailure", "reportonlyinterrupted"}
NOT_APPLIED_RESULTS = {"notapplied", "reportonlynotapplied"}
# notEnabled means the policy was disabled, which our engine also calls
# not-applicable. unknown means Entra itself couldn't say.
DISABLED_RESULTS = {"notenabled"}
UNKNOWN_RESULTS = {"unknown", "unknownfuturevalue"}

# Microsoft's own "not enough information to decide".
MS_UNCERTAIN = "notenoughinformation"

MAX_THROTTLE_RETRIES = 5
DEFAULT_BACKOFF_SECONDS = 20


# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------

def build_evaluate_request(conditions, ip_address=None, applied_policies_only=False):
    """A signInIdentity / signInContext / signInConditions body from one tuple.

    Fields the sign-in didn't report are **omitted rather than defaulted**.
    That matters: signInConditions defaults `devicePlatform` and `clientAppType`
    to `all`, so sending a guess would make Microsoft evaluate a different
    sign-in than the one observed and manufacture a disagreement. Our engine
    reports UNSUPPORTED for those same tuples, so they are excluded from the
    comparison anyway — but only if we don't quietly invent a value here.
    """
    body = {
        "signInIdentity": {"@odata.type": "#microsoft.graph.userSignIn",
                           "userId": conditions.user_id},
        # The resource, matching what CA targets and what our engine compares
        # against. Sending the client appId here would ask Microsoft about a
        # different sign-in than the one observed.
        "signInContext": {"@odata.type": "#microsoft.graph.applicationContext",
                          "includeApplications": [conditions.resource_id]},
        "appliedPoliciesOnly": applied_policies_only,
    }

    sign_in_conditions = {}
    if conditions.device_platform:
        sign_in_conditions["devicePlatform"] = conditions.device_platform
    if conditions.client_app_type:
        sign_in_conditions["clientAppType"] = conditions.client_app_type
    if conditions.country:
        sign_in_conditions["country"] = conditions.country
    if ip_address:
        sign_in_conditions["ipAddress"] = ip_address
    if conditions.sign_in_risk_level:
        sign_in_conditions["signInRiskLevel"] = conditions.sign_in_risk_level
    if conditions.user_risk_level:
        sign_in_conditions["userRiskLevel"] = conditions.user_risk_level
    if conditions.is_compliant is not None:
        sign_in_conditions["deviceInfo"] = {"isCompliant": conditions.is_compliant}

    body["signInConditions"] = sign_in_conditions
    return body


def call_evaluate(client, body, sleep=time.sleep):
    """POST to the What If endpoint, backing off when Graph throttles.

    This is the high-volume path — one call per tuple — so 429 is expected
    rather than exceptional, and Retry-After is respected rather than guessed
    at, since guessing low on a throttled tenant just extends the throttle.
    """
    for attempt in range(MAX_THROTTLE_RETRIES):
        try:
            return client.post_one(EVALUATE_ENDPOINT, body)
        except GraphError as e:
            if e.status != 429 or attempt == MAX_THROTTLE_RETRIES - 1:
                raise
            wait = e.retry_after
            if wait is None:
                wait = DEFAULT_BACKOFF_SECONDS * (2 ** attempt)
            sleep(wait)
    raise GraphError("Throttled by Graph and out of retries",
                     status=429, endpoint=EVALUATE_ENDPOINT)


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------

@dataclass
class Disagreement:
    """One policy where our verdict and Microsoft's differ, and what each said."""
    policy_id: str
    policy_name: str
    ours: bool
    theirs: bool
    our_reason: str
    their_reason: str          # analysisReasons — the condition Microsoft blames
    conditions: dict
    sign_ins: int

    def as_dict(self):
        return {
            "policy_id": self.policy_id, "policy_name": self.policy_name,
            "ours": self.ours, "theirs": self.theirs,
            "our_reason": self.our_reason, "their_reason": self.their_reason,
            "conditions": self.conditions, "sign_ins": self.sign_ins,
        }


@dataclass
class AgreementReport:
    tuples_compared: int = 0
    sign_ins_covered: int = 0
    corpus_sign_ins: int = 0
    comparisons: int = 0
    agreements: int = 0
    disagreements: list = field(default_factory=list)

    # Our declared gaps, by condition. Not disagreements.
    unsupported: Counter = field(default_factory=Counter)
    # Microsoft declining to answer. Also not a disagreement.
    microsoft_uncertain: int = 0
    # Policies one side returned and the other didn't.
    missing_from_theirs: int = 0
    errors: list = field(default_factory=list)

    @property
    def agreement_rate(self):
        """Agreement over comparisons that both sides actually answered."""
        if not self.comparisons:
            return None
        return self.agreements / self.comparisons

    @property
    def coverage(self):
        """Share of the corpus's real sign-ins the compared tuples represent."""
        if not self.corpus_sign_ins:
            return 0.0
        return self.sign_ins_covered / self.corpus_sign_ins

    @property
    def perfect(self):
        return self.comparisons > 0 and not self.disagreements

    def summary(self):
        rate = self.agreement_rate
        return {
            "tuples_compared": self.tuples_compared,
            "sign_ins_covered": self.sign_ins_covered,
            "corpus_sign_ins": self.corpus_sign_ins,
            "coverage": round(self.coverage, 4),
            "comparisons": self.comparisons,
            "agreements": self.agreements,
            "disagreements": len(self.disagreements),
            "agreement_rate": None if rate is None else round(rate, 4),
            "unsupported": dict(self.unsupported),
            "microsoft_uncertain": self.microsoft_uncertain,
            "missing_from_theirs": self.missing_from_theirs,
            "errors": list(self.errors),
        }


def compare(our_evaluations, what_if_results, conditions, sign_ins, report):
    """Diff one tuple's verdicts into `report`."""
    theirs_by_id = {r.get("id"): r for r in what_if_results}

    for ours in our_evaluations:
        if ours.applies is None:
            for condition in (ours.unsupported_conditions or ("unspecified",)):
                report.unsupported[condition] += 1
            continue

        theirs = theirs_by_id.get(ours.policy_id)
        if theirs is None:
            report.missing_from_theirs += 1
            continue

        reason = str(theirs.get("analysisReasons") or "").lower()
        if reason == MS_UNCERTAIN:
            # Both sides declining to decide is agreement about uncertainty,
            # not a conflict.
            report.microsoft_uncertain += 1
            continue

        report.comparisons += 1
        if bool(theirs.get("policyApplies")) == bool(ours.applies):
            report.agreements += 1
        else:
            report.disagreements.append(Disagreement(
                policy_id=ours.policy_id,
                policy_name=ours.policy_name,
                ours=bool(ours.applies),
                theirs=bool(theirs.get("policyApplies")),
                our_reason=ours.reason,
                their_reason=theirs.get("analysisReasons") or "notSet",
                conditions=conditions.as_dict(),
                sign_ins=sign_ins,
            ))


def validate(client, corpus, policies, memberships, max_tuples=None,
             sleep=time.sleep, progress=None):
    """Run the whole corpus through both evaluators and diff them.

    Tuples are taken busiest-first, so a capped run covers as much real traffic
    as possible per call rather than an arbitrary slice.
    """
    report = AgreementReport(
        corpus_sign_ins=corpus.total_sign_ins)

    observations = sorted(corpus.observations, key=lambda o: o.sign_ins,
                          reverse=True)
    if max_tuples is not None:
        observations = observations[:max_tuples]

    for index, observation in enumerate(observations):
        conditions = observation.conditions
        membership = memberships.get(conditions.user_id) if memberships else None

        ours = [evaluate(p, conditions, membership) for p in policies]

        # One representative address. Deterministic so a rerun compares the
        # same thing; which address is chosen only matters once named-location
        # conditions are supported, and those are UNSUPPORTED today.
        ip = min(observation.ip_addresses) if observation.ip_addresses else None

        try:
            body = build_evaluate_request(conditions, ip_address=ip)
            response = call_evaluate(client, body, sleep=sleep)
        except GraphError as e:
            report.errors.append(f"{conditions.user_id}: {e}")
            continue

        compare(ours, (response or {}).get("value", []), conditions,
                observation.sign_ins, report)

        report.tuples_compared += 1
        report.sign_ins_covered += observation.sign_ins
        if progress:
            progress(index + 1, len(observations))

    return report


# ---------------------------------------------------------------------------
# Cross-check against what the tenant actually did
# ---------------------------------------------------------------------------

@dataclass
class CrossCheck:
    """Our verdicts against appliedConditionalAccessPolicies from real sign-ins."""
    comparisons: int = 0
    agreements: int = 0
    disagreements: list = field(default_factory=list)
    skipped_unsupported: int = 0
    skipped_unknown: int = 0
    # Sign-ins that predate the policy, or a named location it references.
    # Comparing today's configuration against yesterday's events is not a
    # disagreement about evaluation; it is a disagreement about when.
    skipped_config_changed: int = 0
    # Tuples whose own sign-ins disagree about whether a policy applied. A
    # finding about the tuple key, not about the engine: some condition that
    # matters isn't in it.
    ambiguous: list = field(default_factory=list)

    @property
    def agreement_rate(self):
        if not self.comparisons:
            return None
        return self.agreements / self.comparisons

    def summary(self):
        rate = self.agreement_rate
        return {
            "comparisons": self.comparisons,
            "agreements": self.agreements,
            "disagreements": len(self.disagreements),
            "agreement_rate": None if rate is None else round(rate, 4),
            "skipped_unsupported": self.skipped_unsupported,
            "skipped_unknown": self.skipped_unknown,
            "skipped_config_changed": self.skipped_config_changed,
            "ambiguous_tuples": len(self.ambiguous),
        }


def _observed_applied(results):
    """(applied, ambiguous) from the per-result counts on one tuple.

    None means nothing conclusive was recorded.
    """
    seen = {r.lower() for r in results}
    applied = bool(seen & APPLIED_RESULTS)
    not_applied = bool(seen & NOT_APPLIED_RESULTS)
    disabled = bool(seen & DISABLED_RESULTS)

    if applied and (not_applied or disabled):
        return None, True
    if applied:
        return True, False
    if not_applied or disabled:
        return False, False
    return None, False


# Directory audit activities that change whether a user is in a group or role,
# and therefore whether a membership-scoped policy applies to them.
MEMBERSHIP_ACTIVITIES = {
    "add member to role", "remove member from role",
    "add member to group", "remove member from group",
    "add eligible member to role", "remove eligible member from role",
}


def fetch_membership_changes(client, days=30):
    """{user_id: when their group or role membership last changed}.

    A policy scoped to a role applies to whoever held it *at sign-in time*. Make
    someone an admin today and every sign-in they made yesterday will disagree
    with our evaluation — correctly, because they were not an admin then. The
    policy itself is untouched, so its own timestamp cannot detect this; only
    the audit log can.
    """
    from app.utils import utcnow
    from datetime import timedelta

    since = (utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        records = client.get_all(
            "/auditLogs/directoryAudits",
            params={"$filter": f"activityDateTime ge {since}", "$top": 999})
    except GraphError:
        # Without it the cross-check simply behaves as it did before: it may
        # report drift as disagreement, which is wrong but not silently wrong.
        return {}

    changes = {}
    for record in records:
        activity = (record.get("activityDisplayName") or "").strip().lower()
        if activity not in MEMBERSHIP_ACTIVITIES:
            continue
        when = _parse_dt(record.get("activityDateTime"))
        if not when:
            continue
        for target in record.get("targetResources") or []:
            target_id = target.get("id")
            if not target_id:
                continue
            if target_id not in changes or when > changes[target_id]:
                changes[target_id] = when
    return changes


def _depends_on_membership(policy):
    """Whether this policy's answer can change when a user's membership does."""
    users = ((policy.get("conditions") or {}).get("users") or {})
    if users.get("includeGroups") or users.get("excludeGroups"):
        return True
    if users.get("includeRoles") or users.get("excludeRoles"):
        return True
    tokens = {str(v).lower() for v in
              (users.get("includeUsers") or []) + (users.get("excludeUsers") or [])}
    return "guestsorexternalusers" in tokens


def _effective_since(policy, locations_by_id):
    """When this policy last became the thing we are evaluating.

    The later of the policy's own modification and the creation or modification
    of any named location it references — changing a location silently changes
    what the policy does, without touching the policy.

    Returns None when nothing is datable, in which case the comparison proceeds
    as before rather than being skipped on a guess.
    """
    stamps = []
    for key in ("modifiedDateTime", "createdDateTime"):
        parsed = _parse_dt(policy.get(key))
        if parsed:
            stamps.append(parsed)

    conditions = policy.get("conditions") or {}
    locations = conditions.get("locations") or {}
    referenced = list(locations.get("includeLocations") or [])
    referenced += list(locations.get("excludeLocations") or [])
    for ref in referenced:
        key = str(ref).lower()
        if key in ("all", "alltrusted"):
            # AllTrusted depends on every trusted location in the tenant, so
            # any of them appearing changes the answer.
            for loc in locations_by_id.values():
                if loc.get("isTrusted"):
                    stamps += [d for d in (_parse_dt(loc.get("modifiedDateTime")),
                                           _parse_dt(loc.get("createdDateTime"))) if d]
            continue
        loc = locations_by_id.get(key)
        if loc:
            stamps += [d for d in (_parse_dt(loc.get("modifiedDateTime")),
                                   _parse_dt(loc.get("createdDateTime"))) if d]

    return max(stamps) if stamps else None


def crosscheck_applied(corpus, policies, memberships, named_locations=(),
                       membership_changes=None):
    """Compare engine verdicts against what really happened at sign-in time.

    Pure — no Graph calls. The data was already captured into the corpus by
    `signin_corpus`, so this runs on a tenant that would throttle a full
    evaluate sweep, and on a corpus saved from an earlier run.
    """
    check = CrossCheck()
    by_id = {p.get("id"): p for p in policies}
    locations_by_id = {str(loc.get("id")).lower(): loc
                       for loc in (named_locations or []) if loc.get("id")}
    effective = {p.get("id"): _effective_since(p, locations_by_id) for p in policies}
    membership_changes = membership_changes or {}
    membership_scoped = {p.get("id"): _depends_on_membership(p) for p in policies}

    for observation in corpus.observations:
        conditions = observation.conditions
        membership = memberships.get(conditions.user_id) if memberships else None

        for policy_id, results in observation.applied_policies.items():
            policy = by_id.get(policy_id)
            if policy is None:
                continue  # policy deleted or created since the sign-in

            # A sign-in that predates the policy — or a named location it
            # depends on — was evaluated by Entra under a different
            # configuration than the one being checked. Counting that as a
            # disagreement blames the engine for the passage of time.
            since = effective.get(policy_id)
            if membership_scoped.get(policy_id):
                # The user's own group or role membership may have moved since.
                changed = membership_changes.get(conditions.user_id)
                if changed and (since is None or changed > since):
                    since = changed
            if since and observation.last_seen and observation.last_seen < since:
                check.skipped_config_changed += 1
                continue

            observed, ambiguous = _observed_applied(results)
            if ambiguous:
                check.ambiguous.append({
                    "policy_id": policy_id,
                    "policy_name": policy.get("displayName"),
                    "results": dict(results),
                    "conditions": conditions.as_dict(),
                })
                continue
            if observed is None:
                check.skipped_unknown += 1
                continue

            ours = evaluate(policy, conditions, membership)
            if ours.applies is None:
                check.skipped_unsupported += 1
                continue

            check.comparisons += 1
            if ours.applies == observed:
                check.agreements += 1
            else:
                check.disagreements.append(Disagreement(
                    policy_id=policy_id,
                    policy_name=policy.get("displayName") or "(unnamed policy)",
                    ours=bool(ours.applies),
                    theirs=observed,
                    our_reason=ours.reason,
                    their_reason=f"sign-in log recorded {dict(results)}",
                    conditions=conditions.as_dict(),
                    sign_ins=observation.sign_ins,
                ))

    return check
