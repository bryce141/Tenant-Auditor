"""What a draft policy would have done to real traffic.

This is the product. Everything else — the corpus, the membership resolution,
the engine, the agreement harness — exists so that the numbers here can be
believed.

## Impact is a delta, not an absolute

A draft that requires MFA for everyone does not "affect 400 sign-ins" if an
existing policy already required MFA for those same sign-ins. Those users
notice nothing. What they notice is a control they were not already subject to,
so every figure here is computed by evaluating the tenant's policies twice —
once as they stand, once with the draft added — and reporting the difference.

Reporting the absolute instead would inflate every number, and would do it in
the direction that flatters the tool, which is the direction to be most
suspicious of.

## Unevaluable traffic is quarantined, not assumed harmless

When the engine cannot evaluate the draft against a tuple, those sign-ins go in
their own bucket and are excluded from the impact figures rather than counted
as unaffected. A tuple we could not evaluate might be the one that breaks the
CEO. `Impact.complete` is False whenever that bucket is non-empty, and every
surface that renders these numbers has to say so.

## Aggregates first

Lead with "417 sign-ins across 38 users". The per-user detail is there to
answer "which ones", once someone has decided the total matters.
"""
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from app.services.ca_engine import ENABLED, combine, evaluate, evaluate_all


@dataclass
class AffectedUser:
    user_id: str
    user_principal_name: str = None
    sign_ins: int = 0
    blocked: bool = False
    controls: tuple = ()
    reason: str = ""

    def as_dict(self):
        return {
            "user_id": self.user_id,
            "user_principal_name": self.user_principal_name,
            "sign_ins": self.sign_ins,
            "blocked": self.blocked,
            "controls": list(self.controls),
            "reason": self.reason,
        }


@dataclass
class Impact:
    """What the draft would have done, over the window the corpus covers."""
    policy_name: str = "(draft policy)"
    declared_state: str = ENABLED
    window_days: int = 0
    corpus_sign_ins: int = 0
    corpus_users: int = 0

    # Distinct sign-ins the draft would change anything about. Accumulated once
    # per tuple, never by summing the per-control counts: a sign-in that newly
    # needs both MFA and a compliant device is one affected sign-in, not two,
    # and summing produced totals larger than the corpus itself.
    changed_sign_ins: int = 0
    changed_users: set = field(default_factory=set)

    # Sign-ins the draft would newly stop outright.
    blocked_sign_ins: int = 0
    blocked_users: set = field(default_factory=set)

    # control -> {"sign_ins": n, "users": set}, counting only controls the
    # sign-in was not already subject to.
    new_controls: dict = field(default_factory=dict)

    # Sign-ins where the draft applies but imposes nothing new.
    unchanged_sign_ins: int = 0

    # Traffic the engine could not evaluate the draft against.
    unsupported_sign_ins: int = 0
    unsupported_users: set = field(default_factory=set)
    unsupported_reasons: Counter = field(default_factory=Counter)

    by_resource: dict = field(default_factory=lambda: defaultdict(int))
    by_platform: dict = field(default_factory=lambda: defaultdict(int))
    affected: list = field(default_factory=list)

    @property
    def affected_sign_ins(self):
        return self.changed_sign_ins

    @property
    def affected_users(self):
        return self.changed_users

    @property
    def complete(self):
        """False when some traffic could not be evaluated, so totals are floors."""
        return self.unsupported_sign_ins == 0

    @property
    def enforces(self):
        """A draft left in report-only or disabled would change nothing."""
        return self.declared_state == ENABLED

    def headline(self):
        sign_ins = self.affected_sign_ins
        users = len(self.affected_users)
        if not sign_ins:
            return "No sign-ins in the window would be affected"
        return (f"{sign_ins:,} sign-in{'s' if sign_ins != 1 else ''} "
                f"across {users:,} user{'s' if users != 1 else ''} would be affected")

    def summary(self):
        return {
            "policy_name": self.policy_name,
            "declared_state": self.declared_state,
            "enforces": self.enforces,
            "headline": self.headline(),
            "window_days": self.window_days,
            "corpus_sign_ins": self.corpus_sign_ins,
            "corpus_users": self.corpus_users,
            "affected_sign_ins": self.affected_sign_ins,
            "affected_users": len(self.affected_users),
            "blocked_sign_ins": self.blocked_sign_ins,
            "blocked_users": len(self.blocked_users),
            "new_controls": {name: {"sign_ins": c["sign_ins"],
                                    "users": len(c["users"])}
                             for name, c in sorted(self.new_controls.items())},
            "unchanged_sign_ins": self.unchanged_sign_ins,
            "unsupported_sign_ins": self.unsupported_sign_ins,
            "unsupported_users": len(self.unsupported_users),
            "unsupported_reasons": dict(self.unsupported_reasons),
            "complete": self.complete,
            "by_resource": dict(sorted(self.by_resource.items(),
                                       key=lambda kv: -kv[1])),
            "by_platform": dict(sorted(self.by_platform.items(),
                                       key=lambda kv: -kv[1])),
            "affected": [u.as_dict() for u in
                         sorted(self.affected, key=lambda u: -u.sign_ins)],
        }


def _as_enabled(policy):
    """The draft as it would behave once switched on.

    A draft is usually composed in report-only, and evaluating it in that state
    would report that it changes nothing — technically true and completely
    useless, since the question being asked is what happens when it is enabled.
    The declared state is reported separately so the distinction is not lost.
    """
    return {**policy, "state": ENABLED}


def assess(draft, corpus, memberships, existing_policies=()):
    """Evaluate `draft` against the corpus and report what it would change."""
    impact = Impact(
        policy_name=draft.get("displayName") or "(draft policy)",
        declared_state=draft.get("state") or ENABLED,
        window_days=corpus.window_days,
        corpus_sign_ins=corpus.total_sign_ins,
        corpus_users=corpus.distinct_users,
    )

    live = [p for p in existing_policies if p.get("id") != draft.get("id")]
    candidate = _as_enabled(draft)
    per_user = {}

    for observation in corpus.observations:
        conditions = observation.conditions
        membership = memberships.get(conditions.user_id) if memberships else None
        sign_ins = observation.sign_ins
        user_id = conditions.user_id

        verdict = evaluate(candidate, conditions, membership)

        if verdict.applies is None:
            # Could not evaluate. Quarantine rather than assume harmless.
            impact.unsupported_sign_ins += sign_ins
            if user_id:
                impact.unsupported_users.add(user_id)
            for reason in verdict.unsupported_conditions or ("unspecified",):
                impact.unsupported_reasons[reason] += sign_ins
            continue

        if verdict.applies is not True:
            continue

        # What the tenant already does to this sign-in, so that a control the
        # user is already subject to is not counted as new.
        baseline = combine(evaluate_all(live, conditions, membership))

        blocked_now = verdict.result == "block" and not baseline.blocked
        new_controls = [c for c in verdict.grant_controls
                        if c not in baseline.required_controls]

        if verdict.result == "block" and baseline.blocked:
            # Already blocked by something else; the draft changes nothing.
            impact.unchanged_sign_ins += sign_ins
            continue
        if verdict.result != "block" and not new_controls:
            impact.unchanged_sign_ins += sign_ins
            continue

        resource = observation.resource_display_name or conditions.resource_id or "(unknown)"
        platform = conditions.device_platform or "(not reported)"
        impact.by_resource[resource] += sign_ins
        impact.by_platform[platform] += sign_ins

        # Once per tuple, whatever number of controls it newly attracts.
        impact.changed_sign_ins += sign_ins
        if user_id:
            impact.changed_users.add(user_id)

        if blocked_now:
            impact.blocked_sign_ins += sign_ins
            if user_id:
                impact.blocked_users.add(user_id)
        for control in new_controls:
            entry = impact.new_controls.setdefault(
                control, {"sign_ins": 0, "users": set()})
            entry["sign_ins"] += sign_ins
            if user_id:
                entry["users"].add(user_id)

        record = per_user.get(user_id)
        if record is None:
            record = AffectedUser(user_id=user_id,
                                  user_principal_name=observation.user_principal_name,
                                  reason=verdict.reason)
            per_user[user_id] = record
        record.sign_ins += sign_ins
        record.blocked = record.blocked or blocked_now
        record.controls = tuple(dict.fromkeys(list(record.controls) + new_controls))

    impact.affected = list(per_user.values())
    return impact
