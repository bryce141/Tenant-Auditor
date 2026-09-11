"""Evaluate a Conditional Access policy against one observed sign-in.

Microsoft's `POST /identity/conditionalAccess/evaluate` only scores policies
that already exist in a tenant — there is no slot in the request body for a
draft. Simulating an unsaved policy through Microsoft's API would mean writing
it to the tenant first, which needs `Policy.ReadWrite.ConditionalAccess`, and
this tool stays read-only. So the evaluation is implemented here, and
Microsoft's endpoint becomes the correctness harness that proves it right
against existing policies (see `ca_validation`).

`evaluate()` is a pure function of (policy, condition tuple, membership). It
does no I/O, which is what lets the whole engine be tested without a tenant and
what lets the validation harness run it over thousands of tuples cheaply.

## Never guess

Every condition this engine does not implement produces `UNSUPPORTED`, naming
the specific condition. It never falls through to "doesn't apply", because a
policy silently treated as inapplicable is reported as breaking nobody — the
exact false negative that makes a simulator worthless. A tool that admits it
cannot evaluate a location condition is trustworthy; one that quietly scores it
as a non-match is worse than no tool, because it is believed.

## Conjunction lets us answer more than you'd think

A policy's conditions are ANDed. So a *definite* non-match on any one supported
condition settles the whole policy as inapplicable, even when another condition
is unsupported — the unsupported one cannot rescue it. Only when every
evaluable condition matches and some condition is unevaluable do we have to
give up and say UNSUPPORTED. This keeps coverage high without ever guessing.
"""
from dataclasses import dataclass

# Results
BLOCK = "block"
GRANT = "grant"
SESSION_ONLY = "sessionOnly"
NO_CONTROLS = "noControls"
NOT_APPLICABLE = "notApplicable"
UNSUPPORTED = "unsupported"

# Policy states
ENABLED = "enabled"
DISABLED = "disabled"
REPORT_ONLY = "enabledForReportingButNotEnforced"

# conditionalAccessUsers special tokens
ALL_USERS = "all"
NO_USERS = "none"
GUESTS_OR_EXTERNAL = "guestsorexternalusers"

# conditionalAccessApplications tokens that stand for a set of app ids rather
# than one app. Expanding them needs Microsoft's published membership list for
# the suite, which changes; until that is resolved from somewhere authoritative
# these are declared unsupported rather than guessed at.
APP_GROUP_TOKENS = {"office365", "microsoftadminportals"}

# The portal's "Exchange ActiveSync clients" maps to exchangeActiveSync.
# easSupported and easUnsupported are older spellings still present on policies
# created years ago; easUnsupported is deprecated in favour of
# exchangeActiveSync, which covers EAS supported and unsupported platforms
# alike. The sign-in log only ever produces exchangeActiveSync, so the policy
# spellings are folded onto it here rather than silently never matching.
EAS_EQUIVALENTS = {"exchangeactivesync", "eassupported", "easunsupported"}


@dataclass(frozen=True)
class Evaluation:
    """What one policy would do to one sign-in."""
    policy_id: str
    policy_name: str
    state: str
    applies: bool                 # None when it could not be determined
    result: str
    enforced: bool                # False for report-only and disabled policies
    grant_operator: str = None
    grant_controls: tuple = ()
    session_controls: tuple = ()
    reason: str = ""
    unsupported_conditions: tuple = ()

    @property
    def blocks(self):
        """Would actually stop this sign-in — report-only policies do not."""
        return self.applies is True and self.enforced and self.result == BLOCK

    @property
    def requires_grant(self):
        """Would actually impose a grant control the user has to satisfy."""
        return (self.applies is True and self.enforced
                and self.result == GRANT and bool(self.grant_controls))

    def as_dict(self):
        return {
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "state": self.state,
            "applies": self.applies,
            "result": self.result,
            "enforced": self.enforced,
            "grant_operator": self.grant_operator,
            "grant_controls": list(self.grant_controls),
            "session_controls": list(self.session_controls),
            "reason": self.reason,
            "unsupported_conditions": list(self.unsupported_conditions),
        }


def _lower_set(values):
    return {str(v).lower() for v in (values or [])}


# ---------------------------------------------------------------------------
# Condition matching
#
# Each returns (matched, detail): True, False, or None for "cannot evaluate".
# ---------------------------------------------------------------------------

def _match_users(users, conditions, membership):
    users = users or {}
    include_users = _lower_set(users.get("includeUsers"))
    exclude_users = _lower_set(users.get("excludeUsers"))
    include_groups = set(users.get("includeGroups") or [])
    exclude_groups = set(users.get("excludeGroups") or [])
    include_roles = set(users.get("includeRoles") or [])
    exclude_roles = set(users.get("excludeRoles") or [])

    if users.get("includeGuestsOrExternalUsers") or users.get("excludeGuestsOrExternalUsers"):
        # These carry guestOrExternalUserTypes and a membership of external
        # tenants, neither of which the sign-in log reports.
        return None, "users.guestsOrExternalUsers"

    user_id = (conditions.user_id or "").lower()
    needs_directory = bool(include_groups or exclude_groups
                           or include_roles or exclude_roles
                           or GUESTS_OR_EXTERNAL in include_users
                           or GUESTS_OR_EXTERNAL in exclude_users)

    if membership is None or not membership.resolved:
        if needs_directory:
            # An unresolved user is not a user who belongs to nothing. Saying
            # "not a member" here would report a group-targeted policy as
            # breaking nobody.
            return None, "users (directory membership unresolved)"
        # A policy targeting only literal user ids or All can still be answered.

    def in_group(group_ids):
        return bool(membership and membership.group_ids & group_ids)

    def in_role(role_refs):
        return bool(membership and any(membership.in_role(r) for r in role_refs))

    is_guest = bool(membership and membership.is_guest)

    # Exclusions win outright, and they win before inclusions are considered.
    if user_id and user_id in exclude_users:
        return False, "user is excluded"
    if GUESTS_OR_EXTERNAL in exclude_users and is_guest:
        return False, "guests are excluded"
    if in_group(exclude_groups):
        return False, "user is in an excluded group"
    if in_role(exclude_roles):
        return False, "user is in an excluded role"

    if NO_USERS in include_users:
        return False, "policy targets no users"

    included = (
        ALL_USERS in include_users
        or (user_id and user_id in include_users)
        or (GUESTS_OR_EXTERNAL in include_users and is_guest)
        or in_group(include_groups)
        or in_role(include_roles)
    )
    if not included:
        return False, "user is not in scope"
    return True, "user is in scope"


def _match_applications(applications, conditions):
    applications = applications or {}

    if applications.get("includeUserActions"):
        # urn:user:registersecurityinfo / urn:user:registerdevice. A sign-in
        # record does not say which user action was being performed.
        return None, "applications.includeUserActions"
    if applications.get("includeAuthenticationContextClassReferences"):
        return None, "applications.authenticationContext"
    if applications.get("applicationFilter"):
        return None, "applications.applicationFilter"

    include = _lower_set(applications.get("includeApplications"))
    exclude = _lower_set(applications.get("excludeApplications"))

    if (include | exclude) & APP_GROUP_TOKENS:
        # Office365 / MicrosoftAdminPortals stand for a published set of app
        # ids. Treating the token as a literal app id would never match and
        # would silently under-report a policy that covers most of the tenant.
        return None, "applications (Office365/MicrosoftAdminPortals not expanded)"

    app_id = (conditions.app_id or "").lower()
    if not app_id:
        return None, "applications (sign-in reported no appId)"

    if app_id in exclude:
        return False, "application is excluded"
    if NO_USERS in include:
        return False, "policy targets no applications"
    if ALL_USERS in include or app_id in include:
        return True, "application is in scope"
    return False, "application is not in scope"


def _match_client_app_types(client_app_types, conditions):
    wanted = _lower_set(client_app_types)
    if not wanted or ALL_USERS in wanted:
        return True, "all client app types"

    observed = (conditions.client_app_type or "").lower()
    if not observed:
        return None, "clientAppTypes (sign-in client app not recognised)"

    if observed in EAS_EQUIVALENTS:
        return (bool(wanted & EAS_EQUIVALENTS),
                "Exchange ActiveSync client app type")
    return observed in wanted, "client app type"


def _match_platforms(platforms, conditions):
    if not platforms:
        return True, "no platform condition"

    include = _lower_set(platforms.get("includePlatforms"))
    exclude = _lower_set(platforms.get("excludePlatforms"))
    observed = (conditions.device_platform or "").lower()

    if not observed:
        # No device information on the sign-in. Whether an "all platforms"
        # policy covers a sign-in from an unidentifiable platform is exactly
        # the kind of thing to verify against Microsoft rather than assume.
        return None, "platforms (sign-in reported no device platform)"

    if observed in exclude:
        return False, "platform is excluded"
    if ALL_USERS in include or observed in include:
        return True, "platform is in scope"
    return False, "platform is not in scope"


def _match_risk(levels, observed, label):
    wanted = _lower_set(levels)
    if not wanted:
        return True, f"no {label} condition"
    observed = (observed or "none").lower()
    if observed == "hidden":
        # The tenant has no Entra ID P2, so the real risk level is unknown —
        # which is not the same as no risk.
        return None, f"{label} (risk hidden — tenant not licensed for Identity Protection)"
    return observed in wanted, label


def _unsupported_conditions(conditions_block):
    """Conditions present on the policy that this engine does not implement."""
    found = []
    if conditions_block.get("locations"):
        found.append("locations (named locations not yet resolved)")
    if conditions_block.get("devices"):
        found.append("devices (device filter)")
    if conditions_block.get("clientApplications"):
        found.append("clientApplications (workload identities)")
    if conditions_block.get("authenticationFlows"):
        found.append("authenticationFlows")
    if conditions_block.get("insiderRiskLevels"):
        found.append("insiderRiskLevels")
    if conditions_block.get("servicePrincipalRiskLevels"):
        found.append("servicePrincipalRiskLevels")
    return found


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------

def _grant_summary(grant_controls):
    """(result, operator, controls) for a policy's grant controls."""
    if not grant_controls:
        return None, None, ()

    built_in = [c for c in (grant_controls.get("builtInControls") or [])]
    if any(str(c).lower() == BLOCK for c in built_in):
        # Block is absolute: it is never combined with other controls.
        return BLOCK, None, (BLOCK,)

    controls = list(built_in)
    for terms in grant_controls.get("termsOfUse") or []:
        controls.append(f"termsOfUse:{terms}")
    for factor in grant_controls.get("customAuthenticationFactors") or []:
        controls.append(f"customAuthenticationFactor:{factor}")

    strength = grant_controls.get("authenticationStrength")
    if strength:
        name = strength.get("displayName") or strength.get("id") or "required"
        controls.append(f"authenticationStrength:{name}")

    if not controls:
        return None, None, ()
    return GRANT, grant_controls.get("operator"), tuple(controls)


def _session_summary(session_controls):
    """Names of the session controls a policy would impose.

    Enumerated from whatever keys are present rather than from a hardcoded list,
    so a session control Microsoft adds later is reported rather than dropped.
    """
    if not session_controls:
        return ()
    names = []
    for name, value in sorted(session_controls.items()):
        if name.startswith("@"):
            continue
        if isinstance(value, dict):
            if value.get("isEnabled") is not False:
                names.append(name)
        elif value:
            names.append(name)
    return tuple(names)


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------

def evaluate(policy, conditions, membership=None):
    """Would `policy` apply to a sign-in with these `conditions`, and do what?

    `conditions` is a signin_corpus.ConditionTuple; `membership` the
    ca_memberships.Membership for its user, or None when the policy's user
    scope doesn't need one.
    """
    policy_id = policy.get("id")
    policy_name = policy.get("displayName") or "(unnamed policy)"
    state = policy.get("state")
    enforced = state == ENABLED

    result, operator, controls = _grant_summary(policy.get("grantControls"))
    session = _session_summary(policy.get("sessionControls"))
    if result is None:
        result = SESSION_ONLY if session else NO_CONTROLS

    def outcome(applies, final_result, reason, unsupported=()):
        return Evaluation(
            policy_id=policy_id, policy_name=policy_name, state=state,
            applies=applies, result=final_result, enforced=enforced,
            grant_operator=operator, grant_controls=controls,
            session_controls=session, reason=reason,
            unsupported_conditions=tuple(unsupported),
        )

    if state == DISABLED:
        return outcome(False, NOT_APPLICABLE, "policy is disabled")

    if state not in (ENABLED, REPORT_ONLY):
        return outcome(None, UNSUPPORTED, f"unrecognised policy state {state!r}",
                       [f"state:{state}"])

    condition_block = policy.get("conditions") or {}

    checks = [
        _match_users(condition_block.get("users"), conditions, membership),
        _match_applications(condition_block.get("applications"), conditions),
        _match_client_app_types(condition_block.get("clientAppTypes"), conditions),
        _match_platforms(condition_block.get("platforms"), conditions),
        _match_risk(condition_block.get("signInRiskLevels"),
                    conditions.sign_in_risk_level, "signInRiskLevels"),
        _match_risk(condition_block.get("userRiskLevels"),
                    conditions.user_risk_level, "userRiskLevels"),
    ]

    unsupported = [detail for matched, detail in checks if matched is None]
    unsupported += _unsupported_conditions(condition_block)

    # Conditions are ANDed, so one definite non-match settles the policy even
    # if another condition is unevaluable — the unevaluable one cannot rescue
    # it. This is what keeps coverage high without ever guessing.
    for matched, detail in checks:
        if matched is False:
            return outcome(False, NOT_APPLICABLE, detail)

    if unsupported:
        return outcome(None, UNSUPPORTED,
                       "cannot evaluate: " + "; ".join(unsupported), unsupported)

    reason = ("policy applies" if enforced
              else "policy applies but is report-only and would not be enforced")
    return outcome(True, result, reason)


def evaluate_all(policies, conditions, membership=None):
    return [evaluate(p, conditions, membership) for p in policies]


@dataclass
class Outcome:
    """What the whole policy set would do to one sign-in."""
    blocked: bool = False
    blocking_policies: tuple = ()
    required_controls: tuple = ()
    requiring_policies: tuple = ()
    session_controls: tuple = ()
    report_only_policies: tuple = ()
    unsupported_policies: tuple = ()

    @property
    def determinate(self):
        """False when some policy could not be evaluated, so the answer is partial."""
        return not self.unsupported_policies

    def as_dict(self):
        return {
            "blocked": self.blocked,
            "blocking_policies": list(self.blocking_policies),
            "required_controls": list(self.required_controls),
            "requiring_policies": list(self.requiring_policies),
            "session_controls": list(self.session_controls),
            "report_only_policies": list(self.report_only_policies),
            "unsupported_policies": list(self.unsupported_policies),
            "determinate": self.determinate,
        }


def combine(evaluations):
    """Reduce per-policy evaluations to what the sign-in would actually experience.

    A block by any enforced policy wins over every grant control, which is how
    Entra resolves them. Report-only policies are tracked separately and never
    counted as impact: reporting them as breakage is how a simulator cries wolf.
    """
    blocked, blocking = False, []
    controls, requiring, session = [], [], []
    report_only, unsupported = [], []

    for e in evaluations:
        if e.applies is None:
            unsupported.append(e.policy_name)
            continue
        if e.applies is not True:
            continue
        if not e.enforced:
            report_only.append(e.policy_name)
            continue
        if e.result == BLOCK:
            blocked = True
            blocking.append(e.policy_name)
            continue
        for control in e.grant_controls:
            if control not in controls:
                controls.append(control)
        if e.grant_controls:
            requiring.append(e.policy_name)
        for control in e.session_controls:
            if control not in session:
                session.append(control)

    return Outcome(
        blocked=blocked,
        blocking_policies=tuple(blocking),
        required_controls=tuple(controls),
        requiring_policies=tuple(requiring),
        session_controls=tuple(session),
        report_only_policies=tuple(report_only),
        unsupported_policies=tuple(unsupported),
    )
