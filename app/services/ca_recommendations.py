"""Turn audit findings into policies, and price each one against real traffic.

The simulator answers "what would this policy break". The more useful question
for someone actually running a tenant is the reverse: *which policies am I
missing, and what would each cost me?* The audit already knows what is missing.
The engine already knows who would be affected. This joins them.

The output is the sentence an admin actually wants and cannot get from anything
Microsoft ships:

    Legacy Auth Blocked   FAIL
    → Block legacy authentication — would affect 0 sign-ins. Safe to enable.

## Honesty constraints, because this is advice

**Only five of the twelve scored controls have a Conditional Access policy as
their remedy.** SPF and DKIM, mailbox forwarding, password policy, app
credentials — none of those are fixed by a CA policy, and a recommendations page
that stayed silent about them would imply the list is exhaustive. They are
listed as out of scope, with where the fix actually lives.

**Some remedies are partial.** Standing privileged access is fixed by PIM, not
by Conditional Access. Requiring MFA for admins reduces the damage without
clearing the finding, and saying so is the difference between advice and a
sales pitch.

**One policy can address several findings.** Recommending "require MFA" three
times because three checks failed would pad the list and suggest more work than
there is. Remedies are keyed by the policy, and each lists the findings it
covers.

**A recommendation whose impact cannot be fully evaluated says so.** It is
otherwise indistinguishable from one that is genuinely safe, which is the worst
possible confusion on a page whose whole purpose is "is this safe to turn on".
"""
from dataclasses import dataclass, field

from app.services.ca_builder import (EXCHANGE_ONLINE_APP, GLOBAL_ADMIN_ROLE,
                                     build_policy)
from app.services.ca_impact import assess

REPORT_ONLY = "enabledForReportingButNotEnforced"

# A policy, the findings it addresses, and whether it actually closes them.
# Keyed by remedy rather than by check, so one policy answering three findings
# appears once.
REMEDIES = {
    "block-legacy": {
        "label": "Block legacy authentication",
        "why": "Legacy protocols cannot present a second factor, so they are the "
               "standard way an attacker sidesteps MFA entirely.",
        "addresses": {"legacy_auth_blocked"},
        "partial": None,
        "form": {
            "displayName": "Block legacy authentication",
            "allUsers": "on", "allApplications": "on",
            "clientAppTypes": ["exchangeActiveSync", "other"],
            "grantControls": ["block"], "grantOperator": "OR",
            "state": REPORT_ONLY,
        },
    },
    "baseline-mfa": {
        "label": "Require MFA for all users",
        "why": "The single control that closes the largest share of account "
               "compromise. Everything else is refinement.",
        "addresses": {"conditional_access", "mfa_registration"},
        "partial": None,
        "form": {
            "displayName": "Require MFA for all users",
            "allUsers": "on", "allApplications": "on",
            "grantControls": ["mfa"], "grantOperator": "OR",
            "state": REPORT_ONLY,
        },
    },
    "admin-mfa": {
        "label": "Require MFA for administrators",
        "why": "Privileged accounts are the ones worth stealing, and the ones "
               "whose compromise is hardest to undo.",
        "addresses": {"pim_standing_roles", "admin_role_hygiene"},
        "partial": "Reduces the damage but does not clear the finding — standing "
                   "privileged access is fixed by PIM, which grants the role only "
                   "when it is activated. This makes the role harder to use, not "
                   "shorter-lived.",
        "form": {
            "displayName": "Require MFA for administrators",
            "includeRoles": [GLOBAL_ADMIN_ROLE], "allApplications": "on",
            "grantControls": ["mfa"], "grantOperator": "OR",
            "state": REPORT_ONLY,
        },
    },
    "compliant-exchange": {
        "label": "Require a compliant device for Exchange",
        "why": "Mail is where the valuable content is, and an unmanaged device "
               "is where it leaks from.",
        "addresses": {"mailbox_forwarding"},
        "partial": "Does not stop forwarding rules that already exist — it limits "
                   "which devices can create new ones.",
        "form": {
            "displayName": "Require a compliant device for Exchange",
            "allUsers": "on", "includeApplications": [EXCHANGE_ONLINE_APP],
            "grantControls": ["compliantDevice"], "grantOperator": "OR",
            "state": REPORT_ONLY,
        },
    },
}

# Findings a Conditional Access policy cannot fix, and where the fix does live.
# Listed so the page does not imply the recommendations above are exhaustive.
OUT_OF_SCOPE = {
    "email_authentication": "SPF, DKIM and DMARC are DNS records, not access policy.",
    "password_policy": "Set in the tenant's authentication methods policy.",
    "sspr_enabled": "Self-service password reset is its own configuration.",
    "app_credential_expiry": "Rotate the secret on the app registration.",
    "app_permissions": "Review and revoke the consented Graph permissions.",
    "named_locations": "Define the locations themselves — a policy can only "
                       "reference locations that already exist.",
}

# How much of the tenant a recommendation touches before it stops being an easy
# decision. A policy affecting nobody is safe to switch on today; one affecting
# a quarter of the tenant needs a rollout, not a toggle.
SAFE = "safe"
LOW = "low"
SIGNIFICANT = "significant"
UNKNOWN = "unknown"

LOW_IMPACT_CEILING = 0.15


@dataclass
class Recommendation:
    remedy_id: str
    label: str
    why: str
    partial: str = None
    findings: list = field(default_factory=list)   # the audit checks it answers
    draft: dict = None
    impact: object = None
    verdict: str = UNKNOWN

    @property
    def headline(self):
        if self.impact is None:
            return "Impact not assessed"
        if self.verdict == UNKNOWN:
            return "Impact cannot be fully assessed"
        if self.impact.affected_sign_ins == 0:
            return "Would affect nobody — safe to enable"
        return self.impact.headline()

    def as_dict(self):
        return {
            "remedy_id": self.remedy_id,
            "label": self.label,
            "why": self.why,
            "partial": self.partial,
            "findings": self.findings,
            "verdict": self.verdict,
            "headline": self.headline,
            "impact": self.impact.summary() if self.impact else None,
        }


def _verdict(impact, corpus_users):
    """How easy a call this is, or that we cannot say."""
    if impact is None:
        return UNKNOWN
    if not impact.complete:
        # Some traffic could not be evaluated, so "affects nobody" might be
        # wrong in the one direction that matters.
        return UNKNOWN
    affected = len(impact.affected_users)
    if affected == 0:
        return SAFE
    if corpus_users and affected / corpus_users <= LOW_IMPACT_CEILING:
        return LOW
    return SIGNIFICANT


def _failing(checks):
    """{check_name: check} for everything the audit flagged."""
    return {c.check_name: c for c in checks
            if getattr(c, "status", None) in ("fail", "warn")}


def recommend(checks, corpus, memberships, existing_policies=()):
    """Policies worth adding, each priced against the tenant's own traffic.

    `checks` are ReportCheck rows from the most recent audit. Only remedies
    whose findings actually failed are returned — this is a list of what is
    missing, not a catalogue.
    """
    flagged = _failing(checks)
    recommendations = []

    for remedy_id, remedy in REMEDIES.items():
        matched = [flagged[name] for name in remedy["addresses"] if name in flagged]
        if not matched:
            continue

        draft = build_policy(dict(remedy["form"]))
        impact = assess(draft, corpus, memberships,
                        existing_policies=existing_policies)

        recommendations.append(Recommendation(
            remedy_id=remedy_id,
            label=remedy["label"],
            why=remedy["why"],
            partial=remedy["partial"],
            findings=[{"check_name": c.check_name,
                       "display_name": c.display_name,
                       "status": c.status,
                       "summary": c.summary} for c in matched],
            draft=draft,
            impact=impact,
            verdict=_verdict(impact, corpus.distinct_users),
        ))

    # Easiest decisions first: a policy affecting nobody is something to do this
    # afternoon, and burying it under one needing a rollout wastes it.
    order = {SAFE: 0, LOW: 1, SIGNIFICANT: 2, UNKNOWN: 3}
    recommendations.sort(key=lambda r: (order.get(r.verdict, 9),
                                        len(r.impact.affected_users) if r.impact else 0))
    return recommendations


def out_of_scope(checks):
    """Findings no Conditional Access policy will fix, and where the fix lives."""
    flagged = _failing(checks)
    return [{"check_name": name, "display_name": check.display_name,
             "status": check.status, "summary": check.summary,
             "where": OUT_OF_SCOPE[name]}
            for name, check in flagged.items() if name in OUT_OF_SCOPE]


def unaddressed(checks):
    """Flagged findings this module has nothing to say about at all.

    Kept visible rather than dropped: a page that silently ignores a third of
    the audit reads as a complete answer when it is not.
    """
    flagged = _failing(checks)
    covered = {name for remedy in REMEDIES.values() for name in remedy["addresses"]}
    return [{"check_name": name, "display_name": check.display_name,
             "status": check.status, "summary": check.summary}
            for name, check in flagged.items()
            if name not in covered and name not in OUT_OF_SCOPE]
