# Conditional Access Policy Simulator — Project Brief

## Context

I maintain a personal multi-tenant M365 auditing tool (Python/Flask) that reads Entra ID
configuration via Microsoft Graph and maps findings against the CIS M365 Benchmark. It
already has working multi-tenant app registration, admin consent flow, token acquisition,
and Graph pagination/throttle handling. **Reuse all of that — do not build new auth.**

Deadline is ~3 weeks (internal company competition judged on business value / ROI).

## What we're building

A Conditional Access policy builder with live impact simulation. You compose a policy in
the tool, and before it ever touches a tenant you see exactly which real users and
sign-ins it would have affected over the last 30 days.

Entra's What If tool evaluates one hypothetical sign-in at a time — you have to already
imagine the scenario that breaks. This evaluates a draft policy against **real observed
traffic**, surfacing breakage nobody thought to test for.

## Core architectural constraint

Microsoft's `POST /identity/conditionalAccess/evaluate` (Graph v1.0, GA) only scores
policies that **already exist in the tenant**. The request body takes `signInIdentity`,
`signInContext`, and `signInConditions` — there is no slot for a draft policy. Simulating
an unsaved policy through Microsoft's API would require writing it to the tenant first,
which needs `Policy.ReadWrite.ConditionalAccess`.

**We are not doing that.** This tool stays read-only against client tenants.

Instead we implement our own CA evaluation engine, and use Microsoft's `evaluate` endpoint
as a **correctness test harness** against existing policies. This is the central design
idea of the project and the thing that makes the tool trustworthy.

## Architecture

### 1. Sign-in corpus

`GET /auditLogs/signIns` over a configurable window (default 30 days). Reduce raw sign-ins
to **distinct condition tuples**:

```
(userId, groupMemberships, roleMemberships, appId, devicePlatform, clientAppType,
 country, ipAddress, isCompliant, deviceJoinType, signInRiskLevel, userRiskLevel)
```

Retain a count of real sign-ins per tuple so impact can be reported as both "N sign-ins"
and "N distinct users." A small tenant should collapse to dozens of tuples. **Print the
reduction ratio early** — it validates the whole approach.

### 2. Evaluation engine

Pure function: `evaluate(policy, tuple) -> {applies, grantResult, sessionControls, reason}`

Implement CA condition matching:
- Users/groups/roles include and exclude (exclusions always win)
- Target resources (cloud apps) include/exclude — app *groups* like "Office 365" expand
  to member app IDs
- Device platforms, client app types, locations (named locations, trusted/untrusted)
- Sign-in risk and user risk levels
- Device filters / compliance state
- Grant controls: block, require MFA, require compliant device, require hybrid join, and
  the AND/OR operator between them
- Policy state: enabled / disabled / report-only

**Fail loud on anything unsupported.** If a policy contains a condition the engine doesn't
implement, return `UNSUPPORTED` naming the specific condition. Never guess. A simulator
that admits it can't evaluate something is trustworthy; one that silently gets it wrong is
worthless and the whole premise collapses.

### 3. Validation harness — build this BEFORE the builder UI

For every tuple in the corpus, evaluate the tenant's **existing** policies two ways:
- Through our engine
- Through `POST /identity/conditionalAccess/evaluate` (returns a `whatIfAnalysisResult`
  collection)

Diff the results. Output an agreement report: tuples compared, agreements, disagreements
with the specific policy and condition that diverged, and count of `UNSUPPORTED`.

Iterate the engine until agreement is 100% on supported conditions. This report is a
first-class product feature, not just a test — surface it in the UI. It is the evidence
that draft simulations can be trusted, and it's the strongest thing in the demo.

Also cross-check against the `appliedConditionalAccessPolicies` property on each sign-in
record, which shows what actually happened at real sign-in time.

### 4. Policy builder

UI to compose a CA policy object matching the Graph `conditionalAccessPolicy` schema.
Cover exactly what the engine supports and nothing more — builder and engine capability
sets must stay in lockstep.

Export the composed policy as Graph-ready JSON for manual deployment or existing
PowerShell workflows. **The tool never writes to a tenant.**

### 5. Impact report

Run the draft through the engine against the full tuple corpus. Report:
- Sign-ins and distinct users blocked
- Sign-ins and distinct users newly required to satisfy a grant control
- Affected users listed with the condition that triggered the match
- Breakdown by app and by device platform
- Anything `UNSUPPORTED`, called out prominently

Lead with aggregates — "417 sign-ins across 38 users" — not per-user detail.

## Things to verify before building (do not assume)

- **Exact permission scopes** for `evaluate` and `auditLogs/signIns`. Likely
  `Policy.Read.All` and `AuditLog.Read.All`, but confirm rather than guessing.
- **Sign-in log retention by license.** 7 days without Entra ID P1, 30 with. If target
  tenants are on 7, the corpus is thin and aggregate numbers get weak.
- **Throttling limits on `evaluate`.** Only used during validation runs, but those are the
  high-volume path. Back off on 429 and respect `Retry-After`.
- **Group and role membership resolution** — sign-in logs give a userId, not memberships.
  Needs a separate resolution pass, cached per tenant.

## Reference implementation

The **Maester** PowerShell project has `Test-MtConditionalAccessWhatIf`. Read it first —
working reference for the evaluate call shape and response structure.

Docs: `POST /identity/conditionalAccess/evaluate` (v1.0), `whatIfAnalysisResult` resource
type, `conditionalAccessPolicy` resource type, `GET /auditLogs/signIns`.

## Explicitly out of scope for v1

- Any write operation against any tenant
- Running across the whole tenant book at once — one tenant at a time
- Scheduling, alerting, historical trending
- Session control simulation beyond reporting which controls would apply

## Build order

1. Sign-in log pull + tuple dedup; print reduction ratio to sanity check
2. Group/role membership resolution with caching
3. Evaluation engine — start with users/groups/apps/block-or-grant only
4. Validation harness and agreement report
5. Iterate until 100% agreement on supported conditions; widen condition coverage and
   re-validate after each addition
6. Policy builder UI, scoped to supported conditions
7. Impact report
8. Integrate into existing auditor UI

If time runs short, cut condition coverage — not validation. A simulator that handles four
conditions provably correctly beats one that handles twelve conditions unverifiably.
