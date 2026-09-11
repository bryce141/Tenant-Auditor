#!/usr/bin/env python3
"""Generate real sign-in events in a DEV tenant, to fill the CA simulator's corpus.

A brand-new tenant has no sign-in history at all, and Entra's retention is not
retroactive — the corpus starts accumulating from the first sign-in anyone
performs. So the demo's aggregate numbers depend entirely on traffic generated
between now and when the report is run.

    python scripts/generate_signin_traffic.py --dry-run
    python scripts/generate_signin_traffic.py --count 200
    python scripts/generate_signin_traffic.py --count 500 --delay 0.5

THIS PERFORMS REAL AUTHENTICATIONS as real users against a real directory. Run
it against a DEV tenant only.

## What this can and cannot produce

It varies the **resource** — which is the dimension that matters most, because
Conditional Access targets resources, so `resource_id` is what splits tuples
along the axis policies actually test. Requesting a token for Exchange, then
SharePoint, then Graph produces sign-ins that a cloud-app-scoped policy sees as
genuinely different.

It cannot produce device platform, device compliance, or country. Those come
from a real client on a real network: the resource-owner password flow reports
no device, and every request leaves from this machine's IP. Tuples generated
here will carry `device_platform = None`, which the engine correctly reports as
UNSUPPORTED against any platform-conditioned policy rather than guessing.

**So this is half the job.** Run it for volume, and separately sign in as two
or three of these users from a phone and a laptop, in a couple of browsers, to
get real platform and device spread. A corpus that is 100% scripted traffic
will show a large UNSUPPORTED count against the platform policies and no
country diversity at all, and that is an honest result rather than a bug.

## Why the resource-owner flow

It is the only headless way to produce a sign-in that Entra logs as
interactive, which is what `/auditLogs/signIns` returns in v1.0. It requires
the app registration to allow public client flows, and it fails against any
account subject to enforced MFA — which is exactly why the seeded CA policies
are report-only.
"""
import argparse
import json
import random
import sys
import time
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import msal  # noqa: E402

CREDENTIAL_FILE = REPO_ROOT / "test-users.json"

# Resources worth spreading traffic across. Each yields a different resourceId
# in the sign-in log, which is what gives the corpus tuples that a cloud-app
# scoped policy can tell apart.
#
# A scope the app has no consent for still produces a logged sign-in — a failed
# one — which is itself useful corpus data, but the failures are reported
# separately below rather than being passed off as successes.
DEFAULT_SCOPES = [
    ("Microsoft Graph", "https://graph.microsoft.com/.default"),
    ("Exchange Online", "https://outlook.office365.com/.default"),
    ("Azure AD Graph", "https://graph.windows.net/.default"),
]


def load_users():
    if not CREDENTIAL_FILE.exists():
        raise SystemExit(
            f"No {CREDENTIAL_FILE.name}. Run scripts/seed_test_users.ps1 -Execute first."
        )
    data = json.loads(CREDENTIAL_FILE.read_text())
    users = data if isinstance(data, list) else [data]
    if not users:
        raise SystemExit(f"{CREDENTIAL_FILE.name} is empty.")
    return users


def sign_in(app, user, scope):
    """One authentication. Returns (ok, detail)."""
    try:
        result = app.acquire_token_by_username_password(
            username=user["userPrincipalName"],
            password=user["password"],
            scopes=[scope],
        )
    except Exception as e:
        return False, f"exception: {e}"[:120]

    if "access_token" in result:
        return True, "ok"
    # AADSTS50126 bad credentials, AADSTS65001 no consent, AADSTS50076 MFA
    # required, AADSTS7000218 public client flows not enabled. All of these
    # still register a sign-in event, which is why failures are counted rather
    # than treated as nothing having happened.
    return False, (result.get("error_description") or result.get("error") or "unknown").split("\n")[0][:120]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--tenant", help="name (or part of one) of the configured "
                                     "tenant to authenticate against")
    ap.add_argument("--tenant-id", help="tenant id, instead of --tenant")
    ap.add_argument("--client-id", help="app registration to authenticate with "
                                        "(must allow public client flows)")
    ap.add_argument("--count", type=int, default=100,
                    help="how many sign-ins to perform (default 100)")
    ap.add_argument("--delay", type=float, default=0.3,
                    help="seconds between sign-ins (default 0.3)")
    ap.add_argument("--dry-run", action="store_true",
                    help="show the plan without authenticating")
    args = ap.parse_args()

    users = load_users()

    tenant_id, client_id = args.tenant_id, args.client_id
    if not (tenant_id and client_id):
        # Resolve from the auditor's configured tenants, so the values do not
        # need pasting in twice. Never silently pick one: generating traffic
        # against the wrong tenant is slow to notice — the sign-ins land
        # somewhere real, just not where the corpus is being built.
        from app import create_app
        from app.models.tenant import Tenant

        flask_app = create_app()
        with flask_app.app_context():
            tenants = Tenant.query.order_by(Tenant.name).all()
            if not tenants:
                raise SystemExit("No tenants configured, and --tenant-id/--client-id not given.")
            if args.tenant:
                matches = [t for t in tenants if args.tenant.lower() in t.name.lower()]
            else:
                matches = tenants
            if not matches:
                known = ", ".join(t.name for t in tenants)
                raise SystemExit(f"No tenant matching {args.tenant!r}. Known: {known}")
            if len(matches) > 1:
                known = ", ".join(t.name for t in matches)
                raise SystemExit(f"Several tenants match — pass --tenant. Candidates: {known}")
            tenant_id = tenant_id or matches[0].tenant_id
            client_id = client_id or matches[0].client_id
            print(f"Using configured tenant: {matches[0].name}")

    print(f"Tenant : {tenant_id}")
    print(f"Client : {client_id}")
    print(f"Users  : {len(users)}")
    print(f"Sign-ins to perform: {args.count}\n")

    if args.dry_run:
        print("Dry run — no authentication attempted. Resources that would be hit:")
        for name, scope in DEFAULT_SCOPES:
            print(f"  {name:<18} {scope}")
        print("\nThis produces no device platform and a single source IP. Sign in "
              "manually\nfrom a phone and a laptop as well, or the corpus will have "
              "no platform spread.")
        return 0

    app = msal.PublicClientApplication(
        client_id, authority=f"https://login.microsoftonline.com/{tenant_id}")

    successes = Counter()
    failures = Counter()
    reasons = Counter()

    for n in range(1, args.count + 1):
        user = random.choice(users)
        resource_name, scope = random.choice(DEFAULT_SCOPES)

        ok, detail = sign_in(app, user, scope)
        if ok:
            successes[resource_name] += 1
        else:
            failures[resource_name] += 1
            reasons[detail] += 1

        if n % 10 == 0 or n == args.count:
            total_ok = sum(successes.values())
            print(f"  {n}/{args.count}  ok={total_ok} failed={sum(failures.values())}",
                  flush=True)
        time.sleep(args.delay)

    print("\nBy resource:")
    for name, _ in DEFAULT_SCOPES:
        print(f"  {name:<18} ok={successes[name]:<5} failed={failures[name]}")

    if reasons:
        print("\nFailure reasons — these still generated sign-in events, but if one")
        print("dominates it is worth fixing rather than filling the corpus with it:")
        for reason, count in reasons.most_common(5):
            print(f"  {count:>5}  {reason}")

    if not sum(successes.values()):
        print("\nNothing succeeded. The usual causes, in order of likelihood:")
        print("  * the app registration does not allow public client flows")
        print("    (Entra > App registrations > Authentication > Allow public client flows)")
        print("  * the users need a moment after creation before they can authenticate")
        print("  * a CA policy is enforcing MFA — the seeded ones are report-only,")
        print("    so check for anything enabled, and that Security Defaults are off")
        return 1

    print("\nSign-in logs lag a few minutes. Then:")
    print("  FLASK_APP=run.py flask ca-corpus --tenant <name>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
