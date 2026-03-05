import os
import json
import argparse
from datetime import datetime, timezone
from dotenv import load_dotenv
from auditor.auth import get_token
from auditor.checks.mfa import check_mfa
from auditor.checks.conditional_access import check_conditional_access
from auditor.checks.stale_accounts import check_stale_accounts
from auditor.checks.risky_users import check_risky_users
from auditor.checks.mailbox_forwarding import check_mailbox_forwarding
from auditor.checks.admin_roles import check_admin_roles
from auditor.checks.guest_users import check_guest_users
from auditor.checks.legacy_auth import check_legacy_auth
from auditor.checks.password_policy import check_password_policy
from auditor.checks.sspr import check_sspr
from auditor.checks.pim_roles import check_pim_roles
from auditor.checks.app_registrations import check_app_registrations
from auditor.checks.named_locations import check_named_locations
from auditor.scorer import calculate_score
from auditor.reporter import generate_html, save_report

load_dotenv()


def run_audit():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    results = {
        "mfa":                 check_mfa(headers),
        "conditional_access":  check_conditional_access(headers),
        "stale_accounts":      check_stale_accounts(headers),
        "risky_users":         check_risky_users(headers),
        "mailbox_forwarding":  check_mailbox_forwarding(headers),
        "admin_roles":         check_admin_roles(headers),
        "guest_users":         check_guest_users(headers),
        "legacy_auth":         check_legacy_auth(headers),
        "password_policy":     check_password_policy(headers),
        "sspr":                check_sspr(headers),
        "pim_roles":           check_pim_roles(headers),
        "app_registrations":   check_app_registrations(headers),
        "named_locations":     check_named_locations(headers),
    }
    score = calculate_score(results)
    return results, score


def save_run(tenant_id, results, score):
    os.makedirs("runs", exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    run = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "score": score,
        "results": results,
    }
    path = os.path.join("runs", f"{timestamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(run, f, indent=2, default=str)
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tenant Security Auditor")
    parser.add_argument("--output",  default="report.html", help="Output HTML report path (default: report.html)")
    parser.add_argument("--no-html", action="store_true",   help="Skip HTML report generation")
    args = parser.parse_args()

    tenant_id = os.getenv("TENANT_ID")

    print("Authenticating...")
    results, score = run_audit()

    run_path = save_run(tenant_id, results, score)
    print(f"Run saved: {run_path}")

    # ── Console summary ───────────────────────────────────────────────────────
    print(f"\n{'='*52}")
    print(f"  SECURITY SCORE: {score['overall']}/100")
    print(f"{'='*52}")
    for s in score["sections"]:
        cis = s.get("cis", {})
        cis_tag = f"  [{cis['id']}]" if cis.get("id") else ""
        if s["skipped"]:
            print(f"  {'(skipped)':<12} {s['name']}{cis_tag}")
        else:
            bar = round((s["earned"] / s["possible"]) * 10) if s["possible"] else 0
            print(f"  {s['earned']:>2}/{s['possible']:<3} {'█' * bar}{'░' * (10 - bar)}  {s['name']}{cis_tag}")
            for issue in s["issues"]:
                print(f"               ↳ {issue}")

    if not args.no_html:
        html = generate_html(tenant_id, results, score)
        save_report(html, args.output)
        print(f"  Open {args.output} in your browser to view the full report.")
