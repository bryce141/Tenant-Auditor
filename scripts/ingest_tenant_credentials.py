#!/usr/bin/env python3
"""Read the three values setup_tenant.ps1 printed and store them, without
showing them.

    ./scripts/prepare_sim_tenant.ps1 -Execute *> ~/prepare.log
    python scripts/ingest_tenant_credentials.py ~/prepare.log --name "Perco Labs"

The client secret is displayed exactly once, by the script that mints it. That
makes it awkward to move: reading it out of a terminal and pasting it somewhere
puts a live credential into whatever carries the paste — which is how this
repo's history came to need rewriting once already.

So the secret goes from the log file into the encrypted tenants table directly.
Nothing here prints it, and the log file is deleted on success unless --keep is
passed.
"""
import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

PATTERNS = {
    "tenant_id": re.compile(r"Directory \(tenant\) ID\s*:\s*([0-9a-fA-F-]{36})"),
    "client_id": re.compile(r"Application \(client\) ID\s*:\s*([0-9a-fA-F-]{36})"),
    "client_secret": re.compile(r"Client secret\s*:\s*(\S+)"),
}


def parse(text):
    found = {}
    for field, pattern in PATTERNS.items():
        match = pattern.search(text)
        if match:
            found[field] = match.group(1)
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile", help="output of prepare_sim_tenant.ps1 -Execute")
    ap.add_argument("--name", default="Sim Tenant", help="name for this tenant")
    ap.add_argument("--keep", action="store_true",
                    help="do not delete the log file afterwards")
    args = ap.parse_args()

    path = Path(args.logfile).expanduser()
    if not path.exists():
        raise SystemExit(f"No such file: {path}")

    values = parse(path.read_text(errors="replace"))
    missing = [f for f in PATTERNS if f not in values]
    if missing:
        raise SystemExit(
            f"Could not find {', '.join(missing)} in {path}.\n"
            "If the app registration already existed, the secret was not "
            "reprinted — delete the app and re-run, or add a secret in the portal."
        )

    from app import create_app, db
    from app.models.tenant import Tenant

    app = create_app()
    with app.app_context():
        existing = Tenant.query.filter_by(tenant_id=values["tenant_id"]).first()
        if existing:
            existing.name = args.name
            existing.client_id = values["client_id"]
            existing.client_secret = values["client_secret"]
            action = "updated"
        else:
            tenant = Tenant(name=args.name, tenant_id=values["tenant_id"],
                            client_id=values["client_id"])
            tenant.client_secret = values["client_secret"]
            db.session.add(tenant)
            action = "added"
        db.session.commit()

    # Only the identifiers, never the secret.
    print(f"{action} tenant {args.name!r}")
    print(f"  tenant id : {values['tenant_id']}")
    print(f"  client id : {values['client_id']}")
    print(f"  secret    : stored encrypted, not displayed")

    if not args.keep:
        path.unlink()
        print(f"\nDeleted {path} — it contained a live secret in plain text.")
    else:
        print(f"\n{path} still contains a live secret in plain text. Delete it "
              "when you are done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
