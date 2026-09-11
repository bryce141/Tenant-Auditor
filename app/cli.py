"""Command-line entry points, for running audits on a schedule.

Scheduling lives outside the app on purpose. An in-process scheduler only runs
while the web process is alive, and a host that sleeps an idle service would
stop auditing without telling anyone — the failure mode of a security tool
silently not running is worse than the inconvenience of a crontab entry.

    flask audit                    # audit every tenant
    flask audit --tenant Contoso   # just one
    flask digest                   # email the summary
    flask digest --dry-run         # print it instead of sending
    flask scheduled-run            # audit everything, then send the digest
    flask ca-corpus --tenant X     # sign-in corpus stats for the CA simulator
    flask ca-validate --tenant X   # prove the CA engine against Microsoft
    flask ca-impact draft.json     # what a draft policy would break
"""
import sys
from pathlib import Path

import click
from flask.cli import with_appcontext

from app.models.tenant import Tenant


def _resolve(name):
    """Tenants to operate on. An unmatched name is an error, not an empty run."""
    tenants = Tenant.query.order_by(Tenant.name).all()
    if not name:
        return tenants
    matches = [t for t in tenants if name.lower() in t.name.lower()]
    if not matches:
        known = ", ".join(t.name for t in tenants) or "none configured"
        raise click.ClickException(f"No tenant matching {name!r}. Known: {known}")
    return matches


@click.command("audit")
@click.option("--tenant", help="only audit tenants matching this name")
@with_appcontext
def audit_command(tenant):
    """Run a full audit for every configured tenant."""
    from flask import current_app
    from app.services.report_runner import run_full

    tenants = _resolve(tenant)
    if not tenants:
        click.echo("No tenants configured.")
        return

    failures = 0
    for t in tenants:
        click.echo(f"auditing {t.name} ({t.tenant_id})… ", nl=False)
        try:
            # Synchronous here, unlike the web path: cron wants a process that
            # exits when the work is done and a status code it can alert on.
            report_id = run_full(current_app.app_context(), t)
        except Exception as e:
            failures += 1
            click.echo(f"ERROR {e}")
            continue

        from app import db
        from app.models.report import Report
        report = db.session.get(Report, report_id) if report_id else None
        if report is None:
            failures += 1
            click.echo("ERROR no report produced")
        elif report.status == "failed":
            failures += 1
            click.echo(f"FAILED {report.error}")
        else:
            click.echo(f"done — {report.score}/100")

    if failures:
        raise SystemExit(1)


@click.command("digest")
@click.option("--tenant", help="only include tenants matching this name")
@click.option("--dry-run", is_flag=True, help="print the digest instead of sending it")
@click.option("--base-url", help="dashboard URL to link to from the email")
@with_appcontext
def digest_command(tenant, dry_run, base_url):
    """Email a summary of the most recent audits."""
    from app.services import mailer
    from app.services.digest import build

    tenants = _resolve(tenant)
    if not tenants:
        click.echo("No tenants configured.")
        return

    subject, text, html = build(tenants, base_url=base_url)

    if dry_run:
        click.echo(f"Subject: {subject}\n")
        click.echo(text)
        click.echo("\nSMTP configuration:")
        for k, v in mailer.describe_config().items():
            click.echo(f"  {k}: {v}")
        return

    try:
        sent_to = mailer.send(subject, text, html)
    except mailer.MailNotConfigured as e:
        raise click.ClickException(
            f"{e}\nSet the SMTP_* variables, or use --dry-run to preview.")
    except Exception as e:
        raise click.ClickException(f"Sending failed: {e}")

    click.echo(f"Sent to {', '.join(sent_to)}")


@click.command("scheduled-run")
@click.option("--base-url", help="dashboard URL to link to from the email")
@click.pass_context
def scheduled_run_command(ctx, base_url):
    """Audit every tenant, then email the digest. One crontab line."""
    audit_failed = False
    try:
        ctx.invoke(audit_command, tenant=None)
    except SystemExit:
        # Send the digest anyway: a tenant that failed to audit is exactly what
        # the recipient needs to hear about.
        audit_failed = True

    ctx.invoke(digest_command, tenant=None, dry_run=False, base_url=base_url)

    if audit_failed:
        click.echo("one or more audits failed", err=True)
        sys.exit(1)


@click.command("ca-corpus")
@click.option("--tenant", help="only this tenant (required when several exist)")
@click.option("--days", default=30, show_default=True,
              help="size of the sign-in window")
@click.option("--max-records", type=int,
              help="stop after this many sign-ins (a truncated corpus understates impact)")
@click.option("--show", default=10, show_default=True,
              help="how many of the busiest tuples to print")
@with_appcontext
def ca_corpus_command(tenant, days, max_records, show):
    """Reduce a tenant's sign-in log to distinct CA condition tuples.

    The reduction ratio this prints is the sanity check on the whole simulator:
    if real sign-ins don't collapse to a manageable number of distinct
    condition combinations, evaluating a draft policy against the corpus is not
    cheaper than evaluating it against every sign-in.
    """
    from app.auth.graph_auth import get_headers
    from app.services.graph_client import GraphClient, GraphError
    from app.services.signin_corpus import build_corpus

    tenants = _resolve(tenant)
    if not tenants:
        click.echo("No tenants configured.")
        return

    failures = 0
    for t in tenants:
        click.echo(f"\n{t.name} ({t.tenant_id})")
        click.echo("-" * 70)
        try:
            headers, _ = get_headers(t)
            corpus = build_corpus(GraphClient(headers), days=days,
                                  max_records=max_records)
        except GraphError as e:
            # A tenant without Entra ID P1 has no sign-in logs to read at all,
            # which is a licensing answer rather than a bug. Say which.
            failures += 1
            click.echo(f"  ERROR {e}")
            continue
        except Exception as e:
            failures += 1
            click.echo(f"  ERROR {e}")
            continue

        s = corpus.summary()
        if not s["sign_ins"]:
            click.echo(f"  No sign-ins in the last {days} days.")
            click.echo("  Sign-in logs require Entra ID P1 or P2 — check the licence "
                       "before assuming the window is simply quiet.")
            continue

        click.echo(f"  sign-ins            {s['sign_ins']:,}")
        click.echo(f"  distinct tuples     {s['tuples']:,}")
        click.echo(f"  distinct users      {s['distinct_users']:,}")
        click.echo(f"  reduction ratio     {s['reduction_ratio']}x "
                   f"({s['sign_ins']:,} sign-ins -> {s['tuples']:,} evaluations)")
        click.echo(f"  window              {s['first_seen']} .. {s['last_seen']}")

        if s["truncated"]:
            click.echo("\n  TRUNCATED at --max-records. The window above is the most "
                       "recent slice,\n  not the full period, and impact totals "
                       "computed from it will be low.")

        if not s["ca_data_visible"]:
            click.echo("\n  No appliedConditionalAccessPolicies on any sign-in. The app "
                       "needs\n  Policy.Read.All to see them; without it the engine "
                       "cannot be cross-checked\n  against what the tenant actually did.")

        if s["risk_hidden"]:
            pct = 100 * s["risk_hidden"] / s["sign_ins"]
            click.echo(f"\n  {s['risk_hidden']:,} sign-ins ({pct:.0f}%) report risk as "
                       "'hidden' — no Entra ID P2.\n  Risk-conditioned policies cannot "
                       "be simulated for those.")

        if s["unmapped"]:
            click.echo("\n  UNMAPPED values — the engine is blind to this traffic:")
            for field_name, values in sorted(s["unmapped"].items()):
                for raw, count in sorted(values.items(), key=lambda kv: -kv[1]):
                    click.echo(f"    {field_name:<24} {raw!r} ({count:,} sign-ins)")
            click.echo("  Add these to the maps in services/signin_corpus.py.")

        if show:
            click.echo(f"\n  Busiest {min(show, len(corpus.observations))} tuples:")
            for o in corpus.observations[:show]:
                c = o.conditions
                click.echo(f"    {o.sign_ins:>6,}  {(o.user_principal_name or c.user_id or '?')[:32]:<32} "
                           f"{(o.resource_display_name or c.resource_id or '?')[:26]:<26} "
                           f"{c.client_app_type or '-':<26} {c.device_platform or '-':<12} "
                           f"{c.country or '-'}")

    if failures:
        raise SystemExit(1)


@click.command("ca-validate")
@click.option("--tenant", help="only this tenant (required when several exist)")
@click.option("--days", default=30, show_default=True, help="sign-in window")
@click.option("--max-records", type=int, help="cap the sign-ins fetched")
@click.option("--max-tuples", type=int, default=100, show_default=True,
              help="how many tuples to put through the evaluate endpoint")
@click.option("--show", default=10, show_default=True,
              help="how many disagreements to print")
@with_appcontext
def ca_validate_command(tenant, days, max_records, max_tuples, show):
    """Check the CA engine against Microsoft's What If endpoint.

    Evaluates the tenant's existing policies twice — through our engine and
    through POST /identity/conditionalAccess/evaluate — and diffs the verdicts.
    Exits non-zero on any disagreement, so this can gate a change to the engine.
    """
    from app.auth.graph_auth import get_headers
    from app.services.ca_memberships import MembershipCache, resolve_for_corpus
    from app.services.ca_validation import (crosscheck_applied,
                                        fetch_membership_changes, validate)
    from app.services.graph_client import GraphClient, GraphError
    from app.services.signin_corpus import build_corpus

    tenants = _resolve(tenant)
    if not tenants:
        click.echo("No tenants configured.")
        return

    disagreed = False
    for t in tenants:
        click.echo(f"\n{t.name} ({t.tenant_id})")
        click.echo("-" * 70)
        try:
            headers, tenant_id = get_headers(t)
            client = GraphClient(headers)
            policies = client.get_all("/identity/conditionalAccess/policies")
            corpus = build_corpus(client, days=days, max_records=max_records)
        except GraphError as e:
            click.echo(f"  ERROR {e}")
            disagreed = True
            continue

        if not policies:
            click.echo("  No Conditional Access policies in this tenant — there is "
                       "nothing to\n  validate the engine against. The harness needs a "
                       "tenant with real policies.")
            continue
        if not corpus.observations:
            click.echo(f"  No sign-ins in the last {days} days.")
            continue

        click.echo(f"  {len(policies)} policies, {corpus.total_sign_ins:,} sign-ins, "
                   f"{len(corpus.observations):,} tuples")

        memberships = resolve_for_corpus(client, corpus,
                                         cache=MembershipCache(tenant_id))
        if memberships.unresolved:
            click.echo(f"  {len(memberships.unresolved)} user(s) could not be "
                       "resolved — likely deleted since their sign-in")

        report = validate(client, corpus, policies, memberships,
                          max_tuples=max_tuples)
        s = report.summary()

        click.echo(f"\n  Against Microsoft's What If endpoint")
        click.echo(f"    tuples compared   {s['tuples_compared']:,} "
                   f"({s['coverage'] * 100:.0f}% of sign-ins)")
        click.echo(f"    comparisons       {s['comparisons']:,}")
        click.echo(f"    agreements        {s['agreements']:,}")
        click.echo(f"    disagreements     {len(report.disagreements):,}")
        if s["agreement_rate"] is not None:
            click.echo(f"    agreement rate    {s['agreement_rate'] * 100:.2f}%")
        if s["microsoft_uncertain"]:
            click.echo(f"    both uncertain    {s['microsoft_uncertain']:,} "
                       "(Microsoft returned notEnoughInformation)")

        if s["unsupported"]:
            click.echo("\n  Declared gaps — conditions the engine does not implement:")
            for condition, count in sorted(s["unsupported"].items(),
                                           key=lambda kv: -kv[1]):
                click.echo(f"    {count:>6,}  {condition}")

        if report.disagreements:
            disagreed = True
            click.echo(f"\n  DISAGREEMENTS (first {show}) — "
                       "'they said' names the condition Microsoft blames:")
            for d in report.disagreements[:show]:
                click.echo(f"    {d.policy_name}")
                click.echo(f"      we said applies={d.ours} ({d.our_reason})")
                click.echo(f"      they said applies={d.theirs} ({d.their_reason})")
                click.echo(f"      {d.sign_ins:,} sign-ins: {d.conditions}")

        try:
            named_locations = client.get_all("/identity/conditionalAccess/namedLocations")
        except GraphError:
            named_locations = []
        cross = crosscheck_applied(
            corpus, policies, memberships, named_locations=named_locations,
            membership_changes=fetch_membership_changes(client, days=days))
        cs = cross.summary()
        click.echo("\n  Against what the tenant actually did (sign-in log)")
        click.echo(f"    comparisons       {cs['comparisons']:,}")
        click.echo(f"    agreements        {cs['agreements']:,}")
        click.echo(f"    disagreements     {cs['disagreements']:,}")
        if cs.get("skipped_config_changed"):
            click.echo(f"    skipped           {cs['skipped_config_changed']:,} "
                       "(sign-in predates the policy or a location it uses)")
        if cs["agreement_rate"] is not None:
            click.echo(f"    agreement rate    {cs['agreement_rate'] * 100:.2f}%")
        if cross.disagreements:
            disagreed = True
            for d in cross.disagreements[:show]:
                click.echo(f"    {d.policy_name}: we said applies={d.ours}, "
                           f"{d.their_reason}")
        if cross.ambiguous:
            # Not an engine bug: the tuple key is missing a condition that
            # matters, so sign-ins that should be distinct got merged.
            click.echo(f"\n  {len(cross.ambiguous)} tuple(s) whose own sign-ins "
                       "disagree about whether a policy\n  applied. The tuple key is "
                       "missing a condition — impact numbers built on\n  it will be "
                       "wrong. Affected policies:")
            for item in cross.ambiguous[:show]:
                click.echo(f"    {item['policy_name']}: {item['results']}")

        if report.errors:
            click.echo(f"\n  {len(report.errors)} evaluate call(s) failed:")
            for err in report.errors[:show]:
                click.echo(f"    {err}")

    if disagreed:
        raise SystemExit(1)


@click.command("ca-impact")
@click.argument("policy_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--tenant", help="only this tenant (required when several exist)")
@click.option("--days", default=30, show_default=True, help="sign-in window")
@click.option("--max-records", type=int, help="cap the sign-ins fetched")
@click.option("--show", default=15, show_default=True,
              help="how many affected users to list")
@click.option("--json", "as_json", is_flag=True, help="emit the report as JSON")
@with_appcontext
def ca_impact_command(policy_file, tenant, days, max_records, show, as_json):
    """Report what a draft Conditional Access policy would have broken.

    POLICY_FILE is a Graph conditionalAccessPolicy JSON document. Nothing is
    ever written to the tenant — the draft is evaluated against observed
    sign-ins and discarded.
    """
    import json as jsonlib

    from app.auth.graph_auth import get_headers
    from app.services.ca_impact import assess
    from app.services.ca_memberships import MembershipCache, resolve_for_corpus
    from app.services.graph_client import GraphClient, GraphError
    from app.services.signin_corpus import build_corpus

    draft = jsonlib.loads(Path(policy_file).read_text())

    tenants = _resolve(tenant)
    if len(tenants) > 1:
        names = ", ".join(t.name for t in tenants)
        raise click.ClickException(f"Several tenants configured — pass --tenant. {names}")
    if not tenants:
        raise click.ClickException("No tenants configured.")
    t = tenants[0]

    try:
        headers, tenant_id = get_headers(t)
        client = GraphClient(headers)
        existing = client.get_all("/identity/conditionalAccess/policies")
        corpus = build_corpus(client, days=days, max_records=max_records)
    except GraphError as e:
        raise click.ClickException(str(e))

    if not corpus.observations:
        raise click.ClickException(
            f"No sign-ins in the last {days} days — nothing to simulate against.")

    memberships = resolve_for_corpus(client, corpus, cache=MembershipCache(tenant_id))
    impact = assess(draft, corpus, memberships, existing_policies=existing)
    report = impact.summary()

    if as_json:
        click.echo(jsonlib.dumps(report, indent=2))
        return

    click.echo(f"\n{report['policy_name']}  —  {t.name}")
    click.echo("=" * 70)
    click.echo(f"\n  {impact.headline()}")
    click.echo(f"  out of {report['corpus_sign_ins']:,} sign-ins by "
               f"{report['corpus_users']:,} users over {report['window_days']} days")

    if not impact.enforces:
        click.echo(f"\n  NOTE: this draft is '{report['declared_state']}'. The figures "
                   "above are what it\n  would do once enabled; as written it enforces "
                   "nothing.")

    if report["blocked_sign_ins"]:
        click.echo(f"\n  Blocked outright   {report['blocked_sign_ins']:,} sign-ins, "
                   f"{report['blocked_users']:,} users")

    if report["new_controls"]:
        click.echo("\n  Newly required:")
        for control, counts in report["new_controls"].items():
            click.echo(f"    {control:<32} {counts['sign_ins']:>7,} sign-ins  "
                       f"{counts['users']:>4,} users")

    if report["unchanged_sign_ins"]:
        click.echo(f"\n  {report['unchanged_sign_ins']:,} sign-ins already satisfy an "
                   "equivalent control and\n  would notice no change.")

    if not impact.complete:
        # Loud on purpose: a tuple we could not evaluate might be the one that
        # breaks someone important, so the totals above are floors.
        click.echo(f"\n  INCOMPLETE — {report['unsupported_sign_ins']:,} sign-ins "
                   f"({report['unsupported_users']:,} users) could not be evaluated.")
        click.echo("  The figures above are lower bounds, not totals. Reasons:")
        for reason, count in sorted(report["unsupported_reasons"].items(),
                                    key=lambda kv: -kv[1]):
            click.echo(f"    {count:>7,}  {reason}")

    if report["by_resource"]:
        click.echo("\n  By resource:")
        for name, count in list(report["by_resource"].items())[:10]:
            click.echo(f"    {count:>7,}  {name}")

    if report["by_platform"]:
        click.echo("\n  By device platform:")
        for name, count in list(report["by_platform"].items())[:10]:
            click.echo(f"    {count:>7,}  {name}")

    if report["affected"] and show:
        click.echo(f"\n  Affected users (first {min(show, len(report['affected']))}):")
        for user in report["affected"][:show]:
            marker = "BLOCKED" if user["blocked"] else ", ".join(user["controls"])
            click.echo(f"    {user['sign_ins']:>6,}  "
                       f"{(user['user_principal_name'] or user['user_id'] or '?')[:40]:<40} {marker}")

    click.echo()


def register(app):
    app.cli.add_command(audit_command)
    app.cli.add_command(digest_command)
    app.cli.add_command(scheduled_run_command)
    app.cli.add_command(ca_corpus_command)
    app.cli.add_command(ca_validate_command)
    app.cli.add_command(ca_impact_command)
