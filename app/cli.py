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
"""
import sys

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
                           f"{(o.app_display_name or c.app_id or '?')[:26]:<26} "
                           f"{c.client_app_type or '-':<26} {c.device_platform or '-':<12} "
                           f"{c.country or '-'}")

    if failures:
        raise SystemExit(1)


def register(app):
    app.cli.add_command(audit_command)
    app.cli.add_command(digest_command)
    app.cli.add_command(scheduled_run_command)
    app.cli.add_command(ca_corpus_command)
