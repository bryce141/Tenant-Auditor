from flask import Blueprint, render_template, redirect, url_for, current_app, jsonify
from app.auth.graph_auth import get_active_tenant, has_credentials
from app.models.report import Report, ReportCheck
from app.services.comparison import compare, find_previous, headline
from app.services.formatting import distinct_history
from app.services.scoring import calculate_security_score
from app.services.report_runner import start_full_run, get_latest_report, get_run_progress

bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")


@bp.route("/")
def index():
    if not has_credentials():
        return redirect(url_for("landing.index"))

    tenant = get_active_tenant()
    scope = tenant.tenant_id if tenant else None

    # Latest complete report per category for summary cards
    latest = {cat: get_latest_report(cat, scope) for cat in
              ["identity", "conditional_access", "mail_security", "licensing", "users", "sharepoint", "exchange", "groups"]}

    # Security score from the latest security-related reports
    security_checks = []
    for cat in ["identity", "conditional_access", "mail_security"]:
        r = latest.get(cat)
        if r:
            security_checks.extend(r.checks)

    # Use the shared calculation: summing points_possible by hand counts
    # skipped checks in the denominator and reports a lower score here than the
    # report itself does.
    score = calculate_security_score(security_checks)["overall"] if security_checks else None

    # Alert counts
    alerts = _build_alerts(latest)

    # Score history for chart (from full or identity reports)
    history_q = Report.query.filter(Report.report_type.in_(["full", "identity"]),
                                    Report.status == "complete", Report.score != None)
    if scope:
        history_q = history_q.filter(Report.tenant_id == scope)
    # One point per day: a full audit writes several reports seconds apart,
    # which otherwise draws a flat line against a repeated axis label.
    history_reports = distinct_history(history_q.order_by(Report.created_at.asc()).limit(60).all())
    history = [{"date": r.created_at.strftime("%-d %b"), "score": r.score} for r in history_reports]
    if len(history) < 2:
        history = []  # a single point is not a trend

    # Recent reports (any type, last 10)
    recent_q = Report.query.filter_by(status="complete")
    if scope:
        recent_q = recent_q.filter(Report.tenant_id == scope)
    recent = recent_q.order_by(Report.created_at.desc()).limit(10).all()

    # Extract MS Secure Score check
    secure_score_check = None
    identity_report = latest.get("identity")
    if identity_report:
        for c in identity_report.checks:
            if c.check_name == "secure_score":
                secure_score_check = c
                break

    # What moved since the previous full audit. Compared on full runs only,
    # since a category re-run would otherwise read as everything else vanishing.
    full_q = Report.query.filter_by(report_type="full", status="complete")
    if scope:
        full_q = full_q.filter(Report.tenant_id == scope)
    latest_full = full_q.order_by(Report.created_at.desc()).first()
    diff = compare(latest_full, find_previous(latest_full, Report)) if latest_full else None

    return render_template("dashboard.html",
                           tenant=tenant,
                           score=score,
                           latest=latest,
                           alerts=alerts,
                           history=history,
                           recent=recent,
                           diff=diff,
                           diff_headline=headline(diff),
                           # A tenant with no reports at all gets a first-run
                           # screen rather than a grid of empty tiles.
                           first_run=not recent,
                           secure_score_check=secure_score_check)


@bp.route("/api/run/full", methods=["POST"])
def run_full():
    start_full_run(current_app._get_current_object(), get_active_tenant())
    return {"status": "started"}


@bp.route("/api/progress")
def progress():
    return jsonify(get_run_progress())


def _build_alerts(latest):
    alerts = []

    # Inactive licensed users
    r = latest.get("users")
    if r:
        for c in r.checks:
            if c.check_name == "user_activity" and c.issues:
                alerts.append({"type": "warn", "category": "Users", "message": f"{len(c.issues)} licensed users inactive 90+ days", "url": "/users"})

    # Unused licenses
    r = latest.get("licensing")
    if r:
        for c in r.checks:
            if c.check_name == "license_summary" and c.issues:
                alerts.append({"type": "warn", "category": "Licensing", "message": f"{len(c.issues)} SKUs with unassigned licenses", "url": "/licensing"})

    # Mailboxes near quota
    r = latest.get("exchange")
    if r:
        for c in r.checks:
            if c.check_name == "mailbox_usage" and c.issues:
                alerts.append({"type": "warn", "category": "Exchange", "message": f"{len(c.issues)} mailboxes near quota", "url": "/exchange"})

    # Ownerless groups
    r = latest.get("groups")
    if r:
        for c in r.checks:
            if c.check_name == "groups" and c.details:
                ownerless = c.details.get("ownerless", [])
                if ownerless:
                    alerts.append({"type": "warn", "category": "Groups", "message": f"{len(ownerless)} groups have no owners", "url": "/groups"})

    # External sharing
    r = latest.get("sharepoint")
    if r:
        for c in r.checks:
            if c.check_name == "external_sharing" and c.status in ("warn", "fail"):
                alerts.append({"type": "fail", "category": "SharePoint", "message": c.summary, "url": "/sharepoint"})

    # Failed security checks
    r_list = [latest.get(cat) for cat in ["identity", "conditional_access", "mail_security"] if latest.get(cat)]
    fail_count = sum(1 for r in r_list for c in r.checks if c.status == "fail")
    if fail_count:
        alerts.append({"type": "fail", "category": "Security", "message": f"{fail_count} security checks failing", "url": "/security"})

    return alerts
