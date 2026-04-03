from flask import Blueprint, render_template, redirect, url_for, current_app, jsonify
from app.auth.graph_auth import has_credentials
from app.models.report import Report, ReportCheck
from app.services.report_runner import start_full_run, get_latest_report, get_run_progress

bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")


@bp.route("/")
def index():
    if not has_credentials():
        return redirect(url_for("landing.index"))

    # Latest complete report per category for summary cards
    latest = {cat: get_latest_report(cat) for cat in
              ["identity", "conditional_access", "mail_security", "licensing", "users", "sharepoint", "exchange", "groups"]}

    # Security score from the latest security-related reports
    security_checks = []
    for cat in ["identity", "conditional_access", "mail_security"]:
        r = latest.get(cat)
        if r:
            security_checks.extend(r.checks)

    score = None
    if security_checks:
        earned = sum(c.points_earned for c in security_checks if c.points_earned is not None)
        possible = sum(c.points_possible for c in security_checks if c.points_possible is not None)
        score = round((earned / possible) * 100) if possible else 0

    # Alert counts
    alerts = _build_alerts(latest)

    # Score history for chart (from full or identity reports)
    history_reports = (Report.query
                       .filter(Report.report_type.in_(["full", "identity"]), Report.status == "complete", Report.score != None)
                       .order_by(Report.created_at.asc())
                       .limit(20).all())
    history = [{"date": r.created_at.strftime("%b %d"), "score": r.score} for r in history_reports]

    # Recent reports (any type, last 10)
    recent = (Report.query
              .filter_by(status="complete")
              .order_by(Report.created_at.desc())
              .limit(10).all())

    # Extract MS Secure Score check
    secure_score_check = None
    identity_report = latest.get("identity")
    if identity_report:
        for c in identity_report.checks:
            if c.check_name == "secure_score":
                secure_score_check = c
                break

    return render_template("dashboard.html",
                           score=score,
                           latest=latest,
                           alerts=alerts,
                           history=history,
                           recent=recent,
                           secure_score_check=secure_score_check)


@bp.route("/api/run/full", methods=["POST"])
def run_full():
    start_full_run(current_app._get_current_object())
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
