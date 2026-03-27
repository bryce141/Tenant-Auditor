from flask import Blueprint, render_template, current_app, jsonify
from app.auth.graph_auth import has_credentials
from app.models.report import Report
from app.services.report_runner import (start_category_run, get_latest_report,
                                         get_running_report, SECURITY_CATEGORIES)

bp = Blueprint("security", __name__, url_prefix="/security")


@bp.route("/")
def index():
    reports = {cat: get_latest_report(cat) for cat in SECURITY_CATEGORIES}
    running = {cat: get_running_report(cat) is not None for cat in SECURITY_CATEGORIES}

    all_checks = []
    for r in reports.values():
        if r:
            all_checks.extend(r.checks)

    earned = sum(c.points_earned for c in all_checks if c.points_earned is not None)
    possible = sum(c.points_possible for c in all_checks if c.points_possible is not None)
    score = round((earned / possible) * 100) if possible else None

    score_history = (Report.query
                     .filter(Report.report_type.in_(list(SECURITY_CATEGORIES)), Report.status == "complete", Report.score != None)
                     .order_by(Report.created_at.asc()).limit(20).all())
    history = [{"date": r.created_at.strftime("%b %d"), "score": r.score, "type": r.report_type}
               for r in score_history]

    return render_template("security/index.html",
                           reports=reports, running=running,
                           all_checks=all_checks, score=score, history=history,
                           has_credentials=has_credentials())


@bp.route("/api/run/<category>", methods=["POST"])
def run(category):
    if category not in SECURITY_CATEGORIES:
        return jsonify({"error": "Invalid category"}), 400
    if get_running_report(category):
        return jsonify({"status": "already_running"}), 409
    start_category_run(category, current_app._get_current_object())
    return jsonify({"status": "started"})


@bp.route("/api/status/<category>")
def status(category):
    running = get_running_report(category)
    latest = get_latest_report(category)
    return jsonify({
        "running": running is not None,
        "last_run": latest.created_at.isoformat() if latest else None,
        "last_score": latest.score if latest else None,
    })
