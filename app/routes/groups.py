from flask import Blueprint, render_template, current_app, jsonify
from app.services.report_runner import start_category_run, get_latest_report, get_running_report

bp = Blueprint("groups", __name__, url_prefix="/groups")


@bp.route("/")
def index():
    report = get_latest_report("groups")
    running = get_running_report("groups") is not None
    return render_template("groups/index.html", report=report, running=running)


@bp.route("/api/run", methods=["POST"])
def run():
    if get_running_report("groups"):
        return jsonify({"status": "already_running"}), 409
    start_category_run("groups", current_app._get_current_object())
    return jsonify({"status": "started"})


@bp.route("/api/status")
def status():
    running = get_running_report("groups")
    latest = get_latest_report("groups")
    return jsonify({"running": running is not None,
                    "last_run": latest.created_at.isoformat() if latest else None})
