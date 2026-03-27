from flask import Blueprint, render_template, current_app, jsonify
from app.services.report_runner import start_category_run, get_latest_report, get_running_report

bp = Blueprint("users", __name__, url_prefix="/users")


@bp.route("/")
def index():
    report = get_latest_report("users")
    running = get_running_report("users") is not None
    return render_template("users/index.html", report=report, running=running)


@bp.route("/api/run", methods=["POST"])
def run():
    if get_running_report("users"):
        return jsonify({"status": "already_running"}), 409
    start_category_run("users", current_app._get_current_object())
    return jsonify({"status": "started"})


@bp.route("/api/status")
def status():
    running = get_running_report("users")
    latest = get_latest_report("users")
    return jsonify({"running": running is not None,
                    "last_run": latest.created_at.isoformat() if latest else None})
