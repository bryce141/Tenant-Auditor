from flask import Blueprint, render_template, current_app, jsonify
from app.services.report_runner import start_category_run, get_latest_report, get_running_report

bp = Blueprint("sharepoint", __name__, url_prefix="/sharepoint")


@bp.route("/")
def index():
    report = get_latest_report("sharepoint")
    running = get_running_report("sharepoint") is not None
    return render_template("sharepoint/index.html", report=report, running=running)


@bp.route("/api/run", methods=["POST"])
def run():
    if get_running_report("sharepoint"):
        return jsonify({"status": "already_running"}), 409
    start_category_run("sharepoint", current_app._get_current_object())
    return jsonify({"status": "started"})


@bp.route("/api/status")
def status():
    running = get_running_report("sharepoint")
    latest = get_latest_report("sharepoint")
    return jsonify({"running": running is not None,
                    "last_run": latest.created_at.isoformat() if latest else None})
