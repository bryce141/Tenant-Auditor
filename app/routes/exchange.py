from flask import Blueprint, render_template, current_app, jsonify
from app.services.report_runner import start_category_run, get_latest_report, get_running_report

bp = Blueprint("exchange", __name__, url_prefix="/exchange")


@bp.route("/")
def index():
    report = get_latest_report("exchange")
    running = get_running_report("exchange") is not None
    return render_template("exchange/index.html", report=report, running=running)


@bp.route("/api/run", methods=["POST"])
def run():
    if get_running_report("exchange"):
        return jsonify({"status": "already_running"}), 409
    start_category_run("exchange", current_app._get_current_object())
    return jsonify({"status": "started"})


@bp.route("/api/status")
def status():
    running = get_running_report("exchange")
    latest = get_latest_report("exchange")
    return jsonify({"running": running is not None,
                    "last_run": latest.created_at.isoformat() if latest else None})
