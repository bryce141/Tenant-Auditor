from flask import Blueprint, render_template, current_app, jsonify
from app.auth.graph_auth import get_active_tenant
from app.services.report_runner import start_category_run, get_latest_report, get_running_report

bp = Blueprint("sharepoint", __name__, url_prefix="/sharepoint")


@bp.route("/")
def index():
    tenant = get_active_tenant()
    scope = tenant.tenant_id if tenant else None
    report = get_latest_report("sharepoint", scope)
    running = get_running_report("sharepoint", scope) is not None
    return render_template("sharepoint/index.html", report=report, running=running)


@bp.route("/api/run", methods=["POST"])
def run():
    tenant = get_active_tenant()
    if get_running_report("sharepoint", tenant.tenant_id if tenant else None):
        return jsonify({"status": "already_running"}), 409
    start_category_run("sharepoint", current_app._get_current_object(), tenant)
    return jsonify({"status": "started"})


@bp.route("/api/status")
def status():
    tenant = get_active_tenant()
    scope = tenant.tenant_id if tenant else None
    running = get_running_report("sharepoint", scope)
    latest = get_latest_report("sharepoint", scope)
    return jsonify({"running": running is not None,
                    "last_run": latest.created_at.isoformat() if latest else None})
