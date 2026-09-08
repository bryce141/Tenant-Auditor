from flask import Blueprint, render_template, current_app, jsonify
from app.auth.graph_auth import get_active_tenant
from app.services.report_runner import start_category_run, get_latest_report, get_running_report

bp = Blueprint("groups", __name__, url_prefix="/groups")


@bp.route("/")
def index():
    tenant = get_active_tenant()
    scope = tenant.tenant_id if tenant else None
    report = get_latest_report("groups", scope)
    running = get_running_report("groups", scope) is not None
    return render_template("groups/index.html", report=report, running=running)


@bp.route("/api/run", methods=["POST"])
def run():
    tenant = get_active_tenant()
    if get_running_report("groups", tenant.tenant_id if tenant else None):
        return jsonify({"status": "already_running"}), 409
    start_category_run("groups", current_app._get_current_object(), tenant)
    return jsonify({"status": "started"})


@bp.route("/api/status")
def status():
    tenant = get_active_tenant()
    scope = tenant.tenant_id if tenant else None
    running = get_running_report("groups", scope)
    latest = get_latest_report("groups", scope)
    return jsonify({"running": running is not None,
                    "last_run": latest.created_at.isoformat() if latest else None})
