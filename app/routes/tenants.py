"""Managing and switching between audited tenants."""
from flask import Blueprint, jsonify, redirect, render_template, request, url_for

from app import db
from app.auth.graph_auth import acquire_token, get_active_tenant, set_active_tenant
from app.models.report import Report
from app.models.tenant import Tenant
from app.services.crypto import SecretUnreadable

bp = Blueprint("tenants", __name__, url_prefix="/tenants")


@bp.route("/")
def index():
    tenants = Tenant.query.order_by(Tenant.name).all()
    active = get_active_tenant()

    # Latest score per tenant, for the overview table.
    summary = {}
    for t in tenants:
        latest = (Report.query
                  .filter(Report.tenant_id == t.tenant_id,
                          Report.status == "complete",
                          Report.score.isnot(None))
                  .order_by(Report.created_at.desc())
                  .first())
        summary[t.id] = {"score": latest.score if latest else None,
                         "last_run": latest.created_at if latest else None,
                         "report_count": Report.query.filter_by(tenant_id=t.tenant_id).count()}

    return render_template("tenants/index.html", tenants=tenants,
                           active=active, summary=summary)


@bp.route("/switch/<tenant_id>", methods=["POST"])
def switch(tenant_id):
    tenant = db.session.get(Tenant, tenant_id)
    if not tenant:
        return jsonify({"error": "No such tenant"}), 404
    set_active_tenant(tenant.id)
    return jsonify({"status": "switched", "tenant": tenant.to_dict()})


@bp.route("/api/save", methods=["POST"])
def save():
    """Create or update a tenant.

    An omitted secret on update means 'leave it alone', so the form can be
    re-submitted to rename a tenant without re-entering the credential.
    """
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    tenant_id = (data.get("tenant_id") or "").strip()
    client_id = (data.get("client_id") or "").strip()
    client_secret = (data.get("client_secret") or "").strip()
    existing_id = data.get("id")

    if not all([name, tenant_id, client_id]):
        return jsonify({"error": "Name, tenant ID, and client ID are required."}), 400

    tenant = db.session.get(Tenant, existing_id) if existing_id else None

    if tenant is None:
        if not client_secret:
            return jsonify({"error": "Client secret is required for a new tenant."}), 400
        clash = Tenant.query.filter_by(tenant_id=tenant_id).first()
        if clash:
            return jsonify({"error": f"{tenant_id} is already configured as '{clash.name}'."}), 409
        tenant = Tenant(name=name, tenant_id=tenant_id, client_id=client_id)
        tenant.client_secret = client_secret
        db.session.add(tenant)
    else:
        tenant.name = name
        tenant.tenant_id = tenant_id
        tenant.client_id = client_id
        if client_secret:
            tenant.client_secret = client_secret

    db.session.commit()

    # First tenant added becomes the active one.
    if Tenant.query.count() == 1:
        set_active_tenant(tenant.id)

    return jsonify({"status": "saved", "tenant": tenant.to_dict()})


@bp.route("/api/test", methods=["POST"])
def test_connection():
    """Validate credentials against Entra ID before saving.

    An existing tenant may be tested without resupplying its secret.
    """
    data = request.get_json() or {}
    tenant_id = (data.get("tenant_id") or "").strip()
    client_id = (data.get("client_id") or "").strip()
    client_secret = (data.get("client_secret") or "").strip()

    if not client_secret and data.get("id"):
        stored = db.session.get(Tenant, data["id"])
        if stored:
            try:
                client_secret = stored.client_secret
            except SecretUnreadable as e:
                return jsonify({"error": str(e)}), 400

    if not all([tenant_id, client_id, client_secret]):
        return jsonify({"error": "Tenant ID, client ID, and secret are required."}), 400

    try:
        acquire_token(tenant_id, client_id, client_secret)
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@bp.route("/api/delete/<tenant_id>", methods=["DELETE"])
def delete(tenant_id):
    """Remove a tenant. Its reports are kept unless explicitly dropped."""
    tenant = db.session.get(Tenant, tenant_id)
    if not tenant:
        return jsonify({"error": "No such tenant"}), 404

    if (request.args.get("purge") or "").lower() == "true":
        Report.query.filter_by(tenant_id=tenant.tenant_id).delete()

    db.session.delete(tenant)
    db.session.commit()
    return jsonify({"status": "deleted"})
