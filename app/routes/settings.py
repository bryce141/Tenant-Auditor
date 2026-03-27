import msal
from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from app.auth.graph_auth import has_credentials, save_credentials, _load_credentials

bp = Blueprint("settings", __name__, url_prefix="/settings")


@bp.route("/")
def index():
    tenant_id, client_id, _ = _load_credentials()
    return render_template("settings/index.html",
                           has_credentials=has_credentials(),
                           tenant_id=tenant_id,
                           client_id=client_id)


@bp.route("/api/save", methods=["POST"])
def save():
    data = request.get_json()
    tenant_id = (data.get("tenant_id") or "").strip()
    client_id = (data.get("client_id") or "").strip()
    client_secret = (data.get("client_secret") or "").strip()

    if not all([tenant_id, client_id, client_secret]):
        return jsonify({"error": "All fields are required."}), 400

    save_credentials(tenant_id, client_id, client_secret)
    return jsonify({"status": "saved"})


@bp.route("/api/test", methods=["POST"])
def test_connection():
    data = request.get_json()
    tenant_id = (data.get("tenant_id") or "").strip()
    client_id = (data.get("client_id") or "").strip()
    client_secret = (data.get("client_secret") or "").strip()

    if not all([tenant_id, client_id, client_secret]):
        return jsonify({"error": "All fields are required."}), 400

    try:
        app = msal.ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret,
        )
        result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" in result:
            return jsonify({"status": "ok"})
        return jsonify({"error": result.get("error_description", "Authentication failed.")}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
