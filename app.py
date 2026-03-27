import os
import json
import threading
from glob import glob
from pathlib import Path
from flask import Flask, render_template, jsonify, request, redirect, url_for
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

DATA_DIR = Path(os.getenv("DATA_DIR", "."))
CONFIG_PATH = DATA_DIR / "config.json"

_audit_state = {"running": False, "error": None}


# ── Config helpers ─────────────────────────────────────────────────────────────

def load_config() -> dict:
    """Load credentials from data/config.json, falling back to env vars."""
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "tenant_id": os.getenv("TENANT_ID", ""),
        "client_id": os.getenv("CLIENT_ID", ""),
        "client_secret": os.getenv("CLIENT_SECRET", ""),
    }


def has_credentials() -> bool:
    config = load_config()
    return bool(config.get("tenant_id") and config.get("client_id") and config.get("client_secret"))


def apply_config_to_env():
    """Push config values into os.environ so auth.py picks them up."""
    config = load_config()
    if config.get("tenant_id"):
        os.environ["TENANT_ID"] = config["tenant_id"]
        os.environ["CLIENT_ID"] = config["client_id"]
        os.environ["CLIENT_SECRET"] = config["client_secret"]


# ── Audit helpers ──────────────────────────────────────────────────────────────

def _load_runs():
    files = sorted(glob(str(DATA_DIR / "runs" / "*.json")), reverse=True)
    runs = []
    for f in files:
        try:
            with open(f, encoding="utf-8") as fh:
                runs.append(json.load(fh))
        except Exception:
            continue
    return runs


def _run_audit_background():
    from main import run_audit, save_run
    apply_config_to_env()
    _audit_state["running"] = True
    _audit_state["error"] = None
    try:
        tenant_id = os.getenv("TENANT_ID")
        results, score = run_audit()
        save_run(tenant_id, results, score)
    except Exception as e:
        _audit_state["error"] = str(e)
    finally:
        _audit_state["running"] = False


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if not has_credentials():
        return redirect(url_for("setup"))
    apply_config_to_env()
    runs = _load_runs()
    latest = runs[0] if runs else None
    history = [
        {"timestamp": r["timestamp"], "score": r["score"]["overall"]}
        for r in reversed(runs)
    ]
    return render_template("index.html", latest=latest, history=history, state=_audit_state)


@app.route("/setup")
def setup():
    return render_template("setup.html")


@app.route("/api/save-config", methods=["POST"])
def save_config():
    data = request.get_json()
    config = {
        "tenant_id": (data.get("tenant_id") or "").strip(),
        "client_id": (data.get("client_id") or "").strip(),
        "client_secret": (data.get("client_secret") or "").strip(),
    }
    if not all(config.values()):
        return jsonify({"error": "All fields are required."}), 400
    CONFIG_PATH.parent.mkdir(exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f)
    apply_config_to_env()
    return jsonify({"status": "saved"})


@app.route("/api/test-connection", methods=["POST"])
def test_connection():
    data = request.get_json()
    tenant_id = (data.get("tenant_id") or "").strip()
    client_id = (data.get("client_id") or "").strip()
    client_secret = (data.get("client_secret") or "").strip()

    if not all([tenant_id, client_id, client_secret]):
        return jsonify({"error": "All fields are required."}), 400

    try:
        import msal
        msal_app = msal.ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret,
        )
        result = msal_app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" in result:
            return jsonify({"status": "ok"})
        return jsonify({"error": result.get("error_description", "Authentication failed.")}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/run", methods=["POST"])
def trigger_run():
    if _audit_state["running"]:
        return jsonify({"status": "already_running"}), 409
    thread = threading.Thread(target=_run_audit_background, daemon=True)
    thread.start()
    return jsonify({"status": "started"})


@app.route("/api/status")
def audit_status():
    return jsonify(_audit_state)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
