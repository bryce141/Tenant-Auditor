import os
import json
import msal
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

SCOPE = ["https://graph.microsoft.com/.default"]


def _load_credentials():
    """Load credentials from config.json, falling back to env vars."""
    data_dir = Path(os.getenv("DATA_DIR", "."))
    config_path = data_dir / "config.json"
    if config_path.exists():
        try:
            with open(config_path) as f:
                cfg = json.load(f)
                if cfg.get("tenant_id") and cfg.get("client_id") and cfg.get("client_secret"):
                    return cfg["tenant_id"], cfg["client_id"], cfg["client_secret"]
        except Exception:
            pass
    return (
        os.getenv("TENANT_ID", ""),
        os.getenv("CLIENT_ID", ""),
        os.getenv("CLIENT_SECRET", ""),
    )


def get_token():
    tenant_id, client_id, client_secret = _load_credentials()
    if not all([tenant_id, client_id, client_secret]):
        raise Exception("Tenant credentials not configured. Visit /settings to connect your tenant.")

    msal_app = msal.ConfidentialClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret,
    )
    result = msal_app.acquire_token_for_client(scopes=SCOPE)
    if "access_token" in result:
        return result["access_token"], tenant_id
    raise Exception(f"Auth failed: {result.get('error_description', result.get('error', 'Unknown error'))}")


def get_headers():
    token, tenant_id = get_token()
    return {"Authorization": f"Bearer {token}"}, tenant_id


def has_credentials():
    tenant_id, client_id, client_secret = _load_credentials()
    return bool(tenant_id and client_id and client_secret)


def save_credentials(tenant_id, client_id, client_secret):
    data_dir = Path(os.getenv("DATA_DIR", "."))
    data_dir.mkdir(exist_ok=True)
    config_path = data_dir / "config.json"
    with open(config_path, "w") as f:
        json.dump({"tenant_id": tenant_id, "client_id": client_id, "client_secret": client_secret}, f)
    os.environ["TENANT_ID"] = tenant_id
    os.environ["CLIENT_ID"] = client_id
    os.environ["CLIENT_SECRET"] = client_secret
