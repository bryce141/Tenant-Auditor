import os
import json
import msal
from pathlib import Path
from dotenv import load_dotenv
from flask import session

load_dotenv()

SCOPE = ["https://graph.microsoft.com/.default"]
SESSION_KEY = "active_tenant_id"


# ---------------------------------------------------------------------------
# Tenant selection
# ---------------------------------------------------------------------------

def get_active_tenant():
    """The Tenant selected for this browser session.

    Falls back to the only tenant when exactly one exists, so a single-tenant
    install never has to pick one. Returns None if none are configured.
    """
    from app.models.tenant import Tenant

    tenant_id = session.get(SESSION_KEY) if session else None
    if tenant_id:
        tenant = db_get(Tenant, tenant_id)
        if tenant:
            return tenant

    tenants = Tenant.query.order_by(Tenant.name).all()
    return tenants[0] if len(tenants) == 1 else None


def db_get(model, pk):
    from app import db
    return db.session.get(model, pk)


def set_active_tenant(tenant_id):
    session[SESSION_KEY] = tenant_id


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

def _load_credentials():
    """Legacy single-tenant credentials from config.json, then env vars.

    Retained so an existing install keeps working before its config.json has
    been imported into the tenants table.
    """
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


def resolve_credentials(tenant=None):
    """Credentials for an explicit Tenant, the active one, or the legacy config."""
    if tenant is not None:
        return tenant.credentials()

    try:
        active = get_active_tenant()
    except RuntimeError:
        active = None  # no request/app context, e.g. a background thread
    if active is not None:
        return active.credentials()

    return _load_credentials()


# ---------------------------------------------------------------------------
# Token acquisition
# ---------------------------------------------------------------------------

def acquire_token(tenant_id, client_id, client_secret):
    """Client-credentials token for the given app registration."""
    if not all([tenant_id, client_id, client_secret]):
        raise Exception("Tenant credentials not configured. Add a tenant under Settings.")

    msal_app = msal.ConfidentialClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret,
    )
    result = msal_app.acquire_token_for_client(scopes=SCOPE)
    if "access_token" in result:
        return result["access_token"], tenant_id
    raise Exception(f"Auth failed: {result.get('error_description', result.get('error', 'Unknown error'))}")


def get_token(tenant=None):
    return acquire_token(*resolve_credentials(tenant))


def get_headers(tenant=None):
    token, tenant_id = get_token(tenant)
    return {"Authorization": f"Bearer {token}"}, tenant_id


def has_credentials():
    from app.models.tenant import Tenant

    try:
        if Tenant.query.count():
            return True
    except Exception:
        pass  # table may not exist yet on first boot
    tenant_id, client_id, client_secret = _load_credentials()
    return bool(tenant_id and client_id and client_secret)


# ---------------------------------------------------------------------------
# Legacy single-tenant write path, kept for the existing settings page
# ---------------------------------------------------------------------------

def save_credentials(tenant_id, client_id, client_secret):
    data_dir = Path(os.getenv("DATA_DIR", "."))
    data_dir.mkdir(exist_ok=True)
    with open(data_dir / "config.json", "w") as f:
        json.dump({"tenant_id": tenant_id, "client_id": client_id,
                   "client_secret": client_secret}, f)
    os.environ["TENANT_ID"] = tenant_id
    os.environ["CLIENT_ID"] = client_id
    os.environ["CLIENT_SECRET"] = client_secret


def import_legacy_config():
    """Move a config.json tenant into the tenants table, once.

    Runs at startup so upgrading installs keep their tenant without re-entering
    it. The file is left in place; it simply stops being the source of truth.
    """
    from app import db
    from app.models.tenant import Tenant

    if Tenant.query.count():
        return None

    tenant_id, client_id, client_secret = _load_credentials()
    if not all([tenant_id, client_id, client_secret]):
        return None

    tenant = Tenant(name="Default tenant", tenant_id=tenant_id, client_id=client_id)
    tenant.client_secret = client_secret
    db.session.add(tenant)
    db.session.commit()
    return tenant
