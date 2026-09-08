import os
from datetime import timedelta
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


def _truthy(name, default="false"):
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-prod")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///tenant_auditor.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Session cookie ---------------------------------------------------
    # HttpOnly keeps the session out of reach of any script on the page.
    SESSION_COOKIE_HTTPONLY = True
    # Lax stops the cookie riding along on cross-site POST and DELETE, which is
    # what protects the run and delete endpoints from cross-site request
    # forgery without pulling in a CSRF library for a single-operator app.
    SESSION_COOKIE_SAMESITE = "Lax"
    # Off by default so local HTTP works; SESSION_COOKIE_SECURE=true in any
    # deployment served over TLS, or the cookie travels in the clear.
    SESSION_COOKIE_SECURE = _truthy("SESSION_COOKIE_SECURE")
    PERMANENT_SESSION_LIFETIME = timedelta(
        hours=int(os.getenv("SESSION_HOURS", "12")))

    TENANT_ID = os.getenv("TENANT_ID", "")
    CLIENT_ID = os.getenv("CLIENT_ID", "")
    CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")

    DATA_DIR = Path(os.getenv("DATA_DIR", "."))
    CONFIG_PATH = DATA_DIR / "config.json"
