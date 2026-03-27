import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-prod")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///tenant_auditor.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    TENANT_ID = os.getenv("TENANT_ID", "")
    CLIENT_ID = os.getenv("CLIENT_ID", "")
    CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")

    DATA_DIR = Path(os.getenv("DATA_DIR", "."))
    CONFIG_PATH = DATA_DIR / "config.json"
