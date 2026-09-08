"""Encryption for stored tenant client secrets.

Secrets previously sat in plaintext in config.json. Holding several clients'
credentials in one database makes that materially worse, so they are encrypted
at rest with a key derived from SECRET_KEY.

This protects against someone reading the database file — a stray backup, a
snapshot, a mounted disk. It does not protect against someone who already has
the application's environment, since the key is derivable from it. That is the
honest limit of application-level encryption without a separate key store.
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


class SecretUnreadable(Exception):
    """Stored secret could not be decrypted — usually SECRET_KEY changed."""


def _fernet():
    secret = current_app.config.get("SECRET_KEY") or ""
    if not secret:
        raise SecretUnreadable("SECRET_KEY is not set")
    # Fernet needs 32 url-safe base64 bytes; SECRET_KEY is an arbitrary string.
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    return Fernet(key)


def encrypt(plaintext: str) -> str:
    if plaintext is None:
        return None
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        raise SecretUnreadable(
            "Stored secret could not be decrypted. This usually means SECRET_KEY "
            "changed since it was saved — re-enter the client secret to fix it."
        )
