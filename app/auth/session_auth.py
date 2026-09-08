"""Login state and the request guard.

The guard is fail-closed: every endpoint requires a session unless it is named
in PUBLIC_ENDPOINTS. Protecting routes with a decorator instead would mean a
route added later is exposed until someone remembers to annotate it, and the
failure is silent. This way forgetting locks people out, which gets noticed
immediately and harms nobody.
"""
import time
from functools import wraps

from flask import current_app, flash, redirect, request, session, url_for

SESSION_KEY = "admin_user_id"

# Reachable without a session. Everything else is not.
PUBLIC_ENDPOINTS = {
    "auth.login",
    "auth.setup",
    "static",
}

# Failed logins per source, in memory. Enough to blunt online guessing against
# a single-operator install; a distributed attempt or a restart resets it, and
# a real deployment behind a proxy should rate limit there too.
_attempts = {}
MAX_ATTEMPTS = 8
LOCKOUT_SECONDS = 300


def _client_key():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def lockout_remaining():
    """Seconds left on a lockout for this client, or 0."""
    record = _attempts.get(_client_key())
    if not record:
        return 0
    count, first_seen = record
    if count < MAX_ATTEMPTS:
        return 0
    elapsed = time.time() - first_seen
    if elapsed >= LOCKOUT_SECONDS:
        _attempts.pop(_client_key(), None)
        return 0
    return int(LOCKOUT_SECONDS - elapsed)


def record_failure():
    key = _client_key()
    count, first_seen = _attempts.get(key, (0, time.time()))
    if time.time() - first_seen > LOCKOUT_SECONDS:
        count, first_seen = 0, time.time()
    _attempts[key] = (count + 1, first_seen)


def clear_failures():
    _attempts.pop(_client_key(), None)


def reset_all_failures():
    """Test hook."""
    _attempts.clear()


def current_user():
    from app.models.user import AdminUser

    user_id = session.get(SESSION_KEY)
    if not user_id:
        return None
    return current_app.extensions["sqlalchemy"].session.get(AdminUser, user_id)


def log_in(user):
    # New session identifier on privilege change, so a session fixed before
    # login can't be reused after it.
    session.clear()
    session[SESSION_KEY] = user.id
    session.permanent = True


def log_out():
    session.clear()


def is_logged_in():
    return session.get(SESSION_KEY) is not None


def install_guard(app):
    """Require a session for every request that isn't explicitly public."""

    @app.before_request
    def _require_login():
        from app.models.user import any_admin_exists

        endpoint = request.endpoint

        # An install with no administrator must not serve anything except the
        # page that creates one — otherwise adding auth would leave a fresh
        # deployment as open as it was before.
        if not any_admin_exists():
            if endpoint in ("auth.setup", "static"):
                return None
            return redirect(url_for("auth.setup"))

        if endpoint in PUBLIC_ENDPOINTS or endpoint is None:
            return None

        if is_logged_in():
            return None

        if request.path.startswith("/") and request.accept_mimetypes.best == "application/json":
            return {"error": "Authentication required"}, 401

        return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))


def login_required(view):
    """Belt-and-braces for anything invoked outside the request guard."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapper
