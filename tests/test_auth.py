"""Tests for authentication.

Before this existed, every route was public: an unauthenticated request to
/tenants/ returned directory and client IDs, and POST /dashboard/api/run/full
returned 200 and ran an audit. These pin that shut.
"""
import os

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app import create_app, db  # noqa: E402
from app.auth import session_auth  # noqa: E402
from app.models.tenant import Tenant  # noqa: E402
from app.models.user import AdminUser, password_problem  # noqa: E402

PASSWORD = "correct-horse-battery"


@pytest.fixture
def app():
    application = create_app()
    application.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
                              SECRET_KEY="test-key", TESTING=True,
                              WTF_CSRF_ENABLED=False)
    with application.app_context():
        db.drop_all()
        db.create_all()
        session_auth.reset_all_failures()
        yield application


def add_admin(app, username="admin", password=PASSWORD):
    with app.app_context():
        user = AdminUser(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()


def add_tenant(app):
    with app.app_context():
        t = Tenant(name="Contoso", tenant_id="dir-secret-1234", client_id="client-secret-5678")
        t.client_secret = "s"
        db.session.add(t)
        db.session.commit()


def sign_in(client, username="admin", password=PASSWORD):
    return client.post("/login", data={"username": username, "password": password})


# ------------------------------------------------------- the original hole

PROTECTED = ["/dashboard/", "/security/", "/tenants/", "/reports/", "/settings/",
             "/licensing/", "/users/", "/sharepoint/", "/exchange/", "/groups/"]


@pytest.mark.parametrize("path", PROTECTED)
def test_pages_require_a_session(app, path):
    add_admin(app)
    resp = app.test_client().get(path)

    assert resp.status_code in (302, 401), f"{path} served without a session"
    if resp.status_code == 302:
        assert "/login" in resp.headers["Location"]


def test_tenant_identifiers_are_not_exposed_to_anonymous_visitors(app):
    """The exact leak that motivated this: directory and client IDs in the page."""
    add_admin(app)
    add_tenant(app)

    body = app.test_client().get("/tenants/", follow_redirects=True).get_data(as_text=True)

    assert "dir-secret-1234" not in body
    assert "client-secret-5678" not in body


def test_anonymous_cannot_trigger_an_audit(app):
    """This returned 200 and actually ran an audit."""
    add_admin(app)
    resp = app.test_client().post("/dashboard/api/run/full")
    assert resp.status_code in (302, 401)
    assert resp.status_code != 200


def test_anonymous_cannot_delete_a_report(app):
    add_admin(app)
    resp = app.test_client().delete("/reports/api/delete/anything")
    assert resp.status_code in (302, 401)


def test_anonymous_cannot_write_tenant_credentials(app):
    add_admin(app)
    resp = app.test_client().post("/tenants/api/save", json={
        "name": "Evil", "tenant_id": "x", "client_id": "y", "client_secret": "z"})
    assert resp.status_code in (302, 401)
    with app.app_context():
        assert Tenant.query.count() == 0


def test_every_endpoint_is_covered_by_the_guard(app):
    """Fail-closed: a new route must not be reachable unless declared public."""
    add_admin(app)
    client = app.test_client()

    unprotected = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint in session_auth.PUBLIC_ENDPOINTS or rule.endpoint == "static":
            continue
        if "GET" not in rule.methods or rule.arguments:
            continue
        resp = client.get(str(rule))
        if resp.status_code == 200:
            unprotected.append(str(rule))

    assert not unprotected, f"reachable without a session: {unprotected}"


# ------------------------------------------------------------ signing in

def test_valid_credentials_sign_in(app):
    add_admin(app)
    client = app.test_client()

    resp = sign_in(client)

    assert resp.status_code == 302
    assert "/dashboard" in resp.headers["Location"]
    assert client.get("/dashboard/").status_code == 200


def test_wrong_password_is_rejected(app):
    add_admin(app)
    client = app.test_client()

    sign_in(client, password="wrong-password-here")

    assert client.get("/dashboard/").status_code == 302


def test_failure_message_does_not_reveal_whether_the_user_exists(app):
    """Differing responses would let someone enumerate accounts."""
    add_admin(app)
    client = app.test_client()

    wrong_pw = sign_in(client, password="wrong-password-here").get_data(as_text=True)
    session_auth.reset_all_failures()
    no_user = sign_in(client, username="ghost", password="wrong-password-here").get_data(as_text=True)

    assert "Incorrect username or password" in wrong_pw
    assert wrong_pw == no_user


def test_logout_ends_the_session(app):
    add_admin(app)
    client = app.test_client()
    sign_in(client)
    assert client.get("/dashboard/").status_code == 200

    client.post("/logout")

    assert client.get("/dashboard/").status_code == 302


def test_logout_is_not_reachable_by_get(app):
    """A GET logout can be fired by any <img> tag on another site."""
    add_admin(app)
    client = app.test_client()
    sign_in(client)

    assert client.get("/logout").status_code == 405
    assert client.get("/dashboard/").status_code == 200, "still signed in"


# --------------------------------------------------------- lockout

def test_repeated_failures_lock_the_client_out(app):
    add_admin(app)
    client = app.test_client()

    for _ in range(session_auth.MAX_ATTEMPTS):
        sign_in(client, password="wrong-password-here")

    resp = sign_in(client)  # correct password, but locked out
    assert resp.status_code == 429
    assert "Too many attempts" in resp.get_data(as_text=True)


def test_successful_login_clears_the_failure_count(app):
    """Otherwise a few typos followed by a success would still lock you out later."""
    add_admin(app)
    client = app.test_client()

    for _ in range(session_auth.MAX_ATTEMPTS - 1):
        sign_in(client, password="wrong-password-here")
    sign_in(client)                      # succeeds, resetting the counter
    client.post("/logout")

    # The counter having reset, this many failures must not lock the account.
    for _ in range(session_auth.MAX_ATTEMPTS - 1):
        sign_in(client, password="wrong-password-here")

    resp = sign_in(client)
    assert resp.status_code == 302, "counter did not reset after a successful login"
    assert client.get("/dashboard/").status_code == 200


# --------------------------------------------------------- first-run setup

def test_install_without_an_admin_forces_setup(app):
    """Adding auth must not leave a fresh install as open as it was."""
    client = app.test_client()

    for path in ("/dashboard/", "/tenants/", "/reports/"):
        resp = client.get(path)
        assert resp.status_code == 302
        assert "/setup" in resp.headers["Location"], f"{path} did not redirect to setup"


def test_setup_creates_the_admin_and_signs_in(app):
    client = app.test_client()

    resp = client.post("/setup", data={"username": "bryce", "password": PASSWORD,
                                       "confirm": PASSWORD})

    assert resp.status_code == 302
    with app.app_context():
        assert AdminUser.query.count() == 1
    assert client.get("/dashboard/").status_code == 200


def test_setup_is_closed_once_an_admin_exists(app):
    """Otherwise anyone could create a second administrator."""
    add_admin(app)
    client = app.test_client()

    assert client.get("/setup").status_code == 302
    client.post("/setup", data={"username": "attacker", "password": PASSWORD,
                                "confirm": PASSWORD})
    with app.app_context():
        assert AdminUser.query.count() == 1
        assert AdminUser.query.filter_by(username="attacker").first() is None


def test_setup_rejects_mismatched_passwords(app):
    client = app.test_client()
    client.post("/setup", data={"username": "bryce", "password": PASSWORD, "confirm": "different"})
    with app.app_context():
        assert AdminUser.query.count() == 0


# --------------------------------------------------------- passwords

def test_password_is_stored_hashed_not_in_the_clear(app):
    add_admin(app)
    with app.app_context():
        user = AdminUser.query.first()
        assert PASSWORD not in user.password_hash
        assert user.password_hash.startswith("scrypt:")
        assert user.check_password(PASSWORD)
        assert not user.check_password("nearly-right")


@pytest.mark.parametrize("bad", ["", "short", "password1234", "abcdefghijk"])
def test_weak_passwords_are_refused(bad):
    assert password_problem(bad) is not None


def test_a_long_passphrase_is_accepted():
    assert password_problem("a genuinely long passphrase") is None


# --------------------------------------------------------- open redirect

@pytest.mark.parametrize("target", ["https://evil.example.com/phish",
                                    "//evil.example.com",
                                    "http://evil.example.com"])
def test_next_cannot_redirect_off_site(app, target):
    """An attacker-controlled ?next= would make login a phishing primitive."""
    add_admin(app)
    client = app.test_client()

    resp = client.post(f"/login?next={target}",
                       data={"username": "admin", "password": PASSWORD})

    assert "evil.example.com" not in resp.headers["Location"]


def test_next_still_works_for_internal_paths(app):
    add_admin(app)
    client = app.test_client()

    resp = client.post("/login?next=/security/",
                       data={"username": "admin", "password": PASSWORD})

    assert resp.headers["Location"].endswith("/security/")


# --------------------------------------------------------- cookie hardening

def test_session_cookie_is_hardened(app):
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
