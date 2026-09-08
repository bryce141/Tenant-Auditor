"""Shared test helpers.

Every route now requires a session, so tests that exercise routes need a signed-
in client. `signed_in_client(app)` creates the administrator and logs in, which
keeps the auth requirement from leaking assertions into unrelated tests.
"""
from app import db

TEST_PASSWORD = "test-password-long-enough"


def create_admin(app, username="tester", password=TEST_PASSWORD):
    from app.models.user import AdminUser

    with app.app_context():
        if AdminUser.query.filter_by(username=username).first():
            return
        user = AdminUser(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()


def signed_in_client(app, username="tester", password=TEST_PASSWORD):
    """A test client with an authenticated session."""
    create_admin(app, username, password)
    client = app.test_client()
    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == 302, "test helper failed to sign in"
    return client
