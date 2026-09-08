"""Multi-tenant isolation, credential encryption, and switching."""
import os

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app import create_app, db  # noqa: E402
from app.models.report import Report  # noqa: E402
from app.models.tenant import Tenant  # noqa: E402
from app.services.crypto import SecretUnreadable, decrypt, encrypt  # noqa: E402
from tests.conftest import signed_in_client  # noqa: E402


@pytest.fixture
def app():
    application = create_app()
    application.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
                              SECRET_KEY="test-key", TESTING=True)
    with application.app_context():
        db.drop_all()
        db.create_all()
        yield application


def make_tenant(name, directory_id, secret="s3cret"):
    t = Tenant(name=name, tenant_id=directory_id, client_id=f"client-{name}")
    t.client_secret = secret
    db.session.add(t)
    db.session.commit()
    return t


# ---------------------------------------------------------------- encryption

def test_secret_is_not_stored_in_plaintext(app):
    t = make_tenant("Contoso", "dir-1", secret="super-secret-value")

    assert "super-secret-value" not in t.client_secret_encrypted
    assert t.client_secret == "super-secret-value", "must round-trip"


def test_secret_never_leaves_via_to_dict(app):
    t = make_tenant("Contoso", "dir-1", secret="super-secret-value")
    serialised = str(t.to_dict())

    assert "super-secret-value" not in serialised
    assert "client_secret" not in t.to_dict()


def test_changed_key_reports_clearly_rather_than_returning_junk(app):
    t = make_tenant("Contoso", "dir-1", secret="value")
    ciphertext = t.client_secret_encrypted

    app.config["SECRET_KEY"] = "a-different-key"
    with pytest.raises(SecretUnreadable) as exc:
        decrypt(ciphertext)
    assert "SECRET_KEY" in str(exc.value)


def test_encryption_is_not_deterministic(app):
    """Identical secrets must not produce identical ciphertext."""
    assert encrypt("same") != encrypt("same")


# ---------------------------------------------------------------- isolation

def test_reports_are_scoped_to_the_active_tenant(app):
    from app.services.report_runner import get_latest_report

    make_tenant("Contoso", "dir-1")
    make_tenant("Fabrikam", "dir-2")

    for directory_id, score in (("dir-1", 40), ("dir-2", 90)):
        db.session.add(Report(tenant_id=directory_id, report_type="identity",
                              status="complete", score=score))
    db.session.commit()

    assert get_latest_report("identity", "dir-1").score == 40
    assert get_latest_report("identity", "dir-2").score == 90


def test_unscoped_query_still_sees_everything(app):
    """Passing no tenant is the all-tenants view, not an empty one."""
    from app.services.report_runner import get_latest_report

    db.session.add(Report(tenant_id="dir-1", report_type="identity",
                          status="complete", score=40))
    db.session.commit()
    assert get_latest_report("identity") is not None


def test_reports_page_hides_other_tenants(app):
    a = make_tenant("Contoso", "dir-1")
    make_tenant("Fabrikam", "dir-2")

    db.session.add(Report(tenant_id="dir-1", report_type="full", status="complete", score=1))
    db.session.add(Report(tenant_id="dir-2", report_type="full", status="complete", score=2))
    db.session.commit()

    client = signed_in_client(app)
    with client.session_transaction() as sess:
        sess["active_tenant_id"] = a.id

    html = client.get("/reports/").get_data(as_text=True)
    assert "dir-1" not in html or "dir-2" not in html  # only one tenant's data
    # A stronger assertion: exactly one report row is listed.
    assert html.count("/reports/api/export/") == 2, "one report → one CSV + one HTML link"


# ---------------------------------------------------------------- switching

def test_single_tenant_is_active_without_choosing(app):
    from app.auth.graph_auth import get_active_tenant

    t = make_tenant("Only", "dir-1")
    with app.test_request_context("/"):
        assert get_active_tenant().id == t.id


def test_switching_changes_the_active_tenant(app):
    a = make_tenant("Contoso", "dir-1")
    b = make_tenant("Fabrikam", "dir-2")

    client = signed_in_client(app)
    with client.session_transaction() as sess:
        sess["active_tenant_id"] = a.id

    assert client.post(f"/tenants/switch/{b.id}").status_code == 200
    with client.session_transaction() as sess:
        assert sess["active_tenant_id"] == b.id


def test_switching_to_unknown_tenant_404s(app):
    make_tenant("Contoso", "dir-1")
    assert signed_in_client(app).post("/tenants/switch/nope").status_code == 404


# ---------------------------------------------------------------- management

def test_duplicate_directory_id_is_rejected(app):
    make_tenant("Contoso", "dir-1")
    resp = signed_in_client(app).post("/tenants/api/save", json={
        "name": "Contoso Copy", "tenant_id": "dir-1",
        "client_id": "c", "client_secret": "s"})

    assert resp.status_code == 409
    assert "already configured" in resp.get_json()["error"]


def test_new_tenant_requires_a_secret(app):
    resp = signed_in_client(app).post("/tenants/api/save", json={
        "name": "Contoso", "tenant_id": "dir-1", "client_id": "c"})
    assert resp.status_code == 400


def test_editing_without_a_secret_keeps_the_stored_one(app):
    t = make_tenant("Contoso", "dir-1", secret="original")

    resp = signed_in_client(app).post("/tenants/api/save", json={
        "id": t.id, "name": "Contoso Renamed", "tenant_id": "dir-1",
        "client_id": "client-Contoso", "client_secret": ""})

    assert resp.status_code == 200
    refreshed = db.session.get(Tenant, t.id)
    assert refreshed.name == "Contoso Renamed"
    assert refreshed.client_secret == "original", "blank secret must not wipe it"


def test_delete_keeps_reports_unless_purge_requested(app):
    t = make_tenant("Contoso", "dir-1")
    db.session.add(Report(tenant_id="dir-1", report_type="full", status="complete"))
    db.session.commit()

    signed_in_client(app).delete(f"/tenants/api/delete/{t.id}")

    assert db.session.get(Tenant, t.id) is None
    assert Report.query.filter_by(tenant_id="dir-1").count() == 1, "reports kept by default"


def test_delete_with_purge_removes_reports(app):
    t = make_tenant("Contoso", "dir-1")
    db.session.add(Report(tenant_id="dir-1", report_type="full", status="complete"))
    db.session.commit()

    signed_in_client(app).delete(f"/tenants/api/delete/{t.id}?purge=true")

    assert Report.query.filter_by(tenant_id="dir-1").count() == 0


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
