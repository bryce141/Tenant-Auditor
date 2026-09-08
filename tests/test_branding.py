"""Tests for report branding.

The report is what a client receives, so branding has to survive into it — and
the inputs are user-supplied and land inside HTML, so they have to be handled
as untrusted.
"""
import base64
import io
import os

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from app import create_app, db  # noqa: E402
from app.models.branding import (Branding, encode_logo, get_branding,
                                 logo_problem, normalise_colour)  # noqa: E402
from app.models.report import Report, ReportCheck  # noqa: E402
from app.services.report_export import render_html  # noqa: E402
from tests.conftest import signed_in_client  # noqa: E402

# A one-pixel PNG.
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


@pytest.fixture
def app():
    application = create_app()
    application.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
                              SECRET_KEY="test-key", TESTING=True)
    with application.app_context():
        db.drop_all()
        db.create_all()
        yield application


def make_report(app):
    """Returns the report id — the object itself would detach when the
    context closes, and rendering lazy-loads .checks."""
    with app.app_context():
        r = Report(tenant_id="dir-1", report_type="full", status="complete", score=41)
        db.session.add(r)
        db.session.commit()
        db.session.add(ReportCheck(report_id=r.id, category="identity",
                                   check_name="mfa_registration",
                                   display_name="MFA Registration", status="fail",
                                   points_earned=0, points_possible=20,
                                   summary="0/3 users have MFA registered"))
        db.session.commit()
        return r.id


# --------------------------------------------------------------- validation

@pytest.mark.parametrize("mime", ["image/png", "image/jpeg", "image/webp", "image/gif"])
def test_raster_logos_are_accepted(mime):
    assert logo_problem(mime, PNG) is None


def test_svg_is_refused():
    """SVG can carry script, and reports get opened in clients' browsers."""
    problem = logo_problem("image/svg+xml", b"<svg onload='alert(1)'></svg>")
    assert problem is not None
    assert "SVG" in problem


def test_oversized_logo_is_refused():
    assert "under" in logo_problem("image/png", b"x" * (300 * 1024))


def test_empty_file_is_refused():
    assert logo_problem("image/png", b"") is not None


def test_encode_produces_an_embeddable_data_uri():
    uri = encode_logo("image/png", PNG)
    assert uri.startswith("data:image/png;base64,")
    assert base64.b64decode(uri.split(",", 1)[1]) == PNG


@pytest.mark.parametrize("raw,expected", [
    ("#2563EB", "#2563eb"),
    ("2563eb", "#2563eb"),
    ("", None),
    (None, None),
    ("red", None),
    ("#12345", None),
    ("#zzzzzz", None),
])
def test_colour_normalisation(raw, expected):
    assert normalise_colour(raw) == expected


def test_colour_rejects_css_injection():
    """The colour lands in a style attribute in a document sent to a client."""
    assert normalise_colour("#fff;} body{display:none") is None
    assert normalise_colour("red;background:url(http://evil)") is None


# ------------------------------------------------------------ in the report

def test_report_is_unbranded_but_intact_without_branding(app):
    report_id = make_report(app)
    with app.app_context():
        html = render_html(db.session.get(Report, report_id))
    assert "Microsoft 365 Tenant Security Audit" in html
    assert "Prepared for" not in html


def test_firm_name_and_client_appear(app):
    report_id = make_report(app)
    with app.app_context():
        report = db.session.get(Report, report_id)
        branding = get_branding()
        branding.firm_name = "Acme Security"
        db.session.commit()
        html = render_html(report, branding=branding, client_name="Contoso Ltd")

    assert "Prepared for" in html
    assert "Contoso Ltd" in html
    assert "Acme Security" in html


def test_logo_is_embedded_not_linked(app):
    """A linked logo would break the moment the report leaves this machine."""
    report_id = make_report(app)
    with app.app_context():
        report = db.session.get(Report, report_id)
        branding = get_branding()
        branding.logo_data_uri = encode_logo("image/png", PNG)
        db.session.commit()
        html = render_html(report, branding=branding)

    assert "data:image/png;base64," in html
    assert "<img class=\"logo\"" in html


def test_contact_details_and_footer_note_appear(app):
    report_id = make_report(app)
    with app.app_context():
        report = db.session.get(Report, report_id)
        branding = get_branding()
        branding.contact_email = "security@acme.com"
        branding.website = "acme.com"
        branding.footer_note = "Confidential — for the named client only."
        db.session.commit()
        html = render_html(report, branding=branding)

    assert "security@acme.com" in html
    assert "acme.com" in html
    assert "Confidential" in html


def test_branding_fields_are_escaped(app):
    """Firm name and footer are operator input, but still land in HTML."""
    report_id = make_report(app)
    with app.app_context():
        report = db.session.get(Report, report_id)
        branding = get_branding()
        branding.firm_name = "<script>alert('xss')</script>"
        branding.footer_note = "<img src=x onerror=alert(1)>"
        db.session.commit()
        html = render_html(report, branding=branding, client_name="<b>Client</b>")

    # The escaped text still reads "onerror=alert(1)" — that's fine and inert.
    # What must not survive is an executable tag.
    assert "<script>alert" not in html
    assert "<img src=x" not in html, "an unescaped tag would execute in the client's browser"
    assert "&lt;script&gt;" in html
    assert "&lt;img src=x" in html
    assert "&lt;b&gt;Client&lt;/b&gt;" in html, "client name is escaped too"


def test_branded_report_stays_self_contained(app):
    """The logo must not reintroduce an external request."""
    import re
    report_id = make_report(app)
    with app.app_context():
        report = db.session.get(Report, report_id)
        branding = get_branding()
        branding.firm_name = "Acme"
        branding.logo_data_uri = encode_logo("image/png", PNG)
        db.session.commit()
        html = render_html(report, branding=branding)

    external = re.findall(r'(?:src|href)="(https?://[^"]+)"', html)
    assert [u for u in external if "microsoft.com" not in u] == []


# ------------------------------------------------------------------ the form

def test_saving_branding_persists_it(app):
    client = signed_in_client(app)

    resp = client.post("/settings/branding", data={
        "firm_name": "Acme Security", "contact_email": "hi@acme.com",
        "accent_colour": "#2563eb", "footer_note": "Confidential"},
        content_type="multipart/form-data")

    assert resp.status_code == 302
    with app.app_context():
        b = Branding.query.first()
        assert b.firm_name == "Acme Security"
        assert b.accent_colour == "#2563eb"


def test_uploading_a_logo_stores_a_data_uri(app):
    client = signed_in_client(app)

    resp = client.post("/settings/branding", data={
        "firm_name": "Acme",
        "logo": (io.BytesIO(PNG), "logo.png", "image/png")},
        content_type="multipart/form-data")

    assert resp.status_code == 302
    with app.app_context():
        assert Branding.query.first().logo_data_uri.startswith("data:image/png;base64,")


def test_uploading_an_svg_is_rejected(app):
    client = signed_in_client(app)

    client.post("/settings/branding", data={
        "firm_name": "Acme",
        "logo": (io.BytesIO(b"<svg onload='alert(1)'/>"), "logo.svg", "image/svg+xml")},
        content_type="multipart/form-data")

    with app.app_context():
        assert Branding.query.first().logo_data_uri is None


def test_removing_the_logo(app):
    client = signed_in_client(app)
    with app.app_context():
        b = get_branding()
        b.logo_data_uri = encode_logo("image/png", PNG)
        db.session.commit()

    client.post("/settings/branding", data={"firm_name": "Acme", "remove_logo": "yes"},
                content_type="multipart/form-data")

    with app.app_context():
        assert Branding.query.first().logo_data_uri is None


def test_branding_page_requires_a_session(app):
    assert app.test_client().post("/settings/branding").status_code in (302, 401)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
