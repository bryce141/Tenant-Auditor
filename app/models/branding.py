"""Firm branding applied to client-facing reports.

One row. The report is the thing you hand to a client, so it should carry your
name rather than looking like a screenshot of somebody's internal tool.

The logo is stored as a data URI rather than a file on disk: reports must stay
self-contained (no external requests, so they render offline years later), and
embedding it here means the export needs no filesystem access and no static
route serving user-uploaded content.
"""
import base64
import uuid

from app import db
from app.utils import utcnow

# Raster only. An SVG can carry script, and these logos are embedded in a
# document that gets emailed to clients and opened in their browsers — that is
# not a place to accept arbitrary markup.
ALLOWED_LOGO_TYPES = {
    "image/png": "PNG",
    "image/jpeg": "JPEG",
    "image/webp": "WebP",
    "image/gif": "GIF",
}
MAX_LOGO_BYTES = 200 * 1024  # keeps every generated report small


class Branding(db.Model):
    __tablename__ = "branding"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    firm_name = db.Column(db.String(200), nullable=True)
    logo_data_uri = db.Column(db.Text, nullable=True)
    contact_email = db.Column(db.String(200), nullable=True)
    contact_phone = db.Column(db.String(60), nullable=True)
    website = db.Column(db.String(200), nullable=True)
    accent_colour = db.Column(db.String(7), nullable=True)   # #rrggbb
    footer_note = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    @property
    def is_configured(self):
        return bool(self.firm_name or self.logo_data_uri)

    def to_dict(self):
        return {
            "firm_name": self.firm_name,
            "has_logo": bool(self.logo_data_uri),
            "contact_email": self.contact_email,
            "contact_phone": self.contact_phone,
            "website": self.website,
            "accent_colour": self.accent_colour,
            "footer_note": self.footer_note,
        }


def get_branding():
    """The single branding row, created empty on first access."""
    row = Branding.query.first()
    if row is None:
        row = Branding()
        db.session.add(row)
        db.session.commit()
    return row


def logo_problem(content_type, data):
    """Why this logo is unacceptable, or None."""
    if content_type not in ALLOWED_LOGO_TYPES:
        allowed = ", ".join(sorted(ALLOWED_LOGO_TYPES.values()))
        return f"Use a {allowed} image. SVG isn't accepted — it can carry script."
    if not data:
        return "The file is empty."
    if len(data) > MAX_LOGO_BYTES:
        return f"Keep the logo under {MAX_LOGO_BYTES // 1024} KB — it's embedded in every report."
    return None


def encode_logo(content_type, data):
    """A data URI for embedding. Validate with logo_problem first."""
    encoded = base64.b64encode(data).decode("ascii")
    return f"data:{content_type};base64,{encoded}"


def normalise_colour(value):
    """A #rrggbb colour, or None. Rejects anything that isn't a plain hex code.

    This value lands inside a style attribute in the report, so letting an
    arbitrary string through would allow CSS injection into a document sent to
    a client.
    """
    if not value:
        return None
    value = value.strip()
    if not value.startswith("#"):
        value = "#" + value
    if len(value) != 7:
        return None
    try:
        int(value[1:], 16)
    except ValueError:
        return None
    return value.lower()
