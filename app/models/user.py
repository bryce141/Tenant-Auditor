"""The administrator account that guards the application.

One account, not a user system. This protects a single operator's install; it
is not multi-user access control, and shouldn't be mistaken for it — if several
people need separate logins with different permissions, that is a different
model and a different design.
"""
import uuid

from werkzeug.security import check_password_hash, generate_password_hash

from app import db
from app.utils import utcnow

MIN_PASSWORD_LENGTH = 12


class AdminUser(db.Model):
    __tablename__ = "admin_users"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(120), unique=True, nullable=False)
    # scrypt via werkzeug. Never store or log the password itself.
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        problem = password_problem(password)
        if problem:
            raise ValueError(problem)
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not password:
            return False
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<AdminUser {self.username}>"


def password_problem(password):
    """Why this password is unacceptable, or None.

    Length is the requirement that actually matters. Composition rules push
    people toward predictable substitutions without adding much, so the bar
    here is a genuine minimum length rather than a character-class checklist.
    """
    if not password:
        return "Enter a password."
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Use at least {MIN_PASSWORD_LENGTH} characters."
    if password.lower() in {"password1234", "administrator", "changeme1234"}:
        return "That password is too predictable."
    return None


def any_admin_exists():
    try:
        return db.session.query(AdminUser.id).first() is not None
    except Exception:
        # Table may not exist yet on first boot.
        return False
