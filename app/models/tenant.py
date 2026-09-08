"""A Microsoft 365 tenant this installation can audit."""
import uuid

from app import db
from app.services.crypto import decrypt, encrypt
from app.utils import utcnow


class Tenant(db.Model):
    __tablename__ = "tenants"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(200), nullable=False)          # friendly label, e.g. "Contoso"
    tenant_id = db.Column(db.String(100), nullable=False)     # Entra directory (tenant) GUID
    client_id = db.Column(db.String(100), nullable=False)
    # The client's formal name for report headers. "Contoso Ltd" reads better
    # on a deliverable than an internal label like "contoso-prod".
    client_name = db.Column(db.String(200), nullable=True)
    # Fernet ciphertext — never the raw secret. See app/services/crypto.py.
    client_secret_encrypted = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    last_audited_at = db.Column(db.DateTime, nullable=True)

    @property
    def client_secret(self):
        """Decrypted secret. Raises SecretUnreadable if the key changed."""
        return decrypt(self.client_secret_encrypted)

    @client_secret.setter
    def client_secret(self, value):
        self.client_secret_encrypted = encrypt(value)

    @property
    def report_name(self):
        """What a client should see on a report they receive."""
        return self.client_name or self.name

    def credentials(self):
        return self.tenant_id, self.client_id, self.client_secret

    def to_dict(self):
        """Secret is deliberately absent — this feeds templates and JSON."""
        return {
            "id": self.id,
            "name": self.name,
            "tenant_id": self.tenant_id,
            "client_id": self.client_id,
            "client_name": self.client_name,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_audited_at": self.last_audited_at.isoformat() if self.last_audited_at else None,
        }

    def __repr__(self):
        return f"<Tenant {self.name} ({self.tenant_id})>"
