import uuid
from app import db
from app.utils import utcnow


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = db.Column(db.String(100))
    report_type = db.Column(db.String(50))  # full | security | licensing | users | sharepoint | exchange | groups
    status = db.Column(db.String(20), default="running")  # running | complete | failed
    score = db.Column(db.Integer, nullable=True)
    error = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    checks = db.relationship("ReportCheck", backref="report", lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "report_type": self.report_type,
            "status": self.status,
            "score": self.score,
            "error": self.error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "checks": [c.to_dict() for c in self.checks],
        }


class ReportCheck(db.Model):
    __tablename__ = "report_checks"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id = db.Column(db.String(36), db.ForeignKey("reports.id"), nullable=False)
    category = db.Column(db.String(50))
    check_name = db.Column(db.String(100))
    display_name = db.Column(db.String(200))
    status = db.Column(db.String(20))  # pass | warn | fail | skip | info
    points_earned = db.Column(db.Integer, nullable=True)
    points_possible = db.Column(db.Integer, nullable=True)
    summary = db.Column(db.Text, nullable=True)
    issues = db.Column(db.JSON, nullable=True)   # list of issue strings
    details = db.Column(db.JSON, nullable=True)  # full raw data
    cis_reference = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "category": self.category,
            "check_name": self.check_name,
            "display_name": self.display_name,
            "status": self.status,
            "points_earned": self.points_earned,
            "points_possible": self.points_possible,
            "summary": self.summary,
            "issues": self.issues or [],
            "details": self.details,
            "cis_reference": self.cis_reference,
        }
