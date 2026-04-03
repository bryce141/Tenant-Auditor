"""
Orchestrates running checks for a given category (or all categories),
saves results to the DB as Report + ReportCheck records.
"""
import threading
from datetime import datetime

# ---------------------------------------------------------------------------
# Thread-safe progress store for the full audit run
# ---------------------------------------------------------------------------
_progress_lock = threading.Lock()
_run_progress = {"step": 0, "total": 0, "message": "", "running": False, "category": ""}

CATEGORY_LABELS = {
    "identity": "Checking identity & MFA",
    "conditional_access": "Checking conditional access policies",
    "mail_security": "Checking mail security & app registrations",
    "licensing": "Checking licenses",
    "users": "Checking users & activity",
    "sharepoint": "Checking SharePoint",
    "exchange": "Checking Exchange mailboxes",
    "groups": "Checking groups",
}


def _set_progress(step, total, message, running=True, category=""):
    with _progress_lock:
        _run_progress.update({"step": step, "total": total, "message": message,
                               "running": running, "category": category})


def get_run_progress():
    with _progress_lock:
        return dict(_run_progress)

from app import db
from app.auth.graph_auth import get_headers
from app.models.report import Report, ReportCheck
from app.services.graph_client import GraphClient
from app.services.scoring import calculate_security_score

import app.checks.identity as identity_checks
import app.checks.conditional_access as ca_checks
import app.checks.mail_security as mail_checks
import app.checks.licensing as licensing_checks
import app.checks.users as user_checks
import app.checks.sharepoint as sp_checks
import app.checks.exchange as exchange_checks
import app.checks.groups as group_checks

CATEGORY_MAP = {
    "identity": identity_checks,
    "conditional_access": ca_checks,
    "mail_security": mail_checks,
    "licensing": licensing_checks,
    "users": user_checks,
    "sharepoint": sp_checks,
    "exchange": exchange_checks,
    "groups": group_checks,
}

SECURITY_CATEGORIES = {"identity", "conditional_access", "mail_security"}


def _save_checks(report_id, check_results):
    """Persist a list of check result dicts as ReportCheck rows."""
    for result in check_results:
        if not isinstance(result, dict):
            continue
        db.session.add(ReportCheck(
            report_id=report_id,
            category=result.get("category"),
            check_name=result.get("check_name"),
            display_name=result.get("display_name"),
            status=result.get("status"),
            points_earned=result.get("points_earned"),
            points_possible=result.get("points_possible"),
            summary=result.get("summary"),
            issues=result.get("issues", []),
            details=result.get("details"),
            cis_reference=result.get("cis_reference"),
        ))


def run_category(category: str, app_context):
    """Run all checks for a single category. Called in background thread."""
    with app_context:
        try:
            headers, tenant_id = get_headers()
        except Exception as e:
            return

        report = Report(
            tenant_id=tenant_id,
            report_type=category,
            status="running",
        )
        db.session.add(report)
        db.session.commit()
        report_id = report.id

        try:
            client = GraphClient(headers)
            module = CATEGORY_MAP[category]
            results = module.run_all(client)

            _save_checks(report_id, results)

            # Calculate score for security categories
            score = None
            if category in SECURITY_CATEGORIES or category == "security":
                check_dicts = [{"points_earned": r.get("points_earned"), "points_possible": r.get("points_possible")}
                               for r in results if isinstance(r, dict)]
                score_data = calculate_security_score(check_dicts)
                score = score_data["overall"]

            report.status = "complete"
            report.score = score
            report.completed_at = datetime.utcnow()
            db.session.commit()

        except Exception as e:
            report.status = "failed"
            report.error = str(e)
            report.completed_at = datetime.utcnow()
            db.session.commit()

        return report_id


def run_full(app_context):
    """Run all categories sequentially. Called in background thread."""
    with app_context:
        try:
            headers, tenant_id = get_headers()
        except Exception as e:
            return

        report = Report(
            tenant_id=tenant_id,
            report_type="full",
            status="running",
        )
        db.session.add(report)
        db.session.commit()
        report_id = report.id

        categories = list(CATEGORY_MAP.items())
        total = len(categories)
        _set_progress(0, total, "Starting audit…", running=True)

        try:
            client = GraphClient(headers)
            all_results = []

            for i, (category, module) in enumerate(categories, 1):
                label = CATEGORY_LABELS.get(category, f"Checking {category}")
                _set_progress(i, total, label, running=True, category=category)
                results = module.run_all(client)

                # Save to individual category report so dashboard tiles work
                cat_report = Report(tenant_id=tenant_id, report_type=category, status="running")
                db.session.add(cat_report)
                db.session.commit()
                _save_checks(cat_report.id, results)

                cat_score = None
                if category in SECURITY_CATEGORIES:
                    check_dicts = [{"points_earned": r.get("points_earned"), "points_possible": r.get("points_possible")}
                                   for r in results if isinstance(r, dict)]
                    cat_score = calculate_security_score(check_dicts)["overall"]

                cat_report.status = "complete"
                cat_report.score = cat_score
                cat_report.completed_at = datetime.utcnow()
                db.session.commit()

                all_results.extend(r for r in results if isinstance(r, dict))

            _set_progress(total, total, "Finalizing results…", running=True)
            security_checks = [r for r in all_results if r.get("category") in SECURITY_CATEGORIES
                                and r.get("points_earned") is not None]
            score_data = calculate_security_score(security_checks)

            report.status = "complete"
            report.score = score_data["overall"]
            report.completed_at = datetime.utcnow()
            db.session.commit()

        except Exception as e:
            report.status = "failed"
            report.error = str(e)
            report.completed_at = datetime.utcnow()
            db.session.commit()

        finally:
            _set_progress(total, total, "Done", running=False)

        return report_id


def start_category_run(category: str, flask_app):
    """Kick off a category run in a background thread."""
    ctx = flask_app.app_context()
    t = threading.Thread(target=run_category, args=(category, ctx), daemon=True)
    t.start()


def start_full_run(flask_app):
    """Kick off a full run in a background thread."""
    ctx = flask_app.app_context()
    t = threading.Thread(target=run_full, args=(ctx,), daemon=True)
    t.start()


def get_latest_report(category: str):
    """Return the most recent complete report for a category."""
    return (Report.query
            .filter_by(report_type=category, status="complete")
            .order_by(Report.created_at.desc())
            .first())


def get_running_report(category: str):
    """Return any currently running report for a category."""
    return (Report.query
            .filter_by(report_type=category, status="running")
            .order_by(Report.created_at.desc())
            .first())
