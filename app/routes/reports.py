import csv
import io
from flask import Blueprint, render_template, jsonify, Response
from app import db
from app.auth.graph_auth import get_active_tenant
from app.models.report import Report, ReportCheck

bp = Blueprint("reports", __name__, url_prefix="/reports")


@bp.route("/")
def index():
    tenant = get_active_tenant()
    q = Report.query
    if tenant:
        q = q.filter(Report.tenant_id == tenant.tenant_id)
    reports = q.order_by(Report.created_at.desc()).limit(100).all()
    return render_template("reports/index.html", reports=reports, tenant=tenant)


@bp.route("/api/export/<report_id>")
def export_csv(report_id):
    report = db.get_or_404(Report, report_id)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Category", "Check", "Status", "Points Earned", "Points Possible", "Summary", "Issues"])
    for c in report.checks:
        issues_str = "; ".join(c.issues or [])
        writer.writerow([c.category, c.display_name, c.status,
                         c.points_earned or "", c.points_possible or "",
                         c.summary or "", issues_str])

    filename = f"audit-{report.report_type}-{report.created_at.strftime('%Y%m%d')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@bp.route("/api/export/<report_id>/html")
def export_html(report_id):
    """Standalone HTML report — the client-facing deliverable.

    Rendered inline rather than as an attachment so it can be reviewed and
    printed to PDF straight from the browser.
    """
    from app.services.comparison import compare, find_previous, headline
    from app.services.report_export import render_html

    report = db.get_or_404(Report, report_id)
    diff = compare(report, find_previous(report, Report))
    return Response(render_html(report, diff=diff, diff_headline=headline(diff)),
                    mimetype="text/html")


@bp.route("/api/delete/<report_id>", methods=["DELETE"])
def delete(report_id):
    report = db.get_or_404(Report, report_id)
    db.session.delete(report)
    db.session.commit()
    return jsonify({"status": "deleted"})
