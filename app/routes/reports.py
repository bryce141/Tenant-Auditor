import csv
import io
from flask import Blueprint, render_template, jsonify, Response
from app.models.report import Report, ReportCheck

bp = Blueprint("reports", __name__, url_prefix="/reports")


@bp.route("/")
def index():
    reports = (Report.query
               .order_by(Report.created_at.desc())
               .limit(100).all())
    return render_template("reports/index.html", reports=reports)


@bp.route("/api/export/<report_id>")
def export_csv(report_id):
    report = Report.query.get_or_404(report_id)

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
    from app.services.report_export import render_html

    report = Report.query.get_or_404(report_id)
    return Response(render_html(report), mimetype="text/html")


@bp.route("/api/delete/<report_id>", methods=["DELETE"])
def delete(report_id):
    from app import db
    report = Report.query.get_or_404(report_id)
    db.session.delete(report)
    db.session.commit()
    return jsonify({"status": "deleted"})
