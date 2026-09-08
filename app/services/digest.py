"""The scheduled email digest.

Leads with what changed rather than restating the score. A weekly mail that
says the same thing every week gets filtered into a folder and stops being
read, so an unchanged tenant is one quiet line and the detail is reserved for
tenants that actually moved.
"""
from html import escape

from app.models.report import Report
from app.services import remediation
from app.services.comparison import compare, find_previous, headline
from app.utils import utcnow


def latest_full(tenant):
    return (Report.query
            .filter_by(tenant_id=tenant.tenant_id, report_type="full", status="complete")
            .order_by(Report.created_at.desc())
            .first())


def collect(tenants):
    """Gather one summary per tenant, worst score first."""
    entries = []
    for tenant in tenants:
        report = latest_full(tenant)
        if report is None:
            entries.append({"tenant": tenant, "report": None, "diff": None,
                            "headline": "No audit has run yet.", "findings": []})
            continue

        diff = compare(report, find_previous(report, Report))
        findings = sorted(
            [c for c in report.checks if c.status in ("fail", "warn")],
            key=lambda c: (remediation.sort_key(c.check_name), -(c.points_possible or 0)),
        )
        entries.append({
            "tenant": tenant,
            "report": report,
            "diff": diff,
            "headline": headline(diff) or "First audit — nothing to compare against yet.",
            "findings": findings,
        })

    # Unaudited tenants last; otherwise worst score first.
    return sorted(entries, key=lambda e: (e["report"] is None,
                                          e["report"].score if e["report"] and e["report"].score is not None else 999))


def subject_line(entries):
    """Say the notable thing in the subject, since that is often all that's read."""
    audited = [e for e in entries if e["report"]]
    if not audited:
        return "Tenant audit — no audits have run"

    new_findings = sum(len(e["diff"]["new_findings"]) for e in audited
                       if e["diff"] and not e["diff"].get("unchanged"))
    resolved = sum(len(e["diff"]["resolved"]) for e in audited
                   if e["diff"] and not e["diff"].get("unchanged"))

    if len(audited) == 1:
        name = audited[0]["tenant"].name
        score = audited[0]["report"].score
        if new_findings:
            return f"{name}: {new_findings} new finding{'s' if new_findings != 1 else ''} ({score}/100)"
        if resolved:
            return f"{name}: {resolved} resolved ({score}/100)"
        return f"{name}: no change ({score}/100)"

    if new_findings:
        return f"Tenant audit — {new_findings} new finding{'s' if new_findings != 1 else ''} across {len(audited)} tenants"
    return f"Tenant audit — no new findings across {len(audited)} tenants"


def _score_colour(score):
    if score is None:
        return "#64748b"
    if score >= 80:
        return "#16a34a"
    if score >= 60:
        return "#d97706"
    if score >= 40:
        return "#ea580c"
    return "#dc2626"


def render_text(entries):
    lines = ["Microsoft 365 tenant audit digest",
             utcnow().strftime("%d %B %Y"), ""]

    for e in entries:
        tenant, report = e["tenant"], e["report"]
        lines.append(f"{tenant.name}")
        lines.append("-" * len(tenant.name))
        if report is None:
            lines += ["  No audit has run yet.", ""]
            continue

        lines.append(f"  Score: {report.score}/100")
        lines.append(f"  {e['headline']}")

        if e["findings"]:
            lines.append(f"  {len(e['findings'])} open finding(s):")
            for c in e["findings"][:8]:
                sev = remediation.severity_of(c.check_name)
                lines.append(f"    [{sev}] {c.display_name} — {c.summary or ''}")
            if len(e["findings"]) > 8:
                lines.append(f"    ...and {len(e['findings']) - 8} more")
        else:
            lines.append("  No open findings.")
        lines.append("")

    return "\n".join(lines)


def render_html(entries, base_url=None):
    blocks = []
    for e in entries:
        tenant, report = e["tenant"], e["report"]

        if report is None:
            blocks.append(
                f'<tr><td style="padding:16px 0;border-bottom:1px solid #e2e8f0">'
                f'<strong style="font-size:16px">{escape(tenant.name)}</strong>'
                f'<div style="color:#64748b;font-size:14px;margin-top:4px">No audit has run yet.</div>'
                f'</td></tr>')
            continue

        colour = _score_colour(report.score)
        delta = ""
        if e["diff"] and e["diff"].get("score_delta"):
            d = e["diff"]["score_delta"]
            dc = "#16a34a" if d > 0 else "#dc2626"
            delta = (f'<span style="color:{dc};font-size:13px;font-weight:600;margin-left:8px">'
                     f'{"+" if d > 0 else ""}{d}</span>')

        finding_rows = ""
        if e["findings"]:
            items = []
            for c in e["findings"][:8]:
                sev = remediation.severity_of(c.check_name)
                sev_colour = {"critical": "#dc2626", "high": "#ea580c",
                              "medium": "#d97706", "low": "#64748b"}.get(sev, "#64748b")
                items.append(
                    f'<li style="margin-bottom:6px">'
                    f'<span style="color:{sev_colour};font-weight:700;font-size:11px;'
                    f'text-transform:uppercase">{escape(sev)}</span>&nbsp;'
                    f'<strong>{escape(c.display_name or "")}</strong>'
                    f'<div style="color:#64748b;font-size:13px">{escape(c.summary or "")}</div></li>')
            more = (f'<li style="color:#94a3b8">…and {len(e["findings"]) - 8} more</li>'
                    if len(e["findings"]) > 8 else "")
            finding_rows = (f'<ul style="margin:10px 0 0;padding-left:18px;font-size:14px">'
                            f'{"".join(items)}{more}</ul>')
        else:
            finding_rows = ('<div style="color:#16a34a;font-size:14px;margin-top:8px">'
                            'No open findings.</div>')

        blocks.append(
            f'<tr><td style="padding:18px 0;border-bottom:1px solid #e2e8f0">'
            f'<div><strong style="font-size:16px">{escape(tenant.name)}</strong>'
            f'<span style="color:{colour};font-weight:700;font-size:16px;margin-left:10px">'
            f'{report.score if report.score is not None else "—"}<span style="color:#94a3b8;font-size:13px">/100</span></span>'
            f'{delta}</div>'
            f'<div style="color:#334155;font-size:14px;margin-top:6px">{escape(e["headline"])}</div>'
            f'{finding_rows}</td></tr>')

    link = ""
    if base_url:
        link = (f'<p style="margin-top:24px;font-size:14px">'
                f'<a href="{escape(base_url)}" style="color:#2563eb">Open the dashboard</a></p>')

    return f"""<!doctype html>
<html><body style="margin:0;padding:24px;background:#f8fafc;
 font:15px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#0f172a">
  <div style="max-width:640px;margin:0 auto;background:#fff;border:1px solid #e2e8f0;
              border-radius:10px;padding:26px">
    <h1 style="margin:0 0 4px;font-size:19px">Microsoft 365 tenant audit</h1>
    <p style="margin:0 0 18px;color:#64748b;font-size:13px">
      {utcnow().strftime("%d %B %Y")}</p>
    <table style="width:100%;border-collapse:collapse">{"".join(blocks)}</table>
    {link}
    <p style="margin-top:22px;color:#94a3b8;font-size:12px">
      Checks that could not run are excluded from the score rather than counted as failures.
    </p>
  </div>
</body></html>"""


def build(tenants, base_url=None):
    """Returns (subject, text, html) for the given tenants."""
    entries = collect(tenants)
    return subject_line(entries), render_text(entries), render_html(entries, base_url)
