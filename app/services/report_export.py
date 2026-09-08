"""Standalone HTML audit report — the client-facing deliverable.

Everything is inlined (no external CSS, fonts, or scripts) so the file can be
emailed or archived and still render years later, and so printing it to PDF
from a browser gives a usable document.

Structure follows what an audit deliverable is normally expected to contain:
an executive summary a non-technical reader can act on, then findings ranked
worst-first with remediation, then the passing and skipped checks as evidence
of scope.
"""
from datetime import datetime, timezone
from html import escape

from app.services import remediation
from app.services.scoring import calculate_security_score

SEVERITY_COLOURS = {
    "critical": ("#7f1d1d", "#fecaca"),
    "high":     ("#7c2d12", "#fed7aa"),
    "medium":   ("#78350f", "#fde68a"),
    "low":      ("#334155", "#cbd5e1"),
    "info":     ("#1e293b", "#94a3b8"),
}


def _score_colour(score):
    if score is None:
        return "#64748b"
    if score >= 80:
        return "#16a34a"
    if score >= 50:
        return "#d97706"
    return "#dc2626"


def _score_label(score):
    if score is None:
        return "Not scored"
    if score >= 80:
        return "Good"
    if score >= 50:
        return "Needs attention"
    return "At risk"


def _findings(checks):
    """Failing and warning checks, worst severity first, then by points at stake."""
    findings = [c for c in checks if c.status in ("fail", "warn")]
    return sorted(
        findings,
        key=lambda c: (remediation.sort_key(c.check_name), -(c.points_possible or 0)),
    )


def _severity_counts(findings):
    counts = {}
    for c in findings:
        sev = remediation.severity_of(c.check_name)
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _summary_sentence(score, findings, counts):
    """One plain-language line for a reader who reads nothing else."""
    if not findings:
        return "No failing checks were identified in this audit."

    urgent = counts.get("critical", 0) + counts.get("high", 0)
    lead = f"This tenant scored {score}/100 against the CIS controls assessed. " if score is not None else ""
    if urgent:
        return (f"{lead}{urgent} finding{'s' if urgent != 1 else ''} "
                f"rated high or critical should be addressed first; "
                f"{len(findings)} in total require attention.")
    return f"{lead}{len(findings)} finding{'s' if len(findings) != 1 else ''} require attention, none rated high or critical."


def _badge(sev):
    bg, fg = SEVERITY_COLOURS.get(sev, SEVERITY_COLOURS["info"])
    return (f'<span style="background:{bg};color:{fg};padding:2px 8px;border-radius:4px;'
            f'font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em">'
            f'{escape(sev)}</span>')


def _finding_block(check):
    guidance = remediation.get(check.check_name) or {}
    sev = remediation.severity_of(check.check_name)

    issues = check.issues or []
    shown = issues[:10]
    issues_html = ""
    if shown:
        items = "".join(f"<li>{escape(str(i))}</li>" for i in shown)
        more = (f'<li style="color:#94a3b8">…and {len(issues) - len(shown)} more</li>'
                if len(issues) > len(shown) else "")
        issues_html = (
            '<div class="affected"><p class="label">Affected</p>'
            f'<ul>{items}{more}</ul></div>'
        )

    fix = guidance.get("fix")
    fix_html = (f'<div class="fix"><p class="label">Remediation</p><p>{escape(fix)}</p>'
                + (f'<p class="portal"><a href="{escape(guidance["portal"])}">'
                   f'{escape(guidance["portal"])}</a></p>' if guidance.get("portal") else "")
                + (f'<p class="note">{escape(guidance["note"])}</p>' if guidance.get("note") else "")
                + '</div>') if fix else ""

    why = guidance.get("why")
    why_html = f'<div class="why"><p class="label">Why it matters</p><p>{escape(why)}</p></div>' if why else ""

    points = ""
    if check.points_possible:
        points = (f'<span class="points">{check.points_earned if check.points_earned is not None else 0}'
                  f'/{check.points_possible} pts</span>')

    cis = f'<span class="cis">{escape(check.cis_reference)}</span>' if check.cis_reference else ""

    return f"""
    <section class="finding sev-{escape(sev)}">
      <div class="finding-head">
        <div>
          <h3>{escape(check.display_name or check.check_name)}</h3>
          <p class="summary">{escape(check.summary or "")}</p>
        </div>
        <div class="finding-meta">{_badge(sev)}{cis}{points}</div>
      </div>
      {why_html}
      {issues_html}
      {fix_html}
    </section>"""


def _table_rows(checks):
    rows = []
    for c in sorted(checks, key=lambda c: (c.category or "", c.display_name or "")):
        pts = (f"{c.points_earned if c.points_earned is not None else 0}/{c.points_possible}"
               if c.points_possible else "—")
        rows.append(
            f"<tr><td>{escape(c.category or '')}</td>"
            f"<td>{escape(c.display_name or c.check_name)}</td>"
            f"<td><span class='status status-{escape(c.status or 'info')}'>{escape(c.status or '')}</span></td>"
            f"<td>{pts}</td>"
            f"<td class='muted'>{escape(c.summary or '')}</td></tr>"
        )
    return "".join(rows)


CSS = """
*{box-sizing:border-box}
body{margin:0;font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
     color:#0f172a;background:#f8fafc}
.wrap{max-width:960px;margin:0 auto;padding:40px 32px 64px}
header.doc{border-bottom:3px solid #0f172a;padding-bottom:20px;margin-bottom:32px}
header.doc h1{margin:0 0 6px;font-size:26px;letter-spacing:-.01em}
header.doc .meta{color:#64748b;font-size:13px}
.scorecard{display:flex;gap:28px;align-items:center;background:#fff;border:1px solid #e2e8f0;
           border-radius:10px;padding:24px;margin-bottom:32px}
.scorecard .num{font-size:52px;font-weight:800;line-height:1}
.scorecard .of{font-size:18px;color:#94a3b8;font-weight:600}
.scorecard .label{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-top:4px}
.scorecard .verdict{flex:1}
.scorecard .verdict p{margin:0;color:#334155}
.counts{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.counts span{font-size:12px;padding:3px 9px;border-radius:4px;font-weight:700}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:#64748b;
   border-bottom:1px solid #e2e8f0;padding-bottom:8px;margin:40px 0 18px}
.finding{background:#fff;border:1px solid #e2e8f0;border-left:4px solid #94a3b8;
         border-radius:8px;padding:20px;margin-bottom:14px;page-break-inside:avoid}
.finding.sev-critical{border-left-color:#dc2626}
.finding.sev-high{border-left-color:#ea580c}
.finding.sev-medium{border-left-color:#d97706}
.finding.sev-low{border-left-color:#64748b}
.finding-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}
.finding-head h3{margin:0 0 4px;font-size:17px}
.finding-meta{display:flex;gap:8px;align-items:center;flex-shrink:0;flex-wrap:wrap;justify-content:flex-end}
.summary{margin:0;color:#475569;font-size:14px}
.cis{font-size:11px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
     background:#eff6ff;color:#1d4ed8;padding:2px 7px;border-radius:4px;border:1px solid #dbeafe}
.points{font-size:12px;color:#64748b;font-weight:600}
.label{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;
       color:#94a3b8;margin:16px 0 5px}
.why p,.fix p{margin:0;color:#334155;font-size:14px}
.fix{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:12px 14px;margin-top:14px}
.fix .label{color:#15803d;margin-top:0}
.fix .portal{margin-top:8px;font-size:13px}
.fix .portal a{color:#15803d}
.fix .note{margin-top:8px;font-size:13px;color:#a16207}
.affected ul{margin:0;padding-left:20px;color:#475569;font-size:13.5px}
.affected li{margin-bottom:3px}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e2e8f0;
      border-radius:8px;overflow:hidden;font-size:13.5px}
th{text-align:left;background:#f1f5f9;padding:10px 12px;font-size:11px;text-transform:uppercase;
   letter-spacing:.05em;color:#64748b;border-bottom:1px solid #e2e8f0}
td{padding:9px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top}
tr:last-child td{border-bottom:none}
td.muted{color:#64748b}
.status{font-size:11px;font-weight:700;padding:2px 7px;border-radius:4px;text-transform:uppercase}
.status-pass{background:#dcfce7;color:#15803d}
.status-warn{background:#fef3c7;color:#a16207}
.status-fail{background:#fee2e2;color:#b91c1c}
.status-skip{background:#f1f5f9;color:#64748b}
.status-info{background:#e0f2fe;color:#0369a1}
.none{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:24px;text-align:center;color:#64748b}
footer{margin-top:48px;padding-top:16px;border-top:1px solid #e2e8f0;color:#94a3b8;font-size:12px}
@media print{body{background:#fff}.wrap{padding:0}.finding{break-inside:avoid}}
"""


def render_html(report):
    """Build a standalone HTML document for a completed Report."""
    checks = list(report.checks)
    findings = _findings(checks)
    counts = _severity_counts(findings)

    scored = [{"points_earned": c.points_earned, "points_possible": c.points_possible}
              for c in checks if c.points_possible]
    score = calculate_security_score(scored)["overall"] if scored else None

    generated = datetime.now(timezone.utc).strftime("%d %B %Y at %H:%M UTC")
    audited = report.created_at.strftime("%d %B %Y") if report.created_at else "unknown date"

    count_html = "".join(
        f'<span style="background:{SEVERITY_COLOURS[s][0]};color:{SEVERITY_COLOURS[s][1]}">'
        f'{counts[s]} {s}</span>'
        for s in ("critical", "high", "medium", "low", "info") if counts.get(s)
    )

    findings_html = ("".join(_finding_block(c) for c in findings)
                     if findings else
                     '<div class="none">No failing checks in this audit.</div>')

    passing = [c for c in checks if c.status == "pass"]
    skipped = [c for c in checks if c.status == "skip"]
    informational = [c for c in checks if c.status == "info"]

    def table_section(title, rows, empty_note):
        if not rows:
            return ""
        return (f"<h2>{escape(title)} ({len(rows)})</h2>"
                f"<table><thead><tr><th>Category</th><th>Check</th><th>Status</th>"
                f"<th>Points</th><th>Detail</th></tr></thead>"
                f"<tbody>{_table_rows(rows)}</tbody></table>")

    skipped_note = ""
    if skipped:
        skipped_note = ('<p style="color:#64748b;font-size:13.5px;margin:0 0 12px">'
                        'These checks could not run — usually a missing Graph permission, an '
                        'unlicensed feature, or a workload not present in the tenant. They are '
                        'excluded from the score rather than counted as failures.</p>')

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tenant Security Audit — {escape(audited)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">

  <header class="doc">
    <h1>Microsoft 365 Tenant Security Audit</h1>
    <p class="meta">
      Tenant {escape(report.tenant_id or "unknown")} &middot;
      Audit run {escape(audited)} &middot;
      Report generated {escape(generated)}
    </p>
  </header>

  <div class="scorecard">
    <div>
      <div class="num" style="color:{_score_colour(score)}">
        {score if score is not None else "—"}<span class="of">/100</span>
      </div>
      <div class="label" style="color:{_score_colour(score)}">{escape(_score_label(score))}</div>
    </div>
    <div class="verdict">
      <p>{escape(_summary_sentence(score, findings, counts))}</p>
      <div class="counts">{count_html}</div>
    </div>
  </div>

  <h2>Findings ({len(findings)})</h2>
  {findings_html}

  {table_section("Passing checks", passing, "")}
  {(f'<h2>Skipped checks ({len(skipped)})</h2>{skipped_note}'
    f'<table><thead><tr><th>Category</th><th>Check</th><th>Status</th><th>Points</th>'
    f'<th>Reason</th></tr></thead><tbody>{_table_rows(skipped)}</tbody></table>') if skipped else ""}
  {table_section("Informational", informational, "")}

  <footer>
    Scored against CIS Microsoft 365 Foundations Benchmark controls.
    Checks that could not run are excluded from the score rather than failed.
  </footer>

</div>
</body>
</html>"""
