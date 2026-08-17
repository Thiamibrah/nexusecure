"""PDF report generation with ReportLab."""
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from sqlalchemy.orm import Session
from app.models.scan import Scan
from app.models.report import Report
from app.models.vulnerability import Severity

REPORTS_DIR = "app/reports/files"
os.makedirs(REPORTS_DIR, exist_ok=True)

SEVERITY_COLORS = {
    Severity.critical: colors.HexColor("#dc3545"),
    Severity.high: colors.HexColor("#fd7e14"),
    Severity.medium: colors.HexColor("#ffc107"),
    Severity.low: colors.HexColor("#0dcaf0"),
    Severity.info: colors.HexColor("#6c757d"),
}

SEVERITY_WEIGHT = {Severity.critical: 40, Severity.high: 20, Severity.medium: 8, Severity.low: 2, Severity.info: 0}


def _risk_score(vulns) -> float:
    """Score 0-100. Catégories: 0-20 Sécurisé, 21-40 Faible, 41-60 Moyen, 61-80 Élevé, 81-100 Critique."""
    if not vulns:
        return 0.0
    return min(round(sum(SEVERITY_WEIGHT.get(v.severity, 0) for v in vulns) / max(len(vulns), 1), 1), 100.0)


def _risk_label(score: float) -> tuple[str, str]:
    """Returns (label, hex_color) for score 0-100."""
    if score <= 20:   return "Sécurisé",    "#00e676"
    if score <= 40:   return "Faible risque", "#0dcaf0"
    if score <= 60:   return "Risque moyen",  "#ffc107"
    if score <= 80:   return "Risque élevé",  "#fd7e14"
    return "Risque critique", "#dc3545"


def generate_pdf(scan: Scan, db: Session) -> Report:
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("title", fontSize=20, textColor=colors.HexColor("#0d1b2a"), spaceAfter=6)
    h2 = ParagraphStyle("h2", fontSize=13, textColor=colors.HexColor("#1a73e8"), spaceBefore=12, spaceAfter=4)
    normal = styles["Normal"]

    all_vulns = [v for host in scan.hosts for v in host.vulnerabilities]
    risk = _risk_score(all_vulns)
    risk_label, _ = _risk_label(risk)

    pdf_path = os.path.join(REPORTS_DIR, f"report_scan_{scan.id}_{int(datetime.utcnow().timestamp())}.pdf")
    doc = SimpleDocTemplate(pdf_path, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)

    story = [
        Paragraph("NexusSecure — Rapport d'Audit Sécurité", title_style),
        HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a73e8")),
        Spacer(1, 0.3*cm),
        Paragraph(f"<b>Cible :</b> {scan.target}", normal),
        Paragraph(f"<b>Date :</b> {scan.started_at.strftime('%d/%m/%Y %H:%M')}", normal),
        Paragraph(f"<b>Score de risque global :</b> {risk} / 100 — {risk_label}", normal),
        Spacer(1, 0.5*cm),
    ]

    # Hosts summary
    story.append(Paragraph("Machines détectées", h2))
    host_data = [["IP", "Hostname", "OS", "Ports ouverts"]]
    for h in scan.hosts:
        host_data.append([h.ip, h.hostname or "—", h.os or "Inconnu", len(h.ports)])
    story.append(Table(host_data, colWidths=[3.5*cm, 5*cm, 5*cm, 3*cm],
                       style=TableStyle([
                           ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a73e8")),
                           ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                           ("FONTSIZE", (0, 0), (-1, -1), 9),
                           ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
                       ])))
    story.append(Spacer(1, 0.5*cm))

    # Vulnerabilities
    story.append(Paragraph("Vulnérabilités détectées", h2))
    if all_vulns:
        vuln_data = [["Sévérité", "Titre", "IP", "Port", "CVSS", "Impact", "Recommandation"]]
        for v in sorted(all_vulns, key=lambda x: SEVERITY_WEIGHT.get(x.severity, 0), reverse=True):
            vuln_data.append([
                v.severity.value.upper(),
                v.title,
                v.host.ip,
                str(v.port_number or "—"),
                str(v.cvss_score or "—"),
                Paragraph(v.impact or "—", ParagraphStyle("imp", fontSize=7)),
                Paragraph(v.recommendation or "—", ParagraphStyle("rec", fontSize=7)),
            ])
        tbl = Table(vuln_data, colWidths=[2*cm, 3.5*cm, 2.5*cm, 1.2*cm, 1.5*cm, 3.5*cm, 3.3*cm],
                    style=TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d1b2a")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]))
        # Colorize severity column
        for i, v in enumerate(all_vulns, start=1):
            tbl_style = TableStyle([("BACKGROUND", (0, i), (0, i), SEVERITY_COLORS.get(v.severity, colors.grey))])
            tbl.setStyle(tbl_style)
        story.append(tbl)
    else:
        story.append(Paragraph("Aucune vulnérabilité détectée.", normal))

    doc.build(story)

    report = Report(scan_id=scan.id, pdf_path=pdf_path, risk_score=risk)
    db.add(report); db.commit(); db.refresh(report)
    return report
