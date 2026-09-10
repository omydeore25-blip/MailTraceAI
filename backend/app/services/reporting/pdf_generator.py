import io
from datetime import datetime, timezone
from typing import Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def generate_forensic_pdf(analysis_data: Dict[str, Any]) -> bytes:
    """Generate a pixel-perfect court-ready forensic PDF examination report."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a")
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b")
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        "BodyText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )
    code_style = ParagraphStyle(
        "CodeText",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a")
    )

    elements = []

    # Title Banner
    elements.append(Paragraph("MAILTRACE AI — DIGITAL FORENSIC REPORT", title_style))
    elements.append(Paragraph(f"Autonomous Email Threat Detection & Infrastructure Attribution Platform | SIH 2026", subtitle_style))
    elements.append(Paragraph(f"Generated on: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Case ID: {analysis_data.get('id', 'N/A')}", subtitle_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=12))

    # Executive Threat Summary Block
    risk_score = analysis_data.get("risk_score", 0.0)
    threat_level = analysis_data.get("threat_level", "Clean")
    
    # Color badge for threat level
    badge_color = colors.HexColor("#22c55e") # Green
    if threat_level == "Critical":
        badge_color = colors.HexColor("#ef4444") # Red
    elif threat_level == "Malicious":
        badge_color = colors.HexColor("#f97316") # Orange
    elif threat_level == "Suspicious":
        badge_color = colors.HexColor("#eab308") # Yellow

    overview_data = [
        [Paragraph("<b>Subject:</b>", body_style), Paragraph(analysis_data.get("subject") or "(No Subject)", body_style)],
        [Paragraph("<b>Sender (From):</b>", body_style), Paragraph(analysis_data.get("sender", "N/A"), code_style)],
        [Paragraph("<b>Recipient(s):</b>", body_style), Paragraph(", ".join(analysis_data.get("recipients", [])) or "Undisclosed", body_style)],
        [Paragraph("<b>Overall Risk Score:</b>", body_style), Paragraph(f"<b>{risk_score}/100</b> — <b>{threat_level.upper()}</b>", body_style)],
        [Paragraph("<b>Attributed Campaign:</b>", body_style), Paragraph(analysis_data.get("campaign_id") or "None", code_style)],
        [Paragraph("<b>Threat Actor Profile:</b>", body_style), Paragraph(analysis_data.get("threat_actor") or "Unattributed", body_style)]
    ]
    overview_table = Table(overview_data, colWidths=[130, 400])
    overview_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(overview_table)
    elements.append(Spacer(1, 14))

    # Protocol Authentication Matrix
    elements.append(Paragraph("1. Cryptographic & Protocol Authentication Audit", section_heading))
    auth = analysis_data.get("auth_results", {})
    spf = auth.get("spf", {})
    dkim = auth.get("dkim", {})
    dmarc = auth.get("dmarc", {})
    arc = auth.get("arc", {})

    auth_rows = [
        ["Protocol", "Status", "Domain / Selector", "Policy & Details"],
        ["SPF (RFC 7208)", spf.get("status", "none").upper(), spf.get("evaluated_domain", "N/A"), spf.get("details", "")[:60]],
        ["DKIM (RFC 6376)", dkim.get("status", "none").upper(), f"s={dkim.get('selector', '')} d={dkim.get('domain', '')}", dkim.get("details", "")[:60]],
        ["DMARC (RFC 7489)", dmarc.get("status", "none").upper(), f"p={dmarc.get('policy', 'none')}", dmarc.get("details", "")[:60]],
        ["ARC (RFC 8617)", arc.get("status", "none").upper(), "Chain Verification", arc.get("details", "")[:60]]
    ]
    auth_table = Table(auth_rows, colWidths=[100, 70, 160, 200])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('PADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(auth_table)
    elements.append(Spacer(1, 14))

    # Extracted Indicators of Compromise (IOCs)
    elements.append(Paragraph("2. Indicators of Compromise (IOCs) & Threat Intel", section_heading))
    iocs = analysis_data.get("iocs", [])
    if iocs:
        ioc_rows = [["Type", "Indicator (Defanged)", "Reputation", "Verdict"]]
        for item in iocs[:12]: # Limit to top 12 for PDF space
            ioc_rows.append([
                item.get("ioc_type", "").upper(),
                Paragraph(item.get("defanged_value") or item.get("value", ""), code_style),
                f"{item.get('reputation_score', 0):.0f}/100",
                "MALICIOUS" if item.get("is_malicious") else "CLEAN"
            ])
        ioc_table = Table(ioc_rows, colWidths=[60, 310, 80, 80])
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#334155")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(ioc_table)
    else:
        elements.append(Paragraph("No external indicators of compromise discovered.", body_style))
    elements.append(Spacer(1, 14))

    # MITRE ATT&CK Attribution
    elements.append(Paragraph("3. MITRE ATT&CK Threat Mapping", section_heading))
    mitre_list = analysis_data.get("mitre_attack", [])
    if mitre_list:
        mitre_rows = [["Technique ID", "Name", "Tactic", "Evidence"]]
        for m in mitre_list:
            mitre_rows.append([
                m.get("id", ""),
                m.get("name", ""),
                m.get("tactic", ""),
                Paragraph(m.get("evidence", "")[:70], body_style)
            ])
        mitre_table = Table(mitre_rows, colWidths=[70, 150, 90, 220])
        mitre_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#475569")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(mitre_table)
    else:
        elements.append(Paragraph("No adversarial MITRE ATT&CK techniques mapped.", body_style))

    elements.append(Spacer(1, 18))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=10))
    elements.append(Paragraph("CONFIDENTIAL — Generated by MailTrace AI Autonomous Forensic Engine for Official Security Auditing.", subtitle_style))

    doc.build(elements)
    return buffer.getvalue()
