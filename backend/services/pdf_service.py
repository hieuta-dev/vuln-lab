# FILE: backend/services/pdf_service.py
# PURPOSE: Generates PDF scan report with severity banners, TOC, page numbers, code blocks
# SECURITY NOTE: All text HTML-escaped before rendering; no user HTML injected into PDF

import html as _html
import io
import re
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as _rl_canvas
from reportlab.platypus import (
    HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from services.reproduce_service import get_owasp_ref, get_remediation
SEVERITY_COLORS = {
    "critical": colors.HexColor("#ef4444"),
    "high":     colors.HexColor("#f97316"),
    "medium":   colors.HexColor("#d97706"),  # đậm hơn chút cho nền trắng
    "low":      colors.HexColor("#16a34a"),  # đậm hơn cho nền trắng
    "info":     colors.HexColor("#475569"),  # đậm hơn cho nền trắng
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

BG_PAGE   = colors.white
BG_CARD   = colors.HexColor("#f8fafc")
BG_ROW2   = colors.HexColor("#f1f5f9")
BG_CODE   = colors.HexColor("#1e293b")   # giữ tối cho code block
ACCENT    = colors.HexColor("#7c3aed")
ACCENT_LT = colors.HexColor("#6d28d9")   # tối hơn để đọc được trên trắng
GREEN     = colors.HexColor("#16a34a")   # tối hơn cho nền trắng

TEXT      = colors.HexColor("#0f172a")   # gần đen — body chính
TEXT2     = colors.HexColor("#334155")   # xám đậm — label, subtitle
TEXT3     = colors.HexColor("#475569")   # xám vừa — italic, muted

BORDER    = colors.HexColor("#e2e8f0")   # border nhạt cho nền trắng
WHITE     = colors.white
W, H = A4
PAGE_MARGIN = 14 * mm  # ~40px


# ── Page number canvas (enables "Page X of Y") ────────────────────────────────

class _PageNumCanvas(_rl_canvas.Canvas):
    def __init__(self, *args, **kwargs):
        _rl_canvas.Canvas.__init__(self, *args, **kwargs)
        self._pages: list[dict] = []

    def showPage(self):
        self._pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._pages)
        for state in self._pages:
            self.__dict__.update(state)
            self._draw_footer(total)
            _rl_canvas.Canvas.showPage(self)
        _rl_canvas.Canvas.save(self)

    def _draw_footer(self, total: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(TEXT2)
        self.drawCentredString(W / 2, 8 * mm, f"Page {self._pageNumber} of {total}")
        self.restoreState()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _esc(text: str) -> str:
    return _html.escape(str(text), quote=False)


def _sev_color(sev: str) -> colors.Color:
    return SEVERITY_COLORS.get((sev or "info").lower(), SEVERITY_COLORS["info"])


def _vuln_name(vuln_type: str) -> str:
    return vuln_type.replace("_", " ").title()


def _is_vuln(r: dict) -> bool:
    return r.get("status") == "success" and r.get("severity") and (r.get("severity") or "info") != "info"


def _is_passed(r: dict) -> bool:
    return r.get("status") == "passed"


def _overall_risk(results: list[dict]) -> tuple[str, colors.Color]:
    for sev in SEVERITY_ORDER[:-1]:
        if any((r.get("severity") or "").lower() == sev and r.get("status") == "success"
               for r in results):
            return sev.upper(), _sev_color(sev)
    return "LOW", _sev_color("low")


def _is_code_line(text: str) -> bool:
    """Detect lines that should be rendered as code blocks."""
    t = text.strip().lower()
    return (
        t.startswith("curl ") or
        t.startswith("for ") or
        t.startswith("while ") or
        t.startswith("wget ") or
        t.startswith("nmap ") or
        t.startswith("python") or
        t.startswith("$ ") or
        (t.startswith("http") and "://" in t[:30] and " " not in t[:30])
    )


def _clean_steps(steps: list[str]) -> list[str]:
    """Remove any step that starts with 'Finding:' — that text goes in the Finding box only."""
    return [s for s in steps if not s.strip().lower().startswith("finding:")]


def _step_is_label(text: str) -> bool:
    """Returns True for informational suffix lines like 'Expected:' or 'Tool:'."""
    t = text.strip().lower()
    return t.startswith("expected") or t.startswith("tool:") or t.startswith("alternative")


# ── Style factory ─────────────────────────────────────────────────────────────

def _S() -> dict:
    return {
        # Page title
        "title": ParagraphStyle("vtitle", fontSize=20, textColor=ACCENT_LT,
                                 fontName="Helvetica-Bold", leading=24, spaceAfter=2),
        "subtitle": ParagraphStyle("vsub", fontSize=10, textColor=TEXT2, spaceAfter=6, leading=14),
        # Section headers
        "h2": ParagraphStyle("vh2", fontSize=14, textColor=TEXT,
                               fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=5, leading=18),
        # Vuln name inside banner (white)
        "banner_name": ParagraphStyle("vbn", fontSize=13, textColor=WHITE,
                                       fontName="Helvetica-Bold", leading=16),
        "banner_sev":  ParagraphStyle("vbs", fontSize=12, textColor=WHITE,
                                       fontName="Helvetica-Bold", leading=16),
        # Body text
        "body":  ParagraphStyle("vbody",  fontSize=10, textColor=TEXT,  leading=15, spaceAfter=4),
        "body2": ParagraphStyle("vbody2", fontSize=9,  textColor=TEXT2, leading=13, spaceAfter=3),
        # Section labels (Finding / Remediation / References)
        "label": ParagraphStyle("vlbl", fontSize=9, textColor=TEXT2,
                                  fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=3,
                                  leading=12),
        # "How to Reproduce" heading
        "repro_heading": ParagraphStyle("vrh", fontSize=11, textColor=ACCENT_LT,
                                          fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=6,
                                          leading=14),
        # Numbered steps (normal text)
        "step": ParagraphStyle("vstep", fontSize=10, textColor=TEXT, leading=16,
                                 leftIndent=12, spaceAfter=3),
        # Step label lines (Expected: / Tool:)
        "step_lbl": ParagraphStyle("vsteplbl", fontSize=9, textColor=TEXT3, leading=13,
                                     leftIndent=12, spaceAfter=2, fontName="Helvetica-Oblique"),
        # Code blocks
        "code": ParagraphStyle("vcode", fontSize=8, textColor=ACCENT_LT,
                                 fontName="Courier", leading=12,
                                 leftIndent=8, rightIndent=8, spaceAfter=2),
        # Remediation
        "remed": ParagraphStyle("vremed", fontSize=9, textColor=TEXT3,
                                  fontName="Helvetica-Oblique", leading=13,
                                  leftIndent=10, spaceAfter=3),
        # TOC rows
        "toc_head": ParagraphStyle("vtoch", fontSize=12, textColor=TEXT,
                                     fontName="Helvetica-Bold", spaceAfter=4, leading=16),
        "toc_row":  ParagraphStyle("vtocr", fontSize=10, textColor=TEXT, leading=14),
    }


# ── Table helpers ─────────────────────────────────────────────────────────────

def _meta_table_style() -> TableStyle:
    return TableStyle([
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("BACKGROUND",  (0, 0), (-1, -1), BG_CARD),
        ("TEXTCOLOR",   (0, 0), (-1, -1), TEXT),
        ("GRID",        (0, 0), (-1, -1), 0.3, BORDER),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [BG_CARD, BG_ROW2]),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",(0, 0), (-1, -1), 8),
    ])


def _counts_table_style(n_vuln: int, n_passed: int) -> TableStyle:
    ts = TableStyle([
        ("FONTNAME",    (0, 0), (-1,  0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("BACKGROUND",  (0, 0), (-1,  0), colors.HexColor("#313244")),
        ("BACKGROUND",  (0, 1), (-1, -1), BG_CARD),
        ("TEXTCOLOR",   (0, 0), (-1, -1), TEXT),
        ("GRID",        (0, 0), (-1, -1), 0.3, BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_CARD, BG_ROW2]),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ])
    if n_vuln > 0:
        ts.add("TEXTCOLOR", (1, 2), (1, 2), SEVERITY_COLORS["high"])
        ts.add("FONTNAME",  (1, 2), (1, 2), "Helvetica-Bold")
    if n_passed > 0:
        ts.add("TEXTCOLOR", (1, 3), (1, 3), GREEN)
    return ts


def _code_box(text: str, doc_width: float) -> Table:
    """Render a line as a dark code block."""
    # Break long lines at ~90 chars
    chunks = [text[i:i+90] for i in range(0, len(text), 90)]
    content = "\n".join(chunks)
    s = _S()
    tbl = Table([[Paragraph(_esc(content), s["code"])]], colWidths=[doc_width])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), BG_CODE),
        ("GRID",          (0, 0), (-1, -1), 0.5, BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
    ]))
    return tbl


def _finding_box(text: str, sev_color: colors.Color, doc_width: float) -> Table:
    """Render finding text in a card with severity-colored left border."""
    s = _S()
    tbl = Table([[Paragraph(_esc(text), s["body"])]], colWidths=[doc_width])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), BG_CARD),
        ("LINEBEFORE",    (0, 0), (0, -1),  3, sev_color),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
    ]))
    return tbl


def _remed_box(text: str, doc_width: float) -> Table:
    """Render remediation text with green left border."""
    s = _S()
    tbl = Table([[Paragraph(_esc(text), s["remed"])]], colWidths=[doc_width])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), BG_CARD),
        ("LINEBEFORE",    (0, 0), (0, -1),  2, GREEN),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
    ]))
    return tbl


def _severity_banner(sev: str, vuln_name_str: str, doc_width: float) -> Table:
    """Full-width colored banner: [SEV PILL | VULN NAME]."""
    s = _S()
    sev_color = _sev_color(sev)
    banner = Table(
        [[
            Paragraph(_esc(f" {sev.upper()} "), s["banner_sev"]),
            Paragraph(_esc(f"  {vuln_name_str}"), s["banner_name"]),
        ]],
        colWidths=[22 * mm, doc_width - 22 * mm],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), sev_color),
        ("TOPPADDING",    (0, 0), (-1, -1),  8),
        ("BOTTOMPADDING", (0, 0), (-1, -1),  8),
        ("LEFTPADDING",   (0, 0), (-1, -1),  10),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
    ]))
    return banner


# ── Main ──────────────────────────────────────────────────────────────────────

def generate_pdf(session: dict, target: dict, results: list[dict], scanned_by: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=PAGE_MARGIN, bottomMargin=PAGE_MARGIN + 6 * mm,  # extra for page number
        leftMargin=PAGE_MARGIN, rightMargin=PAGE_MARGIN,
    )
    DW = doc.width   # usable width
    s  = _S()
    story: list = []

    # ── Classify results ──────────────────────────────────────────────────────
    vulns      = sorted([r for r in results if _is_vuln(r)],
                        key=lambda r: SEVERITY_ORDER.index((r.get("severity") or "info").lower()))
    needs_info = [r for r in results if r.get("status") == "needs_info"]
    passed     = [r for r in results if _is_passed(r)]
    failed     = [r for r in results if r.get("status") == "failed"]

    total_checks = len(results)
    n_vuln  = len(vulns)
    n_passed = len(passed)
    n_needs = len(needs_info) + len(failed)

    sev_counts = {sv: 0 for sv in SEVERITY_ORDER}
    for r in vulns:
        sv = (r.get("severity") or "info").lower()
        sev_counts[sv] = sev_counts.get(sv, 0) + 1

    risk_label, risk_color = _overall_risk(results)

    # ═══════════════════════════════════════════════════════════════
    # PAGE 1 — Executive Summary
    # ═══════════════════════════════════════════════════════════════

    story.append(Paragraph("🛡 VulnLab Security Scan Report", s["title"]))
    story.append(Paragraph("Automated OWASP Top 10 Security Assessment", s["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=ACCENT, spaceAfter=5))
    story.append(Spacer(1, 4 * mm))

    # Scan details
    story.append(Paragraph("Scan Details", s["h2"]))
    meta_data = [
        ["Target Name",   target.get("target_name", "—")],
        ["Target URL",    target.get("target_url",  "—")],
        ["Scan ID",       str(session.get("id", "—"))],
        ["Started",       str(session.get("started_at",  ""))[:19]],
        ["Completed",     str(session.get("completed_at") or "")[:19] or "—"],
        ["Scanned By",    scanned_by],
        ["Generated",     datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
    ]
    meta_tbl = Table(meta_data, colWidths=[38 * mm, DW - 38 * mm])
    meta_tbl.setStyle(_meta_table_style())
    story.append(meta_tbl)
    story.append(Spacer(1, 5 * mm))

    # Counts
    story.append(Paragraph("Summary", s["h2"]))
    counts_data = [
        ["Metric", "Count"],
        ["Total checks run",      str(total_checks)],
        ["Vulnerabilities found", str(n_vuln)],
        ["Passed / No issue",     str(n_passed)],
        ["Needs manual review",   str(n_needs)],
    ]
    counts_tbl = Table(counts_data, colWidths=[85 * mm, 35 * mm])
    counts_tbl.setStyle(_counts_table_style(n_vuln, n_passed))
    story.append(counts_tbl)
    story.append(Spacer(1, 4 * mm))

    # Severity breakdown
    if any(sev_counts[sv] for sv in SEVERITY_ORDER[:-1]):
        story.append(Paragraph("Severity Breakdown", s["h2"]))
        sev_rows = [["Severity", "Count"]]
        for sv in SEVERITY_ORDER[:-1]:
            if sev_counts[sv]:
                sev_rows.append([sv.title(), str(sev_counts[sv])])
        sev_tbl = Table(sev_rows, colWidths=[55 * mm, 30 * mm])
        sev_style = TableStyle([
            ("FONTNAME",  (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",  (0, 0), (-1, -1), 9),
            ("BACKGROUND",(0, 0), (-1, 0), colors.HexColor("#313244")),
            ("TEXTCOLOR", (0, 0), (-1, -1), TEXT),
            ("GRID",      (0, 0), (-1, -1), 0.3, BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_CARD, BG_ROW2]),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ])
        for i, sv in enumerate([r[0].lower() for r in sev_rows[1:]], start=1):
            sev_style.add("TEXTCOLOR", (0, i), (0, i), _sev_color(sv))
            sev_style.add("FONTNAME",  (0, i), (0, i), "Helvetica-Bold")
        sev_tbl.setStyle(sev_style)
        story.append(sev_tbl)
        story.append(Spacer(1, 4 * mm))

    # Overall risk
    story.append(Paragraph("Overall Risk Rating", s["h2"]))
    risk_tbl = Table(
        [[Paragraph(f"  {risk_label}", ParagraphStyle(
            "risk_rating", fontSize=20, textColor=risk_color,
            fontName="Helvetica-Bold", leading=24))]],
        colWidths=[DW],
    )
    risk_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), BG_CARD),
        ("LINEBEFORE",    (0, 0), (0, -1),  5, risk_color),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING",   (0, 0), (-1, -1), 16),
        ("GRID",          (0, 0), (-1, -1), 0.3, BORDER),
    ]))
    story.append(risk_tbl)
    story.append(Spacer(1, 4 * mm))

    if not vulns and not needs_info:
        story.append(Paragraph("✓ No vulnerabilities detected in this scan.", s["body"]))

    # ═══════════════════════════════════════════════════════════════
    # PAGE 2 — Table of Contents
    # ═══════════════════════════════════════════════════════════════

    story.append(PageBreak())
    story.append(Paragraph("Table of Contents", s["h2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=5))
    story.append(Spacer(1, 3 * mm))

    if vulns or needs_info:
        story.append(Paragraph("Vulnerabilities Found", s["toc_head"]))
        toc_rows = [["Vulnerability", "Severity"]]
        for r in vulns:
            sev = (r.get("severity") or "—").title()
            toc_rows.append([_vuln_name(r.get("vuln_type", "")), sev])
        for r in needs_info:
            toc_rows.append([_vuln_name(r.get("vuln_type", "")), "Needs Info"])
        toc_tbl = Table(toc_rows, colWidths=[DW - 40 * mm, 40 * mm])
        toc_style = TableStyle([
            ("FONTNAME",  (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",  (0, 0), (-1, -1), 10),
            ("BACKGROUND",(0, 0), (-1, 0), colors.HexColor("#313244")),
            ("TEXTCOLOR", (0, 0), (-1, -1), TEXT),
            ("GRID",      (0, 0), (-1, -1), 0.3, BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_CARD, BG_ROW2]),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ])
        for i, r in enumerate(vulns, start=1):
            sv = (r.get("severity") or "info").lower()
            toc_style.add("TEXTCOLOR", (1, i), (1, i), _sev_color(sv))
            toc_style.add("FONTNAME",  (1, i), (1, i), "Helvetica-Bold")
        for i in range(len(vulns) + 1, len(toc_rows)):
            toc_style.add("TEXTCOLOR", (1, i), (1, i), SEVERITY_COLORS["medium"])
        toc_tbl.setStyle(toc_style)
        story.append(toc_tbl)
        story.append(Spacer(1, 5 * mm))

    if passed:
        story.append(Paragraph("Passed Checks", s["toc_head"]))
        ptoc_rows = [["Vulnerability", "Status"]]
        for r in passed:
            ptoc_rows.append([_vuln_name(r.get("vuln_type", "")), "✓ Passed"])
        ptoc_tbl = Table(ptoc_rows, colWidths=[DW - 40 * mm, 40 * mm])
        ptoc_style = TableStyle([
            ("FONTNAME",  (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",  (0, 0), (-1, -1), 10),
            ("BACKGROUND",(0, 0), (-1, 0), colors.HexColor("#313244")),
            ("TEXTCOLOR", (0, 0), (-1, -1), TEXT),
            ("GRID",      (0, 0), (-1, -1), 0.3, BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_CARD, BG_ROW2]),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ])
        for i in range(1, len(ptoc_rows)):
            ptoc_style.add("TEXTCOLOR", (1, i), (1, i), GREEN)
            ptoc_style.add("FONTNAME",  (1, i), (1, i), "Helvetica-Bold")
        ptoc_tbl.setStyle(ptoc_style)
        story.append(ptoc_tbl)

    # ═══════════════════════════════════════════════════════════════
    # PAGES 3+ — Findings
    # ═══════════════════════════════════════════════════════════════

    if vulns or needs_info:
        story.append(PageBreak())
        story.append(Paragraph("Vulnerability Findings", s["h2"]))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=3))
        story.append(Spacer(1, 4 * mm))

        for r in vulns + needs_info:
            sev = (r.get("severity") or "info").lower()
            sev_col = _sev_color(sev)
            vuln_name_str = _vuln_name(r.get("vuln_type", ""))
            findings_obj  = r.get("findings") or {}
            finding_text  = findings_obj.get("summary", "")
            detail_text   = findings_obj.get("detail", "")
            scenario      = findings_obj.get("scenario", {})
            defense_tips  = scenario.get("defense_tips", [])
            reproduce     = _clean_steps(r.get("reproduce_steps") or [])
            missing       = r.get("missing_info", "")
            owasp_ref     = get_owasp_ref(r.get("vuln_type", ""))
            remediation   = get_remediation(r.get("vuln_type", ""))

            # ── Severity banner ───────────────────────────────────────────────
            story.append(_severity_banner(sev, vuln_name_str, DW))
            story.append(Spacer(1, 4 * mm))

            # ── Finding section ───────────────────────────────────────────────
            story.append(Paragraph("FINDING", s["label"]))
            finding_display = finding_text or missing or "See reproduce steps below."
            story.append(_finding_box(finding_display, sev_col, DW))
            if detail_text:
                story.append(Spacer(1, 2 * mm))
                story.append(Paragraph(_esc(detail_text), s["body2"]))

            # ── How to Reproduce ──────────────────────────────────────────────
            if reproduce:
                story.append(Paragraph("How to Reproduce", s["repro_heading"]))
                for step in reproduce:
                    step = step.strip()
                    if not step:
                        continue
                    if _is_code_line(step):
                        story.append(_code_box(step, DW))
                        story.append(Spacer(1, 1 * mm))
                    elif _step_is_label(step):
                        story.append(Paragraph(_esc(step), s["step_lbl"]))
                    else:
                        # Detect inline curl/code embedded in numbered step
                        if re.search(r"curl |http[s]?://|<[a-zA-Z]", step):
                            story.append(_code_box(step, DW))
                            story.append(Spacer(1, 1 * mm))
                        else:
                            story.append(Paragraph(_esc(step), s["step"]))

            # ── Remediation ───────────────────────────────────────────────────
            story.append(Paragraph("REMEDIATION", s["label"]))
            tips_text = "; ".join(defense_tips[:2]) if defense_tips else remediation
            story.append(_remed_box(tips_text, DW))

            # ── References ────────────────────────────────────────────────────
            story.append(Spacer(1, 2 * mm))
            story.append(Paragraph("REFERENCES", s["label"]))
            story.append(Paragraph(
                f'<a href="{owasp_ref}"><font color="#a78bfa"><u>{_esc(owasp_ref)}</u></font></a>',
                ParagraphStyle("ref", fontSize=9, leading=13, spaceAfter=2)))

            # ── Divider ───────────────────────────────────────────────────────
            story.append(Spacer(1, 6 * mm))
            story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
            story.append(Spacer(1, 6 * mm))

    # ═══════════════════════════════════════════════════════════════
    # LAST PAGE — Passed Checks
    # ═══════════════════════════════════════════════════════════════

    if passed:
        story.append(PageBreak())
        story.append(Paragraph("Passed Checks", s["h2"]))
        story.append(Paragraph(
            "The following vulnerability checks found no issues during this scan.", s["body2"]))
        story.append(Spacer(1, 3 * mm))

        pr_rows = [["Check", "Status", "Note"]]
        for r in passed:
            note = _esc((r.get("findings") or {}).get("summary", "No issue detected"))
            note = note[:100] + "…" if len(note) > 100 else note
            pr_rows.append([_vuln_name(r.get("vuln_type", "")), "✓ PASSED", note])

        pr_tbl = Table(pr_rows, colWidths=[52 * mm, 22 * mm, DW - 74 * mm])
        pr_style = TableStyle([
            ("FONTNAME",  (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",  (0, 0), (-1, -1), 9),
            ("BACKGROUND",(0, 0), (-1, 0), colors.HexColor("#313244")),
            ("TEXTCOLOR", (0, 0), (-1, -1), TEXT),
            ("GRID",      (0, 0), (-1, -1), 0.3, BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_CARD, BG_ROW2]),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ])
        for i in range(1, len(pr_rows)):
            pr_style.add("TEXTCOLOR", (1, i), (1, i), GREEN)
            pr_style.add("FONTNAME",  (1, i), (1, i), "Helvetica-Bold")
        pr_tbl.setStyle(pr_style)
        story.append(pr_tbl)

    doc.build(story, canvasmaker=_PageNumCanvas)
    return buf.getvalue()
