"""PDF report generator for WAF++ PASS using ReportLab."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import KeepTogether

from wafpass import __version__
from wafpass.models import ControlResult, Report

# ── Logo path (resolved relative to this file so it works from any cwd) ───────
_LOGO_PATH = str(
    Path(__file__).parent.parent.parent
    / "waf2p.github.io" / "images" / "WAFpp_upscaled_1000.png"
)
# Pre-load once so ImageReader doesn't re-open on every page render
try:
    _LOGO_IMG = ImageReader(_LOGO_PATH)
except Exception:
    _LOGO_IMG = None  # graceful fallback if image not found

# ── Regulatory logos directory ────────────────────────────────────────────────
_REG_LOGOS_DIR = Path(__file__).parent.parent / "assets" / "regulatory"

# Cache of loaded regulatory logo ImageReaders (None means image not found)
_REG_LOGO_CACHE: dict[str, "ImageReader | None"] = {}


def _reg_logo(framework: str) -> "ImageReader | None":
    """Return an ImageReader for the given regulatory framework, or None."""
    if framework in _REG_LOGO_CACHE:
        return _REG_LOGO_CACHE[framework]
    slug = framework.lower()
    for ch in " /:().,":
        slug = slug.replace(ch, "_")
    # Remove duplicate underscores
    while "__" in slug:
        slug = slug.replace("__", "_")
    slug = slug.strip("_")
    img = None
    for ext in ("png", "jpg", "jpeg", "svg"):
        candidate = _REG_LOGOS_DIR / f"{slug}.{ext}"
        if candidate.exists():
            try:
                img = ImageReader(str(candidate))
            except Exception:
                img = None
            break
    _REG_LOGO_CACHE[framework] = img
    return img


# Palette of badge background colors cycling for frameworks without logos
_BADGE_COLORS = [
    colors.HexColor("#2b7fff"),  # blue
    colors.HexColor("#7c3aed"),  # violet
    colors.HexColor("#0891b2"),  # cyan
    colors.HexColor("#059669"),  # emerald
    colors.HexColor("#d97706"),  # amber
    colors.HexColor("#dc2626"),  # red
    colors.HexColor("#0f172a"),  # navy
    colors.HexColor("#be185d"),  # pink
]

# ── Brand palette ─────────────────────────────────────────────────────────────
C_NAVY     = colors.HexColor("#0f172a")
C_BLUE     = colors.HexColor("#2b7fff")
C_BLUE_LT  = colors.HexColor("#dbeafe")
C_GREEN    = colors.HexColor("#22c55e")
C_GREEN_LT = colors.HexColor("#dcfce7")
C_RED      = colors.HexColor("#ef4444")
C_RED_LT   = colors.HexColor("#fee2e2")
C_ORANGE   = colors.HexColor("#f97316")
C_ORANGE_LT= colors.HexColor("#ffedd5")
C_YELLOW   = colors.HexColor("#eab308")
C_YELLOW_LT= colors.HexColor("#fef9c3")
C_GREY     = colors.HexColor("#64748b")
C_GREY_LT  = colors.HexColor("#f1f5f9")
C_BORDER   = colors.HexColor("#e2e8f0")
C_WHITE    = colors.white
C_DARK     = colors.HexColor("#1e293b")

PAGE_W, PAGE_H = A4
MARGIN     = 2.0 * cm
CONTENT_W  = PAGE_W - 2 * MARGIN

SEVERITY_COLORS: dict[str, tuple] = {
    "critical": (C_RED,    C_RED_LT),
    "high":     (C_ORANGE, C_ORANGE_LT),
    "medium":   (C_YELLOW, C_YELLOW_LT),
    "low":      (C_BLUE,   C_BLUE_LT),
}
STATUS_COLORS: dict[str, tuple] = {
    "PASS": (C_GREEN,  C_GREEN_LT),
    "FAIL": (C_RED,    C_RED_LT),
    "SKIP": (C_GREY,   C_GREY_LT),
}
STATUS_ICON = {"PASS": "✓", "FAIL": "✗", "SKIP": "─"}


# ── Styles ────────────────────────────────────────────────────────────────────

def _styles() -> dict[str, ParagraphStyle]:
    base = dict(
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=C_DARK,
    )
    return {
        "h1": ParagraphStyle("h1", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 26,
            "leading": 32, "textColor": C_NAVY, "spaceAfter": 8}),
        "h2": ParagraphStyle("h2", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 16,
            "leading": 20, "textColor": C_NAVY, "spaceBefore": 18, "spaceAfter": 6}),
        "h3": ParagraphStyle("h3", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 12,
            "leading": 16, "textColor": C_DARK, "spaceBefore": 10, "spaceAfter": 4}),
        "body": ParagraphStyle("body", **{**base, "spaceAfter": 4}),
        "body_sm": ParagraphStyle("body_sm", **{**base, "fontSize": 9, "leading": 12}),
        "muted": ParagraphStyle("muted", **{**base,
            "fontSize": 9, "leading": 12, "textColor": C_GREY}),
        "code": ParagraphStyle("code", **{**base,
            "fontName": "Courier", "fontSize": 8, "leading": 11,
            "textColor": C_DARK, "backColor": C_GREY_LT,
            "borderPadding": (3, 5, 3, 5)}),
        "cover_sub": ParagraphStyle("cover_sub", **{**base,
            "fontSize": 14, "leading": 18, "textColor": C_GREY}),
        "cover_meta": ParagraphStyle("cover_meta", **{**base,
            "fontSize": 11, "leading": 16, "textColor": C_DARK}),
        "center": ParagraphStyle("center", **{**base, "alignment": TA_CENTER}),
        "right": ParagraphStyle("right", **{**base, "alignment": TA_RIGHT}),
        "pill_pass": ParagraphStyle("pill_pass", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 9,
            "textColor": C_GREEN, "alignment": TA_CENTER}),
        "pill_fail": ParagraphStyle("pill_fail", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 9,
            "textColor": C_RED, "alignment": TA_CENTER}),
        "pill_skip": ParagraphStyle("pill_skip", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 9,
            "textColor": C_GREY, "alignment": TA_CENTER}),
        "sev_critical": ParagraphStyle("sev_critical", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 8,
            "textColor": C_RED, "alignment": TA_CENTER}),
        "sev_high": ParagraphStyle("sev_high", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 8,
            "textColor": C_ORANGE, "alignment": TA_CENTER}),
        "sev_medium": ParagraphStyle("sev_medium", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 8,
            "textColor": C_YELLOW, "alignment": TA_CENTER}),
        "sev_low": ParagraphStyle("sev_low", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 8,
            "textColor": C_BLUE, "alignment": TA_CENTER}),
        "tbl_header": ParagraphStyle("tbl_header", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 8,
            "leading": 11, "textColor": C_WHITE, "alignment": TA_CENTER}),
        "tbl_header_left": ParagraphStyle("tbl_header_left", **{**base,
            "fontName": "Helvetica-Bold", "fontSize": 8,
            "leading": 11, "textColor": C_WHITE}),
    }


# ── Logo drawing helpers ──────────────────────────────────────────────────────

def _draw_logo(c: pdfcanvas.Canvas, x: float, y: float, size: float = 28) -> None:
    """Draw the WAF++ logo image at (x, y) with given size (square)."""
    c.saveState()
    if _LOGO_IMG is not None:
        c.drawImage(_LOGO_IMG, x, y, width=size, height=size, mask="auto")
    else:
        # Minimal fallback: dark square with "W"
        c.setFillColor(C_NAVY)
        c.rect(x, y, size, size, fill=1, stroke=0)
        c.setFillColor(C_WHITE)
        c.setFont("Helvetica-Bold", size * 0.55)
        c.drawCentredString(x + size / 2, y + size * 0.2, "W")
    c.restoreState()


def _draw_wordmark(c: pdfcanvas.Canvas, x: float, y: float, size: float = 28) -> None:
    """Draw logo image + 'WAF++' text wordmark."""
    _draw_logo(c, x, y, size)
    text_x = x + size + 5
    text_y = y + size * 0.24
    font_size = size * 0.52
    c.saveState()
    c.setFillColor(C_NAVY)
    c.setFont("Helvetica-Bold", font_size)
    c.drawString(text_x, text_y, "WAF")
    w_waf = c.stringWidth("WAF", "Helvetica-Bold", font_size)
    c.setFillColor(C_BLUE)
    c.drawString(text_x + w_waf, text_y, "++")
    c.restoreState()


# ── Page templates ─────────────────────────────────────────────────────────────

class _CoverCanvas:
    """Mixin applied during cover page rendering."""

    def __init__(self, generated_at: str):
        self.generated_at = generated_at

    def __call__(self, canvas: pdfcanvas.Canvas, doc: BaseDocTemplate) -> None:
        canvas.saveState()
        # Full navy background header band
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, PAGE_H - 8 * cm, PAGE_W, 8 * cm, fill=1, stroke=0)

        # Blue accent bar at very top
        canvas.setFillColor(C_BLUE)
        canvas.rect(0, PAGE_H - 4 * mm, PAGE_W, 4 * mm, fill=1, stroke=0)

        # Large logo in header
        _draw_logo(canvas, MARGIN, PAGE_H - 5.5 * cm, size=52)

        # "WAF++" in header
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 28)
        canvas.drawString(MARGIN + 62, PAGE_H - 3.8 * cm, "WAF")
        w = canvas.stringWidth("WAF", "Helvetica-Bold", 28)
        canvas.setFillColor(C_BLUE)
        canvas.drawString(MARGIN + 62 + w, PAGE_H - 3.8 * cm, "++")

        canvas.setFillColor(C_GREY_LT)
        canvas.setFont("Helvetica", 11)
        canvas.drawString(MARGIN + 62, PAGE_H - 5.1 * cm, "Architecture Review Report")

        # Bottom footer bar
        canvas.setFillColor(C_GREY_LT)
        canvas.rect(0, 0, PAGE_W, 1.8 * cm, fill=1, stroke=0)
        canvas.setFillColor(C_GREY)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(MARGIN, 0.65 * cm, f"Generated  {self.generated_at}  ·  WAF++ PASS v{__version__}")
        canvas.drawRightString(PAGE_W - MARGIN, 0.65 * cm, "waf2p.dev")
        canvas.restoreState()


class _PageCanvas:
    """Header/footer applied to all non-cover pages."""

    def __init__(self, generated_at: str):
        self.generated_at = generated_at

    def __call__(self, canvas: pdfcanvas.Canvas, doc: BaseDocTemplate) -> None:
        canvas.saveState()
        page_num = doc.page

        # Header line
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, PAGE_H - MARGIN + 4 * mm, PAGE_W - MARGIN, PAGE_H - MARGIN + 4 * mm)

        # Wordmark (small) top-left
        _draw_wordmark(canvas, MARGIN, PAGE_H - MARGIN + 5 * mm, size=16)

        # Report title top-right
        canvas.setFillColor(C_GREY)
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - MARGIN + 8 * mm,
                               "Architecture Review Report")

        # Footer line
        canvas.line(MARGIN, MARGIN - 4 * mm, PAGE_W - MARGIN, MARGIN - 4 * mm)

        # Footer left: date
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(C_GREY)
        canvas.drawString(MARGIN, MARGIN - 9 * mm,
                          f"WAF++ PASS v{__version__}  ·  {self.generated_at}")

        # Footer right: page number
        canvas.drawRightString(PAGE_W - MARGIN, MARGIN - 9 * mm, f"Page {page_num}")

        canvas.restoreState()


# ── Flowable helpers ──────────────────────────────────────────────────────────

def _hr(color=C_BORDER, thickness=0.5) -> HRFlowable:
    return HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=6)


def _status_pill(status: str, S: dict) -> Paragraph:
    icon = STATUS_ICON.get(status, "?")
    style_key = {"PASS": "pill_pass", "FAIL": "pill_fail", "SKIP": "pill_skip"}.get(status, "body_sm")
    return Paragraph(f"{icon} {status}", S[style_key])


def _severity_para(severity: str, S: dict) -> Paragraph:
    style_key = f"sev_{severity.lower()}"
    if style_key not in S:
        style_key = "body_sm"
    return Paragraph(severity.upper(), S[style_key])


def _section_header(title: str, S: dict) -> list:
    """Blue left-bordered section header."""
    return [
        Spacer(1, 4 * mm),
        Table(
            [[Paragraph(title, S["h2"])]],
            colWidths=[CONTENT_W],
            style=TableStyle([
                ("LEFTPADDING",  (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING",   (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
                ("LINEAFTER",    (0, 0), (0, 0), 0, C_WHITE),
                ("LINEBEFORE",   (0, 0), (0, 0), 3, C_BLUE),
                ("BACKGROUND",   (0, 0), (-1, -1), C_GREY_LT),
            ]),
        ),
        Spacer(1, 3 * mm),
    ]


# ── Cover page content ────────────────────────────────────────────────────────

def _cover_content(report: Report, S: dict, generated_at: str) -> list:
    """Flowables for the cover page body (below the drawn header band)."""
    elems = [
        Spacer(1, 9 * cm),  # clear the drawn header
        Paragraph("Architecture Review Report", S["h1"]),
        Paragraph("Infrastructure Security &amp; Compliance Assessment", S["cover_sub"]),
        Spacer(1, 1 * cm),
        _hr(C_BLUE, 1.5),
        Spacer(1, 6 * mm),
    ]

    meta = [
        ["Checked path",     str(report.path)],
        ["Report date",      generated_at],
        ["Controls loaded",  str(report.controls_loaded)],
        ["Controls run",     str(report.controls_run)],
        ["Tool version",     f"WAF++ PASS v{__version__}"],
    ]
    meta_table = Table(
        [[Paragraph(k, S["muted"]), Paragraph(v, S["body"])] for k, v in meta],
        colWidths=[4 * cm, CONTENT_W - 4 * cm],
        style=TableStyle([
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
            ("LINEBELOW",     (0, 0), (-1, -2), 0.4, C_BORDER),
        ]),
    )
    elems.append(meta_table)
    elems.append(Spacer(1, 1.5 * cm))

    # Quick-stat boxes: PASS / FAIL / SKIP
    stats = [
        (f"{report.total_pass}", "PASS", C_GREEN,  C_GREEN_LT),
        (f"{report.total_fail}", "FAIL", C_RED,    C_RED_LT),
        (f"{report.total_skip}", "SKIP", C_GREY,   C_GREY_LT),
    ]
    stat_cells = []
    for val, label, fg, bg in stats:
        cell = Table(
            [[Paragraph(val,   ParagraphStyle("sv", fontName="Helvetica-Bold",
                                              fontSize=32, leading=36, textColor=fg,
                                              alignment=TA_CENTER))],
             [Paragraph(label, ParagraphStyle("sl", fontName="Helvetica-Bold",
                                              fontSize=10, leading=14, textColor=fg,
                                              alignment=TA_CENTER))]],
            style=TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), bg),
                ("TOPPADDING",    (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
                ("ROUNDEDCORNERS", (0, 0), (-1, -1), 6),
            ]),
        )
        stat_cells.append(cell)

    box_w = (CONTENT_W - 2 * 0.5 * cm) / 3
    stat_row = Table(
        [stat_cells],
        colWidths=[box_w, box_w, box_w],
        style=TableStyle([
            ("LEFTPADDING",   (0, 0), (-1, -1), 4),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
            ("TOPPADDING",    (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]),
    )
    elems.append(stat_row)
    return elems


# ── Executive Summary ─────────────────────────────────────────────────────────

def _executive_summary(report: Report, S: dict) -> list:
    elems = [*_section_header("Executive Summary", S)]

    total_checks = report.check_pass + report.check_fail + report.check_skip

    # Two-column stats
    left = [
        ["Metric", "Controls", "Checks"],
        ["✓ Passed",
         str(report.total_pass),
         str(report.check_pass)],
        ["✗ Failed",
         str(report.total_fail),
         str(report.check_fail)],
        ["─ Skipped",
         str(report.total_skip),
         str(report.check_skip)],
        ["Total",
         str(report.controls_run),
         str(total_checks)],
    ]
    row_colors = [C_GREY_LT, C_GREEN_LT, C_RED_LT, C_YELLOW_LT, C_BLUE_LT]
    col_w = [CONTENT_W * 0.45, CONTENT_W * 0.275, CONTENT_W * 0.275]

    ts = TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("LEADING",       (0, 0), (-1, -1), 14),
        ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
        ("ALIGN",         (0, 0), (0, -1),  "LEFT"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("FONTNAME",      (0, -1), (-1, -1), "Helvetica-Bold"),
        ("BACKGROUND",    (0, -1), (-1, -1), C_BLUE_LT),
    ])
    for i, bg in enumerate(row_colors):
        ts.add("BACKGROUND", (0, i), (-1, i), bg)

    elems.append(Table([[Paragraph(str(v), S["body_sm"]) for v in row]
                         for row in left],
                        colWidths=col_w, style=ts))
    elems.append(Spacer(1, 5 * mm))

    # Pillar/severity breakdown
    pillars: dict[str, dict] = {}
    for cr in report.results:
        p = cr.control.pillar.capitalize()
        if p not in pillars:
            pillars[p] = {"PASS": 0, "FAIL": 0, "SKIP": 0}
        pillars[p][cr.status] = pillars[p].get(cr.status, 0) + 1

    if pillars:
        elems += _section_header("Pillar Breakdown", S)
        pill_rows = [["Pillar", "✓ Pass", "✗ Fail", "─ Skip"]]
        for pname, cnts in sorted(pillars.items()):
            pill_rows.append([pname, str(cnts["PASS"]), str(cnts["FAIL"]), str(cnts["SKIP"])])

        pts = TableStyle([
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 9),
            ("LEADING",       (0, 0), (-1, -1), 13),
            ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("BACKGROUND",    (0, 0), (-1, 0),  C_GREY_LT),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
        ])
        col_w2 = [CONTENT_W * 0.4, CONTENT_W * 0.2, CONTENT_W * 0.2, CONTENT_W * 0.2]
        elems.append(Table([[Paragraph(str(v), S["body_sm"]) for v in row]
                             for row in pill_rows],
                            colWidths=col_w2, style=pts))

    return elems


# ── Controls overview table ───────────────────────────────────────────────────

def _controls_overview(report: Report, S: dict) -> list:
    elems = [*_section_header("Controls Overview", S),
             Paragraph(
                 "All evaluated controls with their overall result. "
                 "Detailed findings for failed controls follow in the next section.",
                 S["muted"]),
             Spacer(1, 4 * mm)]

    header = ["ID", "Title", "Pillar", "Severity", "Status",
              "✓", "✗", "─"]
    rows = [header]
    for cr in report.results:
        c = cr.control
        rows.append([
            c.id,
            c.title[:42] + ("…" if len(c.title) > 42 else ""),
            c.pillar.capitalize(),
            c.severity.upper(),
            cr.status,
            str(sum(1 for r in cr.results if r.status == "PASS")),
            str(sum(1 for r in cr.results if r.status == "FAIL")),
            str(sum(1 for r in cr.results if r.status == "SKIP")),
        ])

    col_w = [2.4*cm, 6.2*cm, 1.8*cm, 1.6*cm, 1.4*cm, 0.7*cm, 0.7*cm, 0.7*cm]

    ts = TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("LEADING",       (0, 0), (-1, -1), 11),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("ALIGN",         (3, 0), (-1, -1), "CENTER"),
        ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
    ])
    # Color status and severity cells per row
    for i, cr in enumerate(report.results, start=1):
        sev = cr.control.severity.lower()
        sev_fg, sev_bg = SEVERITY_COLORS.get(sev, (C_GREY, C_GREY_LT))
        ts.add("BACKGROUND", (3, i), (3, i), sev_bg)
        ts.add("TEXTCOLOR",  (3, i), (3, i), sev_fg)
        ts.add("FONTNAME",   (3, i), (3, i), "Helvetica-Bold")

        st = cr.status
        st_fg, st_bg = STATUS_COLORS.get(st, (C_GREY, C_GREY_LT))
        ts.add("BACKGROUND", (4, i), (4, i), st_bg)
        ts.add("TEXTCOLOR",  (4, i), (4, i), st_fg)
        ts.add("FONTNAME",   (4, i), (4, i), "Helvetica-Bold")

    # Convert to Paragraph cells for wrapping (header row gets white text)
    para_rows = []
    for i, row in enumerate(rows):
        if i == 0:
            para_rows.append([
                Paragraph(str(cell), S["tbl_header_left"] if j == 0 else S["tbl_header"])
                for j, cell in enumerate(row)
            ])
        else:
            para_rows.append([Paragraph(str(cell), S["body_sm"]) for cell in row])

    elems.append(Table(para_rows, colWidths=col_w, style=ts))
    return elems


# ── Findings detail ───────────────────────────────────────────────────────────

def _findings_section(report: Report, S: dict) -> list:
    failing = [cr for cr in report.results if cr.status == "FAIL"]
    if not failing:
        elems = [*_section_header("Findings", S),
                 Paragraph("✓  No failures detected. All evaluated controls passed.", S["body"])]
        return elems

    elems = [*_section_header("Findings", S),
             Paragraph(
                 f"{len(failing)} control(s) produced findings that require attention. "
                 "Each finding includes the affected resource, the specific violation, "
                 "and remediation guidance.",
                 S["muted"]),
             Spacer(1, 4 * mm)]

    for cr in failing:
        c = cr.control
        sev_fg, sev_bg = SEVERITY_COLORS.get(c.severity.lower(), (C_GREY, C_GREY_LT))

        # Control header bar
        header_content = [
            [
                Paragraph(
                    f'<font name="Helvetica-Bold" size="11">{c.id}</font>'
                    f'  <font color="#{_hex(C_GREY)}" size="9">{c.title}</font>',
                    S["body"]),
                Paragraph(
                    f'<font name="Helvetica-Bold">{c.severity.upper()}</font>',
                    ParagraphStyle("sh", fontName="Helvetica-Bold", fontSize=8,
                                   textColor=sev_fg, alignment=TA_CENTER)),
            ]
        ]
        header_table = Table(
            header_content,
            colWidths=[CONTENT_W - 2 * cm, 2 * cm],
            style=TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), sev_bg),
                ("BACKGROUND",    (1, 0), (1, 0),   sev_bg),
                ("TOPPADDING",    (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING",   (0, 0), (0, 0),   10),
                ("RIGHTPADDING",  (-1, 0), (-1, 0), 8),
                ("LINEBEFORE",    (0, 0), (0, 0),   3, sev_fg),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]),
        )

        # Description
        desc_para = Paragraph(
            (c.description or "").strip().replace("\n", " ")[:350] + (
                "…" if len((c.description or "")) > 350 else ""),
            S["muted"])

        # Individual check result rows
        check_rows = []
        for r in cr.results:
            if r.status != "FAIL":
                continue
            st_fg, st_bg = STATUS_COLORS.get(r.status, (C_GREY, C_GREY_LT))
            check_rows.append([
                Paragraph(f'<font name="Helvetica-Bold">{r.status}</font>', ParagraphStyle(
                    "cs", fontName="Helvetica-Bold", fontSize=8,
                    textColor=st_fg, alignment=TA_CENTER)),
                Paragraph(f'<font name="Courier" size="8">{r.resource}</font>', S["body_sm"]),
                Paragraph(r.message or "", S["body_sm"]),
            ])

        if check_rows:
            check_ts = TableStyle([
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("LEADING",       (0, 0), (-1, -1), 11),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
                ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
                ("BACKGROUND",    (0, 0), (-1, -1), C_RED_LT),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ])
            check_table = Table(
                check_rows,
                colWidths=[1.3 * cm, 4.5 * cm, CONTENT_W - 5.8 * cm],
                style=check_ts,
            )
        else:
            check_table = None

        # Remediation box (first failing check's remediation)
        rem_text = next(
            (r.remediation for r in cr.results if r.status == "FAIL" and r.remediation), None
        )
        rem_block = None
        if rem_text:
            rem_para = Paragraph(
                "→ <b>Remediation:</b> " + rem_text.strip().replace("\n", " "),
                S["body_sm"])
            rem_block = Table(
                [[rem_para]],
                colWidths=[CONTENT_W],
                style=TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), C_BLUE_LT),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                    ("TOPPADDING",    (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LINEBEFORE",    (0, 0), (0, 0),   3, C_BLUE),
                ]),
            )

        block_items = [header_table, Spacer(1, 2 * mm), desc_para, Spacer(1, 2 * mm)]
        if check_table:
            block_items.append(check_table)
        if rem_block:
            block_items += [Spacer(1, 2 * mm), rem_block]
        block_items.append(Spacer(1, 6 * mm))

        elems.append(KeepTogether(block_items[:4]))  # header + desc always together
        if check_table:
            elems.append(check_table)
        if rem_block:
            elems += [Spacer(1, 2 * mm), rem_block]
        elems.append(Spacer(1, 6 * mm))

    return elems


# ── Passed controls appendix ──────────────────────────────────────────────────

def _passed_section(report: Report, S: dict) -> list:
    passed = [cr for cr in report.results if cr.status == "PASS"]
    skipped = [cr for cr in report.results if cr.status == "SKIP"]
    elems = [*_section_header("Passed Controls", S)]

    if passed:
        rows = [["Control ID", "Title", "Checks passed"]]
        for cr in passed:
            rows.append([
                cr.control.id,
                cr.control.title[:55] + ("…" if len(cr.control.title) > 55 else ""),
                str(sum(1 for r in cr.results if r.status == "PASS")),
            ])
        ts = TableStyle([
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("LEADING",       (0, 0), (-1, -1), 11),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("BACKGROUND",    (0, 0), (-1, 0),  C_GREEN),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREEN_LT]),
        ])
        col_w = [2.8 * cm, CONTENT_W - 5.8 * cm, 3 * cm]
        elems.append(Table(
            [
                [Paragraph(str(v), S["tbl_header_left"] if j == 0 else S["tbl_header"])
                 for j, v in enumerate(row)]
                if i == 0 else
                [Paragraph(str(v), S["body_sm"]) for v in row]
                for i, row in enumerate(rows)
            ],
            colWidths=col_w, style=ts))
    else:
        elems.append(Paragraph("No controls passed in this run.", S["muted"]))

    if skipped:
        elems += [Spacer(1, 5 * mm), *_section_header("Skipped Controls", S),
                  Paragraph(
                      "The following controls were skipped — either no matching Terraform "
                      "resources were found, or all assertions use operators not supported "
                      "in automated evaluation.",
                      S["muted"]),
                  Spacer(1, 3 * mm)]
        skip_rows = [["Control ID", "Title", "Reason"]]
        for cr in skipped:
            first_skip = next(
                (r.message for r in cr.results if r.status == "SKIP"),
                "No matching resources found.")
            skip_rows.append([cr.control.id,
                               cr.control.title[:45] + ("…" if len(cr.control.title) > 45 else ""),
                               first_skip[:80]])
        ts2 = TableStyle([
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("LEADING",       (0, 0), (-1, -1), 11),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("BACKGROUND",    (0, 0), (-1, 0),  C_GREY),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
        ])
        col_w2 = [2.8 * cm, CONTENT_W * 0.4, CONTENT_W - 2.8 * cm - CONTENT_W * 0.4]
        elems.append(Table(
            [
                [Paragraph(str(v), S["tbl_header_left"] if j == 0 else S["tbl_header"])
                 for j, v in enumerate(row)]
                if i == 0 else
                [Paragraph(str(v), S["body_sm"]) for v in row]
                for i, row in enumerate(skip_rows)
            ],
            colWidths=col_w2, style=ts2))

    return elems


# ── Regulatory Alignment section ─────────────────────────────────────────────

def _build_framework_map(report: Report) -> dict[str, dict]:
    """Aggregate per-framework data from all control results.

    Returns dict keyed by framework name:
        {"items": [ControlResult, ...], "PASS": int, "FAIL": int, "SKIP": int}
    """
    frameworks: dict[str, dict] = {}
    for cr in report.results:
        for reg in cr.control.regulatory_mapping:
            fname = reg.get("framework", "").strip()
            if not fname:
                continue
            if fname not in frameworks:
                frameworks[fname] = {"items": [], "PASS": 0, "FAIL": 0, "SKIP": 0}
            frameworks[fname]["items"].append(cr)
            frameworks[fname][cr.status] = frameworks[fname].get(cr.status, 0) + 1
    return frameworks


# Priority order for the 6 frameworks shown in the PDF cards.
# Only frameworks whose name matches one of these (case-insensitive prefix) will be shown.
_PRIORITY_FRAMEWORKS: list[str] = [
    "GDPR",
    "BSI C5:2020",
    "ISO 27001:2022",
    "EUCS (ENISA)",
    "SOC 2",
    "AWS Well-Architected Framework",
]


def _reg_framework_card(
    framework: str,
    data: dict,
    card_w: float,
    badge_color: colors.Color,
) -> Table:
    """Build a single regulatory framework card as a flat 3-column Table.

    Layout (3 equal columns, all rows span all cols except the stats row):
        Row 0 – header band: initials badge | framework name  (spans all 3)
        Row 1 – stats:        ✓ PASS  |  ✗ FAIL  |  ─ SKIP
        Row 2 – control IDs  (spans all 3)
    """
    col = card_w / 3  # each of the 3 equal columns

    initials = "".join(w[0].upper() for w in framework.split() if w)[:3]
    display_name = framework if len(framework) <= 30 else framework[:28] + "…"

    # Deduplicate control IDs, keeping first occurrence order
    seen_ids: set[str] = set()
    unique_crs = []
    for cr in data["items"]:
        if cr.control.id not in seen_ids:
            seen_ids.add(cr.control.id)
            unique_crs.append(cr)

    # Row 0 – header
    header_para = Paragraph(
        f'<font name="Helvetica-Bold" size="13" color="white">{initials}</font>'
        f'<font name="Helvetica" size="8" color="white">  {display_name}</font>',
        ParagraphStyle("ch", leading=16, alignment=TA_LEFT),
    )

    # Row 1 – stat cells (one per column, no span)
    def _stat_para(icon: str, count: int, fg: colors.Color) -> Paragraph:
        return Paragraph(
            f'<font name="Helvetica-Bold" size="9" color="#{_hex(fg)}">{icon} {count}</font>',
            ParagraphStyle("sp", leading=13, alignment=TA_CENTER),
        )

    pass_p = _stat_para("✓", data["PASS"], C_GREEN)
    fail_p = _stat_para("✗", data["FAIL"], C_RED)
    skip_p = _stat_para("─", data["SKIP"], C_GREY)

    # Row 2 – control IDs
    id_fragments = []
    for cr in unique_crs:
        st_fg = {"PASS": C_GREEN, "FAIL": C_RED, "SKIP": C_GREY}.get(cr.status, C_GREY)
        icon = STATUS_ICON.get(cr.status, "?")
        id_fragments.append(
            f'<font name="Courier" size="7" color="#{_hex(C_DARK)}">{cr.control.id}</font>'
            f'<font name="Helvetica" size="7" color="#{_hex(st_fg)}"> {icon}</font>'
        )
    ids_para = Paragraph(
        "  ·  ".join(id_fragments) if id_fragments else "—",
        ParagraphStyle("ci", leading=11, textColor=C_DARK),
    )

    # Logo image overrides initials in header if available
    logo_img = _reg_logo(framework)
    if logo_img is not None:
        from reportlab.platypus import Image as RLImage
        logo_size = 28.0
        header_para = Paragraph(
            f'<font name="Helvetica-Bold" size="9" color="white">  {display_name}</font>',
            ParagraphStyle("ch2", leading=14, alignment=TA_LEFT),
        )
        # We can't mix Image + Paragraph in a spanned cell simply, so fall back to
        # showing the initials alongside the name (logo dropped to avoid ReportLab
        # nested-image-in-span issues — place logo via background or separate row).
        header_para = Paragraph(
            f'<font name="Helvetica-Bold" size="13" color="white">{initials}</font>'
            f'<font name="Helvetica" size="8" color="white">  {display_name}</font>',
            ParagraphStyle("ch3", leading=16, alignment=TA_LEFT),
        )

    rows = [
        [header_para, "", ""],        # row 0 – header (will be spanned)
        [pass_p, fail_p, skip_p],     # row 1 – stats
        [ids_para, "", ""],           # row 2 – control IDs (will be spanned)
    ]

    ts = TableStyle([
        # Spans
        ("SPAN",          (0, 0), (2, 0)),
        ("SPAN",          (0, 2), (2, 2)),

        # Header band
        ("BACKGROUND",    (0, 0), (2, 0),  badge_color),
        ("TOPPADDING",    (0, 0), (2, 0),  10),
        ("BOTTOMPADDING", (0, 0), (2, 0),  10),
        ("LEFTPADDING",   (0, 0), (2, 0),  10),
        ("RIGHTPADDING",  (0, 0), (2, 0),  8),
        ("VALIGN",        (0, 0), (2, 0),  "MIDDLE"),

        # Stats row
        ("BACKGROUND",    (0, 1), (0, 1),  C_GREEN_LT),
        ("BACKGROUND",    (1, 1), (1, 1),  C_RED_LT),
        ("BACKGROUND",    (2, 1), (2, 1),  C_GREY_LT),
        ("TOPPADDING",    (0, 1), (2, 1),  6),
        ("BOTTOMPADDING", (0, 1), (2, 1),  6),
        ("LEFTPADDING",   (0, 1), (2, 1),  4),
        ("RIGHTPADDING",  (0, 1), (2, 1),  4),
        ("VALIGN",        (0, 1), (2, 1),  "MIDDLE"),
        ("LINEBELOW",     (0, 1), (2, 1),  0.4, C_BORDER),
        ("LINEABOVE",     (0, 1), (2, 1),  0.4, C_BORDER),

        # Controls row
        ("BACKGROUND",    (0, 2), (2, 2),  C_WHITE),
        ("TOPPADDING",    (0, 2), (2, 2),  7),
        ("BOTTOMPADDING", (0, 2), (2, 2),  8),
        ("LEFTPADDING",   (0, 2), (2, 2),  8),
        ("RIGHTPADDING",  (0, 2), (2, 2),  8),
        ("VALIGN",        (0, 2), (2, 2),  "TOP"),

        # Outer border in badge color
        ("BOX",           (0, 0), (-1, -1), 1.2, badge_color),
    ])

    return Table(rows, colWidths=[col, col, col], style=ts)


def _regulatory_alignment(report: Report, S: dict) -> list:
    """Build the Regulatory Alignment section flowables."""
    all_frameworks = _build_framework_map(report)
    if not all_frameworks:
        return []

    # Filter to priority frameworks only (max 6), in defined order
    frameworks: dict[str, dict] = {}
    for priority_name in _PRIORITY_FRAMEWORKS:
        # Match by exact name or case-insensitive prefix
        for fname, data in all_frameworks.items():
            if fname.lower().startswith(priority_name.lower()):
                if fname not in frameworks:
                    frameworks[fname] = data
                break
        if len(frameworks) == 6:
            break

    if not frameworks:
        return []

    elems: list = [
        *_section_header("Regulatory Alignment", S),
        Paragraph(
            "Overview of how WAF++ controls map to the key regulatory and industry frameworks. "
            "Each card shows the compliance posture (PASS / FAIL / SKIP) for all controls "
            "that reference the framework.",
            S["muted"]),
        Spacer(1, 5 * mm),
    ]

    # ── Summary table ─────────────────────────────────────────────────────────
    summary_rows = [["Framework", "Mapped Controls", "✓ Pass", "✗ Fail", "─ Skip"]]
    for fname, d in frameworks.items():
        total = d["PASS"] + d["FAIL"] + d["SKIP"]
        summary_rows.append([fname, str(total), str(d["PASS"]), str(d["FAIL"]), str(d["SKIP"])])

    sum_ts = TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("LEADING",       (0, 0), (-1, -1), 11),
        ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("BACKGROUND",    (0, 0), (-1, 0),  C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_GREY_LT]),
    ])
    for i, (fname, d) in enumerate(frameworks.items(), start=1):
        if d["FAIL"] > 0:
            sum_ts.add("TEXTCOLOR", (3, i), (3, i), C_RED)
            sum_ts.add("FONTNAME",  (3, i), (3, i), "Helvetica-Bold")
        if d["PASS"] > 0:
            sum_ts.add("TEXTCOLOR", (2, i), (2, i), C_GREEN)
            sum_ts.add("FONTNAME",  (2, i), (2, i), "Helvetica-Bold")

    sum_col_w = [CONTENT_W * 0.42, CONTENT_W * 0.15, CONTENT_W * 0.15,
                 CONTENT_W * 0.14, CONTENT_W * 0.14]
    elems.append(Table(
        [[Paragraph(str(v), S["tbl_header_left"] if j == 0 else S["tbl_header"])
          for j, v in enumerate(row)]
         if i == 0 else
         [Paragraph(str(v), S["body_sm"]) for v in row]
         for i, row in enumerate(summary_rows)],
        colWidths=sum_col_w, style=sum_ts))

    elems.append(Spacer(1, 8 * mm))
    elems += _section_header("Framework Cards", S)
    elems.append(Paragraph(
        "Each card shows the framework initials, PASS / FAIL / SKIP counts, "
        "and the WAF++ control IDs that reference it.  "
        "Drop a logo PNG into <code>assets/regulatory/</code> to replace the initials badge.",
        S["muted"]))
    elems.append(Spacer(1, 4 * mm))

    # ── 2-column card grid ────────────────────────────────────────────────────
    # Each grid cell is card_outer_w wide.
    # A gap of `gap` pts separates the two columns:
    #   left cell:  RIGHTPADDING = gap/2  →  content = card_outer_w - gap/2
    #   right cell: LEFTPADDING  = gap/2  →  content = card_outer_w - gap/2
    # Total: 2 * card_outer_w = CONTENT_W  ✓
    gap = int(4 * mm)
    card_outer_w = CONTENT_W / 2
    card_w = card_outer_w - gap / 2   # actual card content width

    names = list(frameworks.keys())
    badge_cycle = _BADGE_COLORS
    card_rows = []
    for i in range(0, len(names), 2):
        left_name = names[i]
        right_name = names[i + 1] if i + 1 < len(names) else None
        left_card  = _reg_framework_card(left_name,  frameworks[left_name],  card_w, badge_cycle[i % len(badge_cycle)])
        right_card = _reg_framework_card(right_name, frameworks[right_name], card_w, badge_cycle[(i + 1) % len(badge_cycle)]) \
                     if right_name else Spacer(card_w, 1)
        card_rows.append([left_card, right_card])

    grid_ts = TableStyle([
        ("LEFTPADDING",   (0, 0), (0, -1), 0),
        ("RIGHTPADDING",  (0, 0), (0, -1), gap // 2),
        ("LEFTPADDING",   (1, 0), (1, -1), gap // 2),
        ("RIGHTPADDING",  (1, 0), (1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), gap),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ])
    elems.append(Table(card_rows, colWidths=[card_outer_w, card_outer_w], style=grid_ts))

    return elems


# ── Hex color helper ──────────────────────────────────────────────────────────

def _hex(color: colors.Color) -> str:
    """Return 6-char hex string for a ReportLab color (no #)."""
    return "{:02x}{:02x}{:02x}".format(
        int(color.red * 255), int(color.green * 255), int(color.blue * 255)
    )


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_pdf(report: Report, output_path: Path) -> None:
    """Generate a structured PDF report for the given WAF++ PASS report.

    Args:
        report: Completed Report object from the engine.
        output_path: Destination path for the PDF file.
    """
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    S = _styles()

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    cover_on_page  = _CoverCanvas(generated_at)
    normal_on_page = _PageCanvas(generated_at)

    # Content frame (inside margins, leaving room for header/footer)
    content_frame = Frame(
        MARGIN, MARGIN,
        CONTENT_W, PAGE_H - 2 * MARGIN,
        leftPadding=0, rightPadding=0,
        topPadding=8 * mm, bottomPadding=4 * mm,
    )

    cover_template  = PageTemplate(id="cover",  frames=[content_frame], onPage=cover_on_page)
    normal_template = PageTemplate(id="normal", frames=[content_frame], onPage=normal_on_page)

    doc = BaseDocTemplate(
        str(output_path),
        pagesize=A4,
        pageTemplates=[cover_template, normal_template],
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN,  bottomMargin=MARGIN,
        title="WAF++ Architecture Review Report",
        author=f"WAF++ PASS v{__version__}",
        subject="Infrastructure Security & Compliance Assessment",
        creator="waf2p.dev",
    )

    story: list = []

    # ── Cover ──────────────────────────────────────────────────────────────────
    story += _cover_content(report, S, generated_at)

    # ── Executive Summary ──────────────────────────────────────────────────────
    story += [NextPageTemplate("normal"), PageBreak()]
    story += _executive_summary(report, S)

    # ── Controls Overview ──────────────────────────────────────────────────────
    story += [PageBreak()]
    story += _controls_overview(report, S)

    # ── Regulatory Alignment ───────────────────────────────────────────────────
    reg_elems = _regulatory_alignment(report, S)
    if reg_elems:
        story += [PageBreak()]
        story += reg_elems

    # ── Findings ──────────────────────────────────────────────────────────────
    story += [PageBreak()]
    story += _findings_section(report, S)

    # ── Passed / Skipped appendix ──────────────────────────────────────────────
    story += [PageBreak()]
    story += _passed_section(report, S)

    doc.build(story)
