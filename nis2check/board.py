"""One-page board report for an assessment.

The page is a management summary: overall score, score by area, the five
largest gaps, the move since the previous assessment, and the Article 20
duty of the management body.

Directive (EU) 2022/2555, Article 20 (OJ L 333, 27.12.2022, p. 80): the
management body approves the cybersecurity risk-management measures, oversees
their implementation, and can be held liable for infringements of Article 21.
Its members must follow training. National rules on the liability of public
institutions and officials are unaffected.

PDF rendering uses fpdf2, which is pure Python and does not need the system
libraries WeasyPrint uses for the long-form report.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

ARTICLE_20 = (
    "Article 20 of Directive (EU) 2022/2555: the management body approves the "
    "cybersecurity risk-management measures taken to comply with Article 21, "
    "oversees their implementation, and can be held liable for infringements of "
    "that article. Its members are required to follow training. National law on "
    "the liability of public institutions, public servants and elected or appointed "
    "officials is unaffected."
)

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def format_date(value: dt.date) -> str:
    return f"{value.day:02d} {_MONTHS[value.month - 1]} {value.year}"


def pdf_text(value: str) -> str:
    """Helvetica in the board PDF is a Latin-1 font."""
    return (value or "").encode("latin-1", "replace").decode("latin-1")


@dataclass(frozen=True)
class AreaScore:
    title: str
    article: str
    score: float | None


@dataclass(frozen=True)
class GapLine:
    ref: str
    text: str
    owner: str
    due: dt.date | None

    @property
    def owner_label(self) -> str:
        return self.owner or "Not set"

    @property
    def due_label(self) -> str:
        return format_date(self.due) if self.due else "Not set"


@dataclass
class BoardReport:
    org_name: str
    assessed_on: dt.date
    score: float | None
    verified: float | None
    areas: list[AreaScore]
    gaps: list[GapLine]
    trend: str
    accountability: str = ARTICLE_20


def trend_sentence(current: float | None, previous_score: float | None, previous_on: dt.date | None) -> str:
    if current is None or previous_score is None or previous_on is None:
        return "No earlier assessment is on record."
    delta = current - previous_score
    when = format_date(previous_on)
    if abs(delta) < 0.05:
        return f"Unchanged from {previous_score:.0f}% on {when}."
    direction = "Up" if delta > 0 else "Down"
    return f"{direction} {abs(delta):.0f} points from {previous_score:.0f}% on {when}."


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0f}%"


def build_board(result, org_name: str, assessed_on: dt.date, previous, actions: dict) -> BoardReport:
    """``previous`` is an older snapshot, or None. ``actions`` maps question id to owner and due date."""
    gaps = []
    for finding in result.gaps[:5]:
        action = actions.get(finding.question.id)
        gaps.append(GapLine(
            ref=finding.question.id,
            text=finding.question.text,
            owner=(action.owner if action else ""),
            due=(action.due_on if action else None),
        ))
    previous_score = previous.score_pct if previous is not None else None
    previous_on = previous.taken_at.date() if previous is not None else None
    return BoardReport(
        org_name=org_name or "Organisation",
        assessed_on=assessed_on,
        score=result.score_pct,
        verified=result.verified_pct,
        areas=[AreaScore(area.domain.title, area.domain.article, area.score_pct) for area in result.domains],
        gaps=gaps,
        trend=trend_sentence(result.score_pct, previous_score, previous_on),
    )


def render_board_pdf(report: BoardReport) -> bytes:
    """A single A4 page. Raises if the content does not fit."""
    from fpdf import FPDF

    pdf = FPDF(format="A4", unit="mm")
    pdf.set_compression(False)
    pdf.set_auto_page_break(auto=False)
    pdf.set_margins(14, 12, 14)
    pdf.add_page()
    width = pdf.w - 28

    def text(content: str, size: int = 9, height: float = 4.5, bold: bool = False, navy: bool = False):
        pdf.set_font("Helvetica", "B" if bold else "", size)
        pdf.set_text_color(22, 40, 90) if navy else pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(width, height, pdf_text(content), new_x="LMARGIN", new_y="NEXT")

    pdf.set_fill_color(22, 40, 90)
    pdf.rect(0, 0, 210, 3, style="F")
    pdf.set_y(10)
    text("Board report", 11, 5, bold=True, navy=True)
    text(report.org_name, 16, 7, bold=True)
    text(f"NIS2 gap assessment, {format_date(report.assessed_on)}", 9, 4.5)
    pdf.ln(1)
    text(f"Overall score {_pct(report.score)}", 14, 7, bold=True, navy=True)
    text(f"Evidence-backed score {_pct(report.verified)}. {report.trend}", 9, 4.5)
    pdf.ln(1)
    text("Score by area", 11, 5, bold=True)

    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(0, 0, 0)
    name_w, article_w, score_w = width - 42, 28, 14
    for area in report.areas:
        y = pdf.get_y()
        if y > 262:
            raise RuntimeError("board report does not fit on one page")
        pdf.set_xy(14, y)
        pdf.cell(name_w, 5, pdf_text(area.title)[:48], border=0)
        pdf.cell(article_w, 5, pdf_text(area.article))
        pdf.cell(score_w, 5, _pct(area.score), align="R", new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(220, 220, 220)
        pdf.line(14, pdf.get_y(), 14 + width, pdf.get_y())

    pdf.ln(2)
    text("Top gaps", 11, 5, bold=True)
    if not report.gaps:
        text("No open gaps.", 9, 4.5)
    for index, gap in enumerate(report.gaps, start=1):
        if pdf.get_y() > 268:
            raise RuntimeError("board report does not fit on one page")
        short = gap.text if len(gap.text) <= 88 else gap.text[:87].rstrip() + "..."
        text(f"{index}. {gap.ref}  {short}", 8, 4, bold=True)
        text(f"Owner: {gap.owner_label}    Due: {gap.due_label}", 8, 4)

    pdf.ln(1)
    if pdf.get_y() > 250:
        raise RuntimeError("board report does not fit on one page")
    text(report.accountability, 8, 3.6)
    pdf.set_y(-12)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 4, pdf_text("nis2check. A self-assessment against Directive (EU) 2022/2555, not legal advice."), align="C")
    if pdf.page != 1:
        raise RuntimeError("board report does not fit on one page")
    return bytes(pdf.output())
