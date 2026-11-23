"""Article 23(4) incident clocks, and the Markdown and PDF for each report.

Directive (EU) 2022/2555, Article 23(4) (OJ L 333, 27.12.2022, p. 80):

* an early warning within 24 hours of becoming aware of the significant incident;
* an incident notification within 72 hours of becoming aware;
* a final report not later than one month after the incident notification was submitted.

Article 23(4) states the periods and does not set the hour at which a month ends.
This helper counts 24 hours and 72 hours from the moment of awareness, and counts
one month as the same clock time on the same date in the following month, or the
last day of that month when that date does not exist. It does not move a deadline
that falls on a Saturday, Sunday or holiday. This is an operational helper, not
legal advice.

Times are naive UTC.
"""

from __future__ import annotations

import datetime as dt
import calendar
from dataclasses import dataclass

EARLY = "early_warning"
NOTIFICATION = "notification"
INTERMEDIATE = "intermediate"
FINAL = "final"
PROGRESS = "progress"

STAGES = (EARLY, NOTIFICATION, INTERMEDIATE, FINAL, PROGRESS)
STAGE_LABELS = {
    EARLY: "Early warning",
    NOTIFICATION: "Incident notification",
    INTERMEDIATE: "Intermediate report",
    FINAL: "Final report",
    PROGRESS: "Progress report",
}
STAGE_ARTICLES = {
    EARLY: "Art. 23(4)(a)",
    NOTIFICATION: "Art. 23(4)(b)",
    INTERMEDIATE: "Art. 23(4)(c)",
    FINAL: "Art. 23(4)(d)",
    PROGRESS: "Art. 23(4)(e)",
}
CHOICES = ("yes", "no", "unknown")
CHOICE_LABELS = {"yes": "Yes", "no": "No", "unknown": "Not yet known", "": "Not answered"}
STATUS_LABELS = {
    "open": "Open",
    "overdue": "Overdue",
    "on_time": "Submitted on time",
    "late": "Submitted late",
    "recorded": "Recorded",
    "not_recorded": "Not recorded",
}

DISCLAIMER = (
    "This follows Article 23(4) of Directive (EU) 2022/2555. "
    "National transposition can set a different reporting channel or a different way "
    "of counting a month. It is not legal advice. "
    "A trust service provider notifies an incident that affects its trust services "
    "within 24 hours (Art. 23(4), second subparagraph), rather than on the 72-hour clock."
)


class IncidentInputError(ValueError):
    """A time or a field on the incident form could not be read."""


def add_months(moment: dt.datetime, months: int) -> dt.datetime:
    """Same clock time, ``months`` later, clamped to the last day of the month."""
    if moment.tzinfo is not None:
        raise IncidentInputError("deadlines are computed from UTC times without a timezone")
    index = moment.month - 1 + months
    year, month = divmod(index, 12)
    year += moment.year
    month += 1
    day = min(moment.day, calendar.monthrange(year, month)[1])
    return moment.replace(year=year, month=month, day=day)


def deadline_status(due: dt.datetime, submitted: dt.datetime | None, now: dt.datetime) -> str:
    if submitted is None:
        return "overdue" if now >= due else "open"
    return "on_time" if submitted <= due else "late"


@dataclass(frozen=True)
class Clock:
    key: str
    title: str
    article: str
    due_at: dt.datetime | None
    provisional: bool
    submitted_at: dt.datetime | None
    status: str
    note: str

    @property
    def status_label(self) -> str:
        return STATUS_LABELS[self.status]


def incident_clocks(
    detected_at: dt.datetime,
    notification_submitted_at: dt.datetime | None,
    early_submitted_at: dt.datetime | None,
    final_submitted_at: dt.datetime | None,
    now: dt.datetime,
    handling_completed_at: dt.datetime | None = None,
    progress_submitted_at: dt.datetime | None = None,
    final_ongoing: bool = False,
    *,
    early_hours: int = 24,
    notification_hours: int = 72,
    final_days: int | None = None,
    further_days: int | None = None,
) -> list[Clock]:
    """The Art. 23(4) clocks, plus the further final report when handling ends later.

    ``early_hours``, ``notification_hours``, ``final_days`` and ``further_days``
    override the Directive only where a national file says the law differs.
    """
    early_due = detected_at + dt.timedelta(hours=early_hours)
    notification_due = detected_at + dt.timedelta(hours=notification_hours)
    if notification_submitted_at is not None:
        final_due = (
            notification_submitted_at + dt.timedelta(days=final_days)
            if final_days is not None else add_months(notification_submitted_at, 1)
        )
        final_provisional = False
        final_note = (
            f"{final_days} days after the incident notification was submitted."
            if final_days is not None else
            "One month after the incident notification was submitted."
        )
    else:
        final_due = (
            notification_due + dt.timedelta(days=final_days)
            if final_days is not None else add_months(notification_due, 1)
        )
        final_provisional = True
        final_span = f"{final_days} days" if final_days is not None else "one month"
        hour_span = f"{notification_hours}-hour"
        final_note = (
            f"Provisional, {final_span} after the {hour_span} deadline. "
            f"The report is due {final_span} after the notification is actually submitted."
        )
    clocks = [
        Clock(
            EARLY, STAGE_LABELS[EARLY], STAGE_ARTICLES[EARLY], early_due, False,
            early_submitted_at, deadline_status(early_due, early_submitted_at, now),
            f"Within {early_hours} hours of becoming aware. Say whether an unlawful or malicious "
            "cause is suspected, and whether there could be a cross-border impact.",
        ),
        Clock(
            NOTIFICATION, STAGE_LABELS[NOTIFICATION], STAGE_ARTICLES[NOTIFICATION],
            notification_due, False, notification_submitted_at,
            deadline_status(notification_due, notification_submitted_at, now),
            f"Within {notification_hours} hours of becoming aware. Update the early warning and give an "
            "initial assessment of severity and impact, and indicators of compromise where you have them.",
        ),
        Clock(
            FINAL, STAGE_LABELS[FINAL], STAGE_ARTICLES[FINAL], final_due, final_provisional,
            final_submitted_at, deadline_status(final_due, final_submitted_at, now),
            final_note,
        ),
    ]
    if handling_completed_at is not None or final_ongoing:
        further_span = f"{further_days} days" if further_days is not None else "one month"
        if handling_completed_at is not None:
            further_due = (
                handling_completed_at + dt.timedelta(days=further_days)
                if further_days is not None else add_months(handling_completed_at, 1)
            )
            clocks.append(Clock(
                "further_final", "Further final report", "Art. 23(4)(e)", further_due, False,
                None, deadline_status(further_due, None, now),
                "The incident was still ongoing when the final report was due. "
                f"A final report is due within {further_span} of handling it.",
            ))
        else:
            clocks.append(Clock(
                "further_final", "Further final report", "Art. 23(4)(e)", None, True,
                progress_submitted_at, "not_recorded" if progress_submitted_at is None else "recorded",
                "The incident was still ongoing. Record when handling finishes; "
                f"a final report is then due within {further_span}.",
            ))
    return clocks


def parse_utc(raw: str, client_tz: str = "", time_is_utc: str = "1") -> dt.datetime:
    """Read a form time into naive UTC.

    ``time_is_utc`` is ``1`` when the value is already UTC (tests, and browsers
    with JavaScript off). Otherwise ``raw`` is local time in ``client_tz``.
    """
    text = (raw or "").strip()
    if not text:
        raise IncidentInputError("time")
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise IncidentInputError("time") from exc
    if parsed.tzinfo is not None:
        return parsed.astimezone(dt.timezone.utc).replace(tzinfo=None, microsecond=0)
    parsed = parsed.replace(microsecond=0)
    if time_is_utc == "1" or not (client_tz or "").strip():
        return parsed
    try:
        from zoneinfo import ZoneInfo
        zone = ZoneInfo(client_tz.strip())
    except Exception as exc:  # unknown zone name, or a zoneinfo data gap
        raise IncidentInputError("time") from exc
    return parsed.replace(tzinfo=zone).astimezone(dt.timezone.utc).replace(tzinfo=None, microsecond=0)


def choice(value: str | None) -> str:
    text = (value or "").strip().lower()
    if text not in ("", *CHOICES):
        raise IncidentInputError("choice")
    return text


def clip(value: str | None, limit: int = 5000) -> str:
    return (value or "").strip()[:limit]


def report_markdown(incident, report, clocks: list[Clock], channel: str = "") -> str:
    """Markdown for one submitted stage. ``incident`` and ``report`` are the ORM rows."""
    label = STAGE_LABELS.get(report.stage, report.stage)
    article = STAGE_ARTICLES.get(report.stage, "Art. 23(4)")
    lines = [
        f"# {label}",
        "",
        f"Incident: {incident.title}",
        f"Detected (became aware), UTC: {_stamp(incident.detected_at)}",
        f"This report sent, UTC: {_stamp(report.submitted_at)}",
        f"Provision: {article} of Directive (EU) 2022/2555",
        "",
    ]
    if channel:
        lines += [channel.rstrip(), ""]
    if incident.summary:
        lines += ["## What happened", "", incident.summary, ""]
    fields = _field_lines(report)
    if fields:
        lines += ["## What Art. 23 asks for at this stage", ""]
        lines += fields
        lines.append("")
    lines += ["## Clocks", ""]
    for clock in clocks:
        due = _stamp(clock.due_at) + (" (provisional)" if clock.provisional else "") if clock.due_at else "Not set"
        sent = _stamp(clock.submitted_at) if clock.submitted_at else "Not submitted"
        lines.append(f"- {clock.title} ({clock.article}): due {due}. Status: {clock.status_label}. Sent: {sent}.")
    lines += ["", DISCLAIMER, ""]
    return "\n".join(lines)


def _field_lines(report) -> list[str]:
    rows = []
    if report.stage in (EARLY, NOTIFICATION, FINAL):
        if report.suspected_unlawful or report.stage == EARLY:
            rows.append(f"- Suspected unlawful or malicious cause: {CHOICE_LABELS.get(report.suspected_unlawful, report.suspected_unlawful)}")
        if report.cross_border or report.stage in (EARLY, FINAL):
            rows.append(f"- Cross-border impact: {CHOICE_LABELS.get(report.cross_border, report.cross_border)}")
    if report.stage == NOTIFICATION:
        rows.append(f"- Initial assessment of severity and impact: {report.severity_impact or 'Not provided'}")
        rows.append(f"- Indicators of compromise: {report.indicators or 'Not available'}")
    if report.stage == INTERMEDIATE:
        rows.append(report.body or "No status update recorded.")
    if report.stage == FINAL:
        rows.append(f"- Description, severity and impact: {report.severity_impact or 'Not provided'}")
        rows.append(f"- Threat or root cause: {report.root_cause or 'Not provided'}")
        rows.append(f"- Mitigation, applied and ongoing: {report.mitigation or 'Not provided'}")
        rows.append(f"- Still ongoing: {'Yes' if report.ongoing else 'No'}")
    if report.stage == PROGRESS:
        rows.append(report.body or "No progress recorded.")
        if report.handling_completed_at:
            rows.append(f"- Handling completed, UTC: {_stamp(report.handling_completed_at)}")
    return rows


def _stamp(moment: dt.datetime | None) -> str:
    if moment is None:
        return ""
    return moment.strftime("%Y-%m-%d %H:%M UTC")


def report_pdf(incident, report, clocks: list[Clock], channel: str = "") -> bytes:
    """A text PDF of one stage. Pure Python, so it does not need system libraries."""
    markdown = report_markdown(incident, report, clocks, channel)
    title = f"{STAGE_LABELS.get(report.stage, 'Report')}: {incident.title}"
    return text_pdf(title, markdown.splitlines())


def text_pdf(title: str, lines: list[str]) -> bytes:
    """A multi-page Helvetica PDF. Characters outside Latin-1 become '?'."""
    wrapped: list[str] = []
    for line in [title, ""] + list(lines):
        text = line.replace("\t", "    ")
        if not text:
            wrapped.append("")
            continue
        while len(text) > 95:
            cut = text.rfind(" ", 0, 95)
            if cut < 40:
                cut = 95
            wrapped.append(text[:cut])
            text = text[cut:].lstrip()
        wrapped.append(text)

    pages: list[list[str]] = []
    for offset in range(0, len(wrapped), 48):
        pages.append(wrapped[offset:offset + 48])
    if not pages:
        pages = [[""]]

    def escape(value: str) -> str:
        raw = value.encode("latin-1", "replace").decode("latin-1")
        return raw.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    font_obj = b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n"
    page_objs: list[bytes] = []
    content_objs: list[bytes] = []
    # Object numbers: 1 catalog, 2 pages, 3 font, then pairs of page/content.
    first_page = 4
    for index, page_lines in enumerate(pages):
        commands = ["BT", "/F1 11 Tf", "48 800 Td", "14 TL"]
        first = True
        for line in page_lines:
            if first:
                commands.append(f"({escape(line)}) Tj")
                first = False
            else:
                commands.append(f"T* ({escape(line)}) Tj")
        commands.append("ET")
        stream = "\n".join(commands).encode("latin-1", "replace")
        content_objs.append(
            f"{first_page + index * 2 + 1} 0 obj\n<< /Length {len(stream)} >>\nstream\n".encode("ascii")
            + stream + b"\nendstream\nendobj\n"
        )
        page_objs.append(
            (
                f"{first_page + index * 2} 0 obj\n"
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                f"/Contents {first_page + index * 2 + 1} 0 R "
                f"/Resources << /Font << /F1 3 0 R >> >> >>\nendobj\n"
            ).encode("ascii")
        )

    kids = " ".join(f"{first_page + i * 2} 0 R" for i in range(len(pages)))
    objects = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        f"2 0 obj\n<< /Type /Pages /Count {len(pages)} /Kids [{kids}] >>\nendobj\n".encode("ascii"),
        font_obj,
    ]
    for page_obj, content_obj in zip(page_objs, content_objs):
        objects.append(page_obj)
        objects.append(content_obj)

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(out))
        out += obj
    xref = len(out)
    out += f"xref\n0 {len(offsets)}\n".encode("ascii")
    out += b"0000000000 65535 f \n"
    for offset in offsets[1:]:
        out += f"{offset:010d} 00000 n \n".encode("ascii")
    out += (
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    ).encode("ascii")
    return bytes(out)
