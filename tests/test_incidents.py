"""Article 23(4) clocks, including the month boundary on the final report."""

import datetime as dt

import pytest

from nis2check.incidents import (
    add_months, incident_clocks, parse_utc, report_markdown, report_pdf, text_pdf,
)


def test_add_months_clamps_to_the_last_day():
    assert add_months(dt.datetime(2026, 1, 31, 15, 30), 1) == dt.datetime(2026, 2, 28, 15, 30)
    assert add_months(dt.datetime(2024, 1, 31, 8, 0), 1) == dt.datetime(2024, 2, 29, 8, 0)
    assert add_months(dt.datetime(2026, 3, 31, 0, 0), 1) == dt.datetime(2026, 4, 30, 0, 0)
    assert add_months(dt.datetime(2026, 5, 31, 23, 15), 1) == dt.datetime(2026, 6, 30, 23, 15)
    assert add_months(dt.datetime(2026, 12, 31, 23, 0), 1) == dt.datetime(2027, 1, 31, 23, 0)
    assert add_months(dt.datetime(2026, 1, 15, 10, 0), 1) == dt.datetime(2026, 2, 15, 10, 0)


def test_clocks_are_24h_72h_and_one_month_after_the_notification():
    detected = dt.datetime(2026, 1, 31, 10, 0)
    now = detected
    clocks = {c.key: c for c in incident_clocks(detected, None, None, None, now)}
    assert clocks["early_warning"].due_at == dt.datetime(2026, 2, 1, 10, 0)
    assert clocks["notification"].due_at == dt.datetime(2026, 2, 3, 10, 0)
    # Provisional final report: one month after the 72-hour deadline.
    assert clocks["final"].provisional is True
    assert clocks["final"].due_at == dt.datetime(2026, 3, 3, 10, 0)
    assert clocks["early_warning"].status == "open"

    submitted = dt.datetime(2026, 1, 31, 18, 0)
    clocks = {c.key: c for c in incident_clocks(detected, submitted, None, None, submitted)}
    assert clocks["notification"].status == "on_time"
    assert clocks["final"].provisional is False
    # 31 January plus one month is 28 February, same time. Not one month after detection.
    assert clocks["final"].due_at == dt.datetime(2026, 2, 28, 18, 0)


def test_late_notification_and_overdue_early_warning():
    detected = dt.datetime(2026, 1, 15, 10, 0)
    submitted = dt.datetime(2026, 1, 20, 10, 0)  # 72 hours ended on 18 January
    now = dt.datetime(2026, 1, 20, 10, 0)
    clocks = {c.key: c for c in incident_clocks(detected, submitted, None, None, now)}
    assert clocks["early_warning"].status == "overdue"
    assert clocks["notification"].status == "late"
    assert clocks["final"].due_at == dt.datetime(2026, 2, 20, 10, 0)


def test_ongoing_incident_adds_a_further_final_report_one_month_after_handling():
    detected = dt.datetime(2026, 1, 10, 9, 0)
    handled = dt.datetime(2026, 3, 31, 9, 0)
    clocks = incident_clocks(
        detected, dt.datetime(2026, 1, 12, 9, 0), None, None,
        dt.datetime(2026, 4, 1), handling_completed_at=handled, final_ongoing=True,
    )
    further = clocks[-1]
    assert further.article == "Art. 23(4)(e)"
    assert further.due_at == dt.datetime(2026, 4, 30, 9, 0)


def test_local_time_converts_to_utc():
    winter = parse_utc("2026-01-15T12:00", "Europe/Bratislava", "0")
    summer = parse_utc("2026-07-15T12:00", "Europe/Bratislava", "0")
    assert winter == dt.datetime(2026, 1, 15, 11, 0)
    assert summer == dt.datetime(2026, 7, 15, 10, 0)
    assert parse_utc("2026-01-15T12:00", "Europe/Bratislava", "1") == dt.datetime(2026, 1, 15, 12, 0)
    with pytest.raises(Exception):
        parse_utc("2026-01-15T12:00", "Not/AZone", "0")


def test_pdf_contains_the_stage_and_the_article_fields():
    class Row:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    incident = Row(title="Pump failure", detected_at=dt.datetime(2026, 1, 31, 10, 0), summary="Water plant")
    report = Row(
        stage="early_warning", submitted_at=dt.datetime(2026, 1, 31, 18, 0),
        suspected_unlawful="yes", cross_border="no", severity_impact="", indicators="",
        root_cause="", mitigation="", body="", ongoing=False, handling_completed_at=None,
    )
    clocks = incident_clocks(incident.detected_at, None, report.submitted_at, None, report.submitted_at)
    markdown = report_markdown(incident, report, clocks)
    assert "Early warning" in markdown
    assert "Suspected unlawful or malicious cause: Yes" in markdown
    pdf = report_pdf(incident, report, clocks)
    assert pdf.startswith(b"%PDF")
    assert b"Early warning" in pdf
    assert b"unlawful" in pdf
    assert b"Art. 23" in pdf
    # The wrapper keeps a short heading intact, so the string is searchable.
    assert b"Pump failure" in text_pdf("Pump failure", ["Early warning"])
