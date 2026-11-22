"""One-page board PDF: scores, gaps, trend and the Article 20 line."""

import datetime as dt

from nis2check.board import (
    AreaScore, BoardReport, GapLine, render_board_pdf, trend_sentence,
)


def _report(**kwargs) -> BoardReport:
    areas = [AreaScore(f"Area {i}", f"Art. {i}", 70.0) for i in range(1, 13)]
    gaps = [
        GapLine("GOV-01", "Has the management body formally approved the measures?", "Ada Lovelace", dt.date(2026, 12, 1)),
        GapLine("RISK-02", "Is a cybersecurity risk assessment performed at least annually?", "", None),
    ]
    base = dict(
        org_name="Acme s.r.o.",
        assessed_on=dt.date(2026, 11, 22),
        score=72.0,
        verified=41.0,
        areas=areas,
        gaps=gaps,
        trend="Up 32 points from 40% on 01 Oct 2026.",
    )
    base.update(kwargs)
    return BoardReport(**base)


def test_trend_sentence():
    assert trend_sentence(None, 40, dt.date(2026, 10, 1)) == "No earlier assessment is on record."
    assert trend_sentence(72, None, None) == "No earlier assessment is on record."
    assert trend_sentence(72, 40, dt.date(2026, 10, 1)) == "Up 32 points from 40% on 01 Oct 2026."
    assert trend_sentence(30, 40, dt.date(2026, 10, 1)) == "Down 10 points from 40% on 01 Oct 2026."
    assert trend_sentence(40, 40, dt.date(2026, 10, 1)) == "Unchanged from 40% on 01 Oct 2026."


def test_pdf_is_one_page_and_contains_the_board_figures():
    data = render_board_pdf(_report())
    assert data.startswith(b"%PDF")
    assert b"/Count 1" in data
    assert b"/Count 2" not in data
    assert b"Acme s.r.o." in data
    assert b"72%" in data
    assert b"GOV-01" in data
    assert b"Ada Lovelace" in data
    assert b"01 Dec 2026" in data
    assert b"Not set" in data
    assert b"Up 32 points" in data
    assert b"Article 20" in data
    assert b"management body" in data
    assert b"Article 21" in data


def test_pdf_still_fits_when_there_is_no_history_and_no_gaps():
    data = render_board_pdf(_report(
        gaps=[], trend="No earlier assessment is on record.", score=None, verified=None,
    ))
    assert b"/Count 1" in data
    assert b"No earlier assessment is on record." in data
    assert b"n/a" in data
