"""Board-report page: the one-page PDF, and owner and due date for the top gaps."""

from __future__ import annotations

import datetime as dt

from flask import (
    Blueprint, Response as FlaskResponse, abort, current_app, flash, g, redirect, render_template,
    request, url_for,
)
from sqlalchemy import select

from ..board import ARTICLE_20, build_board, render_board_pdf
from .auth import require
from .board_models import GapAction
from .models import Snapshot, utcnow
from .services import audit, evaluate_current, organisation

bp = Blueprint("board", __name__)


def _parts():
    return (
        current_app.extensions["nis2_db"](),
        current_app.extensions["nis2_catalogue"],
        current_app.extensions["nis2_settings"],
    )


def _previous(db):
    """The latest snapshot from a day before today, which is the previous assessment."""
    today = utcnow().date()
    rows = db.execute(select(Snapshot).order_by(Snapshot.taken_at.desc())).scalars()
    for row in rows:
        if row.taken_at.date() < today:
            return row
    return None


def _actions(db) -> dict[str, GapAction]:
    return {row.question_id: row for row in db.execute(select(GapAction)).scalars()}


def _report(db, catalogue, settings):
    result, _assessment, _threat = evaluate_current(db, catalogue, settings.evidence_dir)
    org = organisation(db)
    return build_board(result, org.name, utcnow().date(), _previous(db), _actions(db)), result


@bp.route("/board")
@require("view")
def page():
    db, catalogue, settings = _parts()
    report, _result = _report(db, catalogue, settings)
    return render_template(
        "board_report.html", report=report, accountability=ARTICLE_20, editable=g.user.can("edit"),
    )


@bp.route("/board/gaps", methods=["POST"])
@require("edit")
def save_gaps():
    db, catalogue, _settings = _parts()
    known = set(catalogue.question_ids)
    for qid in request.form.getlist("question_id"):
        if qid not in known:
            continue
        row = db.get(GapAction, qid)
        if row is None:
            row = GapAction(question_id=qid)
            db.add(row)
        row.owner = request.form.get(f"owner_{qid}", "").strip()[:255]
        raw = request.form.get(f"due_{qid}", "").strip()
        if not raw:
            row.due_on = None
        else:
            try:
                row.due_on = dt.date.fromisoformat(raw)
            except ValueError:
                db.rollback()
                flash(f"Enter a real date for {qid}.", "error")
                return redirect(url_for("board.page"))
    audit(db, "board.gaps", "", "owner and due date")
    db.commit()
    flash("Gap owners saved.", "ok")
    return redirect(url_for("board.page"))


@bp.route("/board/report.pdf")
@require("view")
def download():
    db, catalogue, settings = _parts()
    report, _result = _report(db, catalogue, settings)
    try:
        body = render_board_pdf(report)
    except RuntimeError:
        abort(500)
    org = organisation(db)
    audit(db, "board.downloaded", org.name or "")
    db.commit()
    stem = f"NIS2-board-report-{(org.name or 'organisation').replace(' ', '-')[:40]}-{report.assessed_on:%Y-%m-%d}"
    resp = FlaskResponse(body, mimetype="application/pdf")
    resp.headers["Content-Disposition"] = f'attachment; filename="{stem}.pdf"'
    return resp
