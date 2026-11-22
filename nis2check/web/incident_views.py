"""Article 23 incident pages: clocks, one form per stage, Markdown and PDF."""

from __future__ import annotations

import datetime as dt

from flask import (
    Blueprint, Response as FlaskResponse, abort, current_app, flash, g, redirect, render_template,
    request, url_for,
)
from sqlalchemy import select

from ..incidents import (
    DISCLAIMER, EARLY, FINAL, INTERMEDIATE, NOTIFICATION, PROGRESS, STAGE_ARTICLES,
    STAGE_LABELS, STAGES, Clock, IncidentInputError, choice, clip, incident_clocks, parse_utc,
    report_markdown, report_pdf,
)
from .auth import require
from .incident_models import Incident, IncidentReport
from .models import utcnow
from .services import audit

bp = Blueprint("incidents", __name__)

SINGLE = (EARLY, NOTIFICATION, FINAL, PROGRESS)


def _db():
    return current_app.extensions["nis2_db"]()


def _incident(iid: int) -> Incident:
    row = _db().get(Incident, iid)
    if row is None:
        abort(404)
    return row


def _reports(db, iid: int) -> list[IncidentReport]:
    return list(db.execute(
        select(IncidentReport).where(IncidentReport.incident_id == iid).order_by(IncidentReport.id)
    ).scalars())


def _one(reports: list[IncidentReport], stage: str) -> IncidentReport | None:
    found = [row for row in reports if row.stage == stage]
    return found[-1] if found else None


def _clocks(incident: Incident, reports: list[IncidentReport], now: dt.datetime | None = None) -> list[Clock]:
    now = now or utcnow()
    final = _one(reports, FINAL)
    progress = _one(reports, PROGRESS)
    notification = _one(reports, NOTIFICATION)
    early = _one(reports, EARLY)
    return incident_clocks(
        incident.detected_at,
        notification.submitted_at if notification else None,
        early.submitted_at if early else None,
        final.submitted_at if final else None,
        now,
        handling_completed_at=(progress.handling_completed_at if progress else None),
        progress_submitted_at=(progress.submitted_at if progress else None),
        final_ongoing=bool(final and final.ongoing),
    )


def _time(field: str, required: bool = False) -> dt.datetime | None:
    raw = request.form.get(field, "")
    if not raw.strip():
        if required:
            raise IncidentInputError(field)
        return None
    return parse_utc(raw, request.form.get("client_tz", ""), request.form.get("time_is_utc", "1"))


def _fill(row: IncidentReport, stage: str) -> None:
    if stage in (EARLY, NOTIFICATION, FINAL):
        row.suspected_unlawful = choice(request.form.get("suspected_unlawful"))
        row.cross_border = choice(request.form.get("cross_border"))
    if stage in (NOTIFICATION, FINAL):
        row.severity_impact = clip(request.form.get("severity_impact"))
    if stage == NOTIFICATION:
        row.indicators = clip(request.form.get("indicators"))
    if stage == FINAL:
        row.root_cause = clip(request.form.get("root_cause"))
        row.mitigation = clip(request.form.get("mitigation"))
        row.ongoing = request.form.get("ongoing") == "on"
    if stage in (INTERMEDIATE, PROGRESS):
        row.body = clip(request.form.get("body"))
    if stage == PROGRESS:
        row.handling_completed_at = _time("handling_completed_at")
    sent = _time("submitted_at")
    row.submitted_at = sent or row.submitted_at or utcnow()


@bp.route("/incidents")
@require("view")
def index():
    db = _db()
    rows = list(db.execute(select(Incident).order_by(Incident.detected_at.desc())).scalars())
    now = utcnow()
    items = []
    for incident in rows:
        reports = _reports(db, incident.id)
        clocks = _clocks(incident, reports, now)
        items.append({"incident": incident, "clocks": clocks[:3]})
    return render_template("incidents.html", items=items, disclaimer=DISCLAIMER)


@bp.route("/incidents/new", methods=["POST"])
@require("edit")
def create():
    db = _db()
    title = clip(request.form.get("title"), 255)
    if not title:
        flash("Give the incident a name.", "error")
        return redirect(url_for("incidents.index"))
    try:
        detected = _time("detected_at", required=True)
    except IncidentInputError:
        flash("Enter the date and time you became aware of the incident.", "error")
        return redirect(url_for("incidents.index"))
    incident = Incident(
        title=title, detected_at=detected, summary=clip(request.form.get("summary")),
        created_by=g.user.email,
    )
    db.add(incident)
    db.flush()
    audit(db, "incident.created", str(incident.id), title)
    db.commit()
    flash("Incident recorded. The 24-hour clock is running from the time you became aware.", "ok")
    return redirect(url_for("incidents.detail", iid=incident.id))


@bp.route("/incidents/<int:iid>")
@require("view")
def detail(iid: int):
    db = _db()
    incident = _incident(iid)
    reports = _reports(db, iid)
    singles = {stage: _one(reports, stage) for stage in SINGLE}
    intermediates = [row for row in reports if row.stage == INTERMEDIATE]
    return render_template(
        "incident.html",
        incident=incident,
        clocks=_clocks(incident, reports),
        singles=singles,
        intermediates=intermediates,
        stages=STAGE_LABELS,
        articles=STAGE_ARTICLES,
        disclaimer=DISCLAIMER,
        editable=g.user.can("edit"),
    )


@bp.route("/incidents/<int:iid>/reports", methods=["POST"])
@require("edit")
def save_report(iid: int):
    db = _db()
    incident = _incident(iid)
    stage = request.form.get("stage", "")
    if stage not in STAGES:
        abort(400)
    reports = _reports(db, iid)
    row = None if stage == INTERMEDIATE else _one(reports, stage)
    if row is None:
        row = IncidentReport(incident_id=incident.id, stage=stage, created_by=g.user.email, submitted_at=utcnow())
        db.add(row)
    try:
        _fill(row, stage)
    except IncidentInputError:
        db.rollback()
        flash("Enter a valid date and time.", "error")
        return redirect(url_for("incidents.detail", iid=iid))
    incident.updated_at = utcnow()
    audit(db, "incident.report", str(incident.id), stage)
    db.commit()
    flash(f"{STAGE_LABELS[stage]} saved.", "ok")
    return redirect(url_for("incidents.detail", iid=iid, _anchor=stage))


@bp.route("/incidents/<int:iid>/reports/<int:rid>.<fmt>")
@require("view")
def export_report(iid: int, rid: int, fmt: str):
    db = _db()
    incident = _incident(iid)
    row = db.get(IncidentReport, rid)
    if row is None or row.incident_id != incident.id or fmt not in ("md", "pdf"):
        abort(404)
    clocks = _clocks(incident, _reports(db, iid))
    if fmt == "md":
        body, mime = report_markdown(incident, row, clocks).encode("utf-8"), "text/markdown; charset=utf-8"
    else:
        body, mime = report_pdf(incident, row, clocks), "application/pdf"
    audit(db, "incident.exported", str(incident.id), f"{row.stage}.{fmt}")
    db.commit()
    filename = f"nis2-art23-{row.stage}-{incident.id}-{row.id}.{fmt}"
    resp = FlaskResponse(body, mimetype=mime)
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp
