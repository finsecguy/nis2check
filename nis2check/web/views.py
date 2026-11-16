"""Main screens: dashboard, organisation, assessment, evidence, reports."""

from __future__ import annotations

import datetime as dt
import hashlib
import re
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from flask import (
    Blueprint, Response as FlaskResponse, abort, current_app, flash, g, redirect, render_template,
    request, send_file, url_for,
)
from sqlalchemy import select

from ..applicability import SECTORS
from ..assessment import ANSWER_VALUES
from ..report import STATUS_LABELS, effort_matrix, fonts_css_uri, render_csv, render_html, render_json, write_pdf
from ..weighting import plain_reason
from .auth import require
from .models import AuditLog, Evidence, Response, Snapshot, ThreatDataVersion, utcnow
from .services import (
    audit, current_app_parts, evaluate_current, evidence_by_question, get_setting, organisation, record_snapshot,
)

bp = Blueprint("main", __name__)

ALLOWED_EXTENSIONS = {
    "pdf", "docx", "doc", "xlsx", "xls", "csv", "pptx", "txt", "md", "png", "jpg", "jpeg",
    "gif", "zip", "msg", "eml", "json", "xml", "odt", "ods",
}
ANSWER_LABELS = {"yes": "Yes", "partial": "Partially", "no": "No", "na": "Not applicable"}


def _safe_filename(name: str) -> str:
    name = Path(name).name
    name = re.sub(r"[^\w.\- ()]", "_", name).strip() or "file"
    return name[:200]


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", text or "organisation").strip("-")[:40] or "organisation"


# ------------------------------------------------------------------ dashboard

def _trend_svg(snapshots: list[Snapshot]) -> dict | None:
    pts = [s for s in snapshots if s.score_pct is not None]
    if len(pts) < 2:
        return None
    w, h, pad = 560, 160, 28
    n = len(pts)

    def xy(i, v):
        return pad + i * (w - 2 * pad) / (n - 1), h - pad - (v or 0) / 100 * (h - 2 * pad)

    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in (xy(i, s.score_pct) for i, s in enumerate(pts)))
    verified = " ".join(f"{x:.1f},{y:.1f}" for x, y in (xy(i, s.verified_pct) for i, s in enumerate(pts)))
    labels = [(xy(i, 0)[0], s.taken_at.strftime("%d %b")) for i, s in enumerate(pts)]
    step = max(1, n // 6)
    return {
        "w": w, "h": h, "pad": pad, "line": line, "verified": verified,
        "labels": labels[::step],
        "grid": [(v, h - pad - v / 100 * (h - 2 * pad)) for v in (0, 25, 50, 75, 100)],
        "last": pts[-1],
    }


@bp.route("/")
@require("view")
def dashboard():
    db, catalogue, settings = current_app_parts()
    result, assessment, threat = evaluate_current(db, catalogue, settings.evidence_dir)
    snapshots = list(db.execute(select(Snapshot).order_by(Snapshot.taken_at.desc()).limit(90)).scalars())[::-1]
    answered = sum(1 for r in assessment.responses.values() if r.answer)
    pending = None
    if g.user.can("admin"):
        pending = db.execute(
            select(ThreatDataVersion).where(ThreatDataVersion.status == "pending")
        ).scalars().first()
    activity = db.execute(select(AuditLog).order_by(AuditLog.ts.desc()).limit(8)).scalars().all()
    return render_template(
        "dashboard.html",
        result=result,
        org=organisation(db),
        answered=answered,
        total=len(catalogue.question_ids),
        matrix=effort_matrix(result),
        trend=_trend_svg(snapshots),
        pending=pending,
        activity=activity,
        threat=threat,
    )


# ------------------------------------------------------------------ organisation

@bp.route("/organisation", methods=["GET", "POST"])
@require("view")
def organisation_page():
    db, _catalogue, _settings = current_app_parts()
    org = organisation(db)
    if request.method == "POST":
        if not g.user.can("admin"):
            abort(403)

        def num(field, cast):
            raw = request.form.get(field, "").replace(" ", "").replace(",", "")
            if not raw:
                return None
            try:
                return cast(raw)
            except ValueError:
                raise ValueError(field)

        try:
            org.name = request.form.get("name", "").strip()
            sector = request.form.get("sector", "")
            org.sector = sector if sector in SECTORS or sector == "other" else None
            org.employees = num("employees", int)
            org.annual_turnover_eur = num("annual_turnover_eur", float)
            org.balance_sheet_eur = num("balance_sheet_eur", float)
            org.size_exempt = request.form.get("size_exempt") == "on"
        except ValueError as exc:
            db.rollback()
            flash(f"Enter a number for {str(exc).replace('_', ' ')}.", "error")
            return redirect(url_for("main.organisation_page"))
        audit(db, "organisation.updated", org.name)
        db.commit()
        flash("Organisation details saved.", "ok")
        return redirect(url_for("main.organisation_page"))
    from ..applicability import Entity, assess_applicability
    scope = assess_applicability(Entity(
        name=org.name, sector=org.sector, employees=org.employees,
        annual_turnover_eur=org.annual_turnover_eur, balance_sheet_eur=org.balance_sheet_eur,
        size_exempt=org.size_exempt,
    ))
    return render_template("organisation.html", org=org, sectors=SECTORS, scope=scope)


# ------------------------------------------------------------------ assessment

@bp.route("/assessment")
@require("view")
def assessment_index():
    db, catalogue, settings = current_app_parts()
    result, _assessment, _threat = evaluate_current(db, catalogue, settings.evidence_dir)
    return render_template("assessment_index.html", result=result)


@bp.route("/assessment/<domain_id>")
@require("view")
def assessment_domain(domain_id: str):
    db, catalogue, settings = current_app_parts()
    try:
        domain = catalogue.domain(domain_id)
    except KeyError:
        abort(404)
    result, _assessment, threat = evaluate_current(db, catalogue, settings.evidence_dir)
    dres = next(d for d in result.domains if d.domain.id == domain_id)
    responses = {r.question_id: r for r in db.execute(select(Response)).scalars()}
    ids = [d.id for d in catalogue.domains]
    i = ids.index(domain_id)
    return render_template(
        "assessment_domain.html",
        domain=domain,
        dres=dres,
        findings={f.question.id: f for f in dres.findings},
        responses=responses,
        evidence=evidence_by_question(db),
        answer_labels=ANSWER_LABELS,
        status_labels=STATUS_LABELS,
        prev_id=ids[i - 1] if i > 0 else None,
        next_id=ids[i + 1] if i < len(ids) - 1 else None,
        threat=threat,
        today=dt.date.today(),
        plain_reason=plain_reason,
    )


@bp.route("/assessment/question/<qid>", methods=["POST"])
@require("edit")
def save_question(qid: str):
    db, catalogue, settings = current_app_parts()
    try:
        q = catalogue.question(qid)
    except KeyError:
        abort(404)
    answer = request.form.get("answer") or None
    if answer is not None and answer not in ANSWER_VALUES:
        abort(400)
    notes = request.form.get("notes", "").strip()[:5000]
    valid_until = _parse_date(request.form.get("valid_until"))
    back = redirect(url_for("main.assessment_domain", domain_id=q.domain_id, _anchor=qid))

    # Validate evidence first: a bad link or file is reported but never discards the
    # answer/notes or a valid attachment, and a rejected file is never written to disk.
    errors: list[str] = []
    link = request.form.get("link", "").strip()
    if link and not _is_http_url(link):
        errors.append("Links must start with https:// or http://")
        link = ""
    upload = request.files.get("file")
    pending_file = None
    if upload and upload.filename:
        pending_file, err = _read_upload(upload)
        if err:
            errors.append(err)

    # Apply the answer and any valid evidence in one transaction.
    r = db.get(Response, qid)
    if r is None:
        r = Response(question_id=qid)
        db.add(r)
    changed = (r.answer != answer) or (r.notes != notes)
    r.answer, r.notes = answer, notes
    if changed:
        r.updated_by, r.updated_at = g.user.email, utcnow()
        audit(db, "answer.saved", qid, f"answer={answer or 'not assessed'}")

    if pending_file:
        _write_upload(db, settings, qid, pending_file, request.form.get("file_title", ""), valid_until)
    if link:
        db.add(Evidence(question_id=qid, kind="link", url=link[:2000],
                        title=request.form.get("link_title", "").strip()[:255] or link[:255],
                        valid_until=valid_until, uploaded_by=g.user.email))
        audit(db, "evidence.link_added", qid, link[:200])

    db.flush()
    result, _a, _t = evaluate_current(db, catalogue, settings.evidence_dir)
    record_snapshot(db, result)
    db.commit()
    for message in errors:
        flash(message, "error")
    flash(f"{qid} answer saved; see the error above about the evidence." if errors
          else f"{qid} saved.", "ok")
    return back


def _is_http_url(link: str) -> bool:
    """A web link only: http/https scheme with a host. Rejects javascript:, data:, file:, etc."""
    try:
        parts = urlsplit(link)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _parse_date(raw: str | None) -> dt.date | None:
    try:
        return dt.date.fromisoformat(raw) if raw else None
    except ValueError:
        return None


def _read_upload(upload) -> tuple[dict | None, str | None]:
    """Validate and read an upload into memory. Returns (payload, error); never writes.

    Keeping the read and validation separate from the disk write means a rejected file
    cannot leave an orphan on disk or force a rollback of the answer saved alongside it.
    """
    filename = _safe_filename(upload.filename)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        return None, f"Files of type .{ext or '?'} are not accepted. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}."
    data = upload.read()
    if not data:
        return None, "The file is empty."
    return {"filename": filename, "data": data}, None


def _write_upload(db, settings, qid, payload, title, valid_until) -> None:
    """Persist a payload from :func:`_read_upload` to disk and record the Evidence row."""
    filename, data = payload["filename"], payload["data"]
    stored = secrets.token_hex(16)
    (settings.evidence_dir / stored).write_bytes(data)
    db.add(Evidence(
        question_id=qid, kind="file", filename=filename, stored_name=stored, size=len(data),
        sha256=hashlib.sha256(data).hexdigest(), title=title.strip()[:255] or filename,
        valid_until=valid_until, uploaded_by=g.user.email,
    ))
    audit(db, "evidence.uploaded", qid, f"{filename} ({len(data)} bytes)")


@bp.route("/evidence/<int:eid>/download")
@require("view")
def download_evidence(eid: int):
    db, _catalogue, settings = current_app_parts()
    ev = db.get(Evidence, eid)
    if ev is None or ev.kind != "file":
        abort(404)
    path = settings.evidence_dir / ev.stored_name
    if not path.exists():
        abort(404)
    audit(db, "evidence.downloaded", ev.question_id, ev.filename or "")
    db.commit()
    return send_file(path, as_attachment=True, download_name=ev.filename, mimetype="application/octet-stream")


@bp.route("/evidence/<int:eid>/delete", methods=["POST"])
@require("edit")
def delete_evidence(eid: int):
    db, catalogue, settings = current_app_parts()
    ev = db.get(Evidence, eid)
    if ev is None:
        abort(404)
    qid = ev.question_id
    if ev.kind == "file" and ev.stored_name:
        (settings.evidence_dir / ev.stored_name).unlink(missing_ok=True)
    audit(db, "evidence.deleted", qid, ev.filename or ev.url or "")
    db.delete(ev)
    db.flush()
    result, _a, _t = evaluate_current(db, catalogue, settings.evidence_dir)
    record_snapshot(db, result)
    db.commit()
    flash("Evidence removed.", "ok")
    return redirect(url_for("main.assessment_domain", domain_id=catalogue.question(qid).domain_id, _anchor=qid))


# ------------------------------------------------------------------ reports

def _report_parts():
    db, catalogue, settings = current_app_parts()
    result, assessment, threat = evaluate_current(db, catalogue, settings.evidence_dir)
    org = organisation(db)
    assessment.assessor = f"{g.user.name or g.user.email}"
    return db, catalogue, result, assessment, threat, org


@bp.route("/report")
@require("view")
def report_page():
    return render_template("report.html")


@bp.route("/report/view")
@require("view")
def report_view():
    _db, catalogue, result, assessment, threat, _org = _report_parts()
    html = render_html(result, assessment, catalogue, top=10, threat=threat, embedded=True,
                       font_css=url_for("static", filename="fonts/fonts.css"))
    return FlaskResponse(html, mimetype="text/html")


@bp.route("/report/download.<fmt>")
@require("view")
def report_download(fmt: str):
    db, catalogue, result, assessment, threat, org = _report_parts()
    stem = f"NIS2-gap-assessment-{_slug(org.name)}-{dt.date.today():%Y-%m-%d}"
    if fmt == "pdf":
        import tempfile
        html = render_html(result, assessment, catalogue, top=10, threat=threat, embedded=True,
                           font_css=fonts_css_uri())
        with tempfile.NamedTemporaryFile(suffix=".pdf") as tmp:
            write_pdf(html, tmp.name)
            data = Path(tmp.name).read_bytes()
        body, mime = data, "application/pdf"
    elif fmt == "csv":
        body, mime = render_csv(result, threat).encode("utf-8"), "text/csv; charset=utf-8"
        stem = stem.replace("assessment", "register")
    elif fmt == "json":
        body, mime = render_json(result, assessment, catalogue, threat).encode("utf-8"), "application/json"
    elif fmt == "html":
        body = render_html(result, assessment, catalogue, top=10, threat=threat).encode("utf-8")
        mime = "text/html; charset=utf-8"
    else:
        abort(404)
    audit(db, "report.downloaded", fmt)
    db.commit()
    resp = FlaskResponse(body, mimetype=mime)
    resp.headers["Content-Disposition"] = f'attachment; filename="{stem}.{fmt}"'
    return resp
