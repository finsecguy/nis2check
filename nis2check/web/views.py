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

from ..assessment import ANSWER_VALUES
from ..ciso import export_zip
from ..frameworks import DORA_SCOPE_NOTE, framework_ids_of, framework_label, parse_frameworks
from ..jurisdictions import COUNTRY_CODES, LANGUAGES, get_jurisdiction
from ..sk_export import render_sk_self_assessment
from ..scope import assess_scope, cached_scope_rules, implied_subsector, scope_for_organisation
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
        deadlines=(get_jurisdiction(organisation(db).country_code).upcoming_deadlines()
                   if get_jurisdiction(organisation(db).country_code) else []),
    )


# ------------------------------------------------------------------ organisation

@bp.route("/organisation", methods=["GET", "POST"])
@require("view")
def organisation_page():
    db, _catalogue, settings = current_app_parts()
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

        rules = cached_scope_rules()
        try:
            org.name = request.form.get("name", "").strip()
            subsector_id = request.form.get("subsector_id", "").strip()
            special: list[str] = []
            for case_id in request.form.getlist("special"):
                if case_id and case_id not in special:
                    rules.case(case_id)
                    special.append(case_id)
            if subsector_id:
                rules.subsector(subsector_id)
            org.subsector_id = subsector_id or None
            org.special_cases = ",".join(special)
            org.employees = num("employees", int)
            org.annual_turnover_eur = num("annual_turnover_eur", float)
            org.balance_sheet_eur = num("balance_sheet_eur", float)
            result = assess_scope(
                org.subsector_id, org.employees, org.annual_turnover_eur,
                org.balance_sheet_eur, special, rules,
            )
            org.sector = result.organisation_sector
            org.size_exempt = result.size_exempt
            selected = parse_frameworks(request.form.getlist("frameworks"), default=None)
            changed = tuple(selected) != org.framework_ids
            org.frameworks = ",".join(selected)
            country = request.form.get("country", "eu").strip().lower() or "eu"
            if country not in COUNTRY_CODES:
                raise ValueError("country")
            if country != org.country_code:
                changed = True
            org.country = country
        except ValueError as exc:
            db.rollback()
            message = str(exc)
            if message.startswith("select at least"):
                message = "Select at least one framework (NIS2, DORA, or both)."
            elif message.startswith("unknown framework"):
                message = message[0].upper() + message[1:] + "."
            elif message == "country":
                message = "Choose a country from the list."
            else:
                message = f"Enter a number for {message.replace('_', ' ')}."
            flash(message, "error")
            return redirect(url_for("main.organisation_page"))
        except KeyError:
            db.rollback()
            flash("Choose a sector from the list.", "error")
            return redirect(url_for("main.organisation_page"))
        audit(db, "organisation.updated", org.name, f"frameworks: {org.frameworks}; country: {org.country_code}")
        if changed:
            # Score the newly selected frameworks. evaluate_current narrows the
            # full catalogue to whatever is now stored on the organisation.
            full = current_app.extensions["nis2_catalogue"]
            scored, _a, _t = evaluate_current(db, full, settings.evidence_dir)
            record_snapshot(db, scored)
        db.commit()
        flash("Organisation details saved.", "ok")
        return redirect(url_for("main.organisation_page"))
    rules = cached_scope_rules()
    scope = scope_for_organisation(
        org.subsector_id, org.employees, org.annual_turnover_eur, org.balance_sheet_eur,
        org.special_case_ids, sector=org.sector, rules=rules,
    )
    return render_template(
        "organisation.html", org=org, rules=rules, scope=scope,
        selected_subsector=org.subsector_id or implied_subsector(rules, org.sector),
        dora_scope_note=DORA_SCOPE_NOTE,
        countries=COUNTRY_CODES,
        languages=LANGUAGES,
        jurisdiction=get_jurisdiction(org.country_code),
    )


@bp.route("/language", methods=["POST"])
@require("view")
def set_language():
    """Per-user language. Empty follows the organisation country."""
    db, _catalogue, _settings = current_app_parts()
    lang = request.form.get("language", "").strip().lower()
    if lang and lang not in LANGUAGES:
        abort(400)
    g.user.language = lang or None
    audit(db, "user.language", g.user.email, lang or "country")
    db.commit()
    return redirect(request.referrer or url_for("main.organisation_page"))


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

    # Apply the answer and any valid evidence in one transaction. A file is written
    # before commit because scoring checks that it exists, and removed again if the
    # commit does not land, so a failed request cannot leave an orphan on disk.
    written: Path | None = None
    try:
        r = db.get(Response, qid)
        if r is None:
            r = Response(question_id=qid)
            db.add(r)
        remediation_due = _parse_date(request.form.get("remediation_due"))
        changed = (r.answer != answer) or (r.notes != notes) or (r.remediation_due != remediation_due)
        r.answer, r.notes, r.remediation_due = answer, notes, remediation_due
        if changed:
            r.updated_by, r.updated_at = g.user.email, utcnow()
            audit(db, "answer.saved", qid, f"answer={answer or 'not assessed'}")

        if pending_file:
            written = _write_upload(
                db, settings, qid, pending_file, request.form.get("file_title", ""), valid_until)
        if link:
            db.add(Evidence(question_id=qid, kind="link", url=link[:2000],
                            title=request.form.get("link_title", "").strip()[:255] or link[:255],
                            valid_until=valid_until, uploaded_by=g.user.email))
            audit(db, "evidence.link_added", qid, link[:200])

        db.flush()
        result, _a, _t = evaluate_current(db, catalogue, settings.evidence_dir)
        record_snapshot(db, result)
        db.commit()
    except Exception:
        db.rollback()
        if written is not None:
            written.unlink(missing_ok=True)
        raise
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


def _write_upload(db, settings, qid, payload, title, valid_until) -> Path:
    """Persist a payload from :func:`_read_upload` to disk and record the Evidence row.

    Returns the path so the caller can delete it if the surrounding commit fails.
    """
    filename, data = payload["filename"], payload["data"]
    stored = secrets.token_hex(16)
    path = settings.evidence_dir / stored
    path.write_bytes(data)
    try:
        db.add(Evidence(
            question_id=qid, kind="file", filename=filename, stored_name=stored, size=len(data),
            sha256=hashlib.sha256(data).hexdigest(), title=title.strip()[:255] or filename,
            valid_until=valid_until, uploaded_by=g.user.email,
        ))
        audit(db, "evidence.uploaded", qid, f"{filename} ({len(data)} bytes)")
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


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
    # Drop the row first and commit, then the file. Unlinking first would leave
    # the row pointing at a missing file when the commit fails.
    stored_path = settings.evidence_dir / ev.stored_name if ev.kind == "file" and ev.stored_name else None
    audit(db, "evidence.deleted", qid, ev.filename or ev.url or "")
    db.delete(ev)
    db.flush()
    result, _a, _t = evaluate_current(db, catalogue, settings.evidence_dir)
    record_snapshot(db, result)
    db.commit()
    if stored_path is not None:
        stored_path.unlink(missing_ok=True)
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
                       font_css=url_for("static", filename="fonts/fonts.css"),
                       lang=getattr(g, "lang", None))
    return FlaskResponse(html, mimetype="text/html")


@bp.route("/report/download.<fmt>")
@require("view")
def report_download(fmt: str):
    db, catalogue, result, assessment, threat, org = _report_parts()
    stem = (
        f"{framework_label(framework_ids_of(catalogue)).replace(' ', '-')}"
        f"-gap-assessment-{_slug(org.name)}-{dt.date.today():%Y-%m-%d}"
    )
    ext = fmt
    if fmt == "pdf":
        import tempfile
        html = render_html(result, assessment, catalogue, top=10, threat=threat, embedded=True,
                           font_css=fonts_css_uri(), lang=getattr(g, "lang", None))
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
        body = render_html(result, assessment, catalogue, top=10, threat=threat,
                           lang=getattr(g, "lang", None)).encode("utf-8")
        mime = "text/html; charset=utf-8"
    elif fmt == "ciso":
        body, mime = export_zip(result, catalogue, assessment), "application/zip"
        stem = f"ciso-assistant-{_slug(org.name)}-{dt.date.today():%Y-%m-%d}"
        ext = "zip"
    elif fmt == "sk":
        jur = get_jurisdiction(org.country_code)
        if jur is None or jur.code != "sk":
            abort(404)
        body = render_sk_self_assessment(result, assessment, catalogue, jur).encode("utf-8")
        mime = "text/html; charset=utf-8"
        stem = f"sk-self-assessment-{_slug(org.name)}-{dt.date.today():%Y-%m-%d}"
        ext = "html"
    else:
        abort(404)
    audit(db, "report.downloaded", fmt)
    db.commit()
    resp = FlaskResponse(body, mimetype=mime)
    resp.headers["Content-Disposition"] = f'attachment; filename="{stem}.{ext}"'
    return resp
