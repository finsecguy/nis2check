"""Glue between the database and the assessment engine."""

from __future__ import annotations

import datetime as dt
import json
import logging
import threading
from pathlib import Path

from flask import current_app, g, request
from sqlalchemy import select

from ..applicability import Entity
from ..assessment import Assessment
from ..assessment import Response as EngineResponse
from ..controls import Catalogue
from ..frameworks import narrow_catalogue
from ..scoring import Result, evaluate
from ..threat.data import ThreatData, load_threat_data
from ..threat.sources import SourceError
from ..threat.update import change_report, collect
from ..weighting import compute_weights
from .models import AuditLog, Evidence, Organisation, Response, Setting, Snapshot, ThreatDataVersion, utcnow

log = logging.getLogger("nis2check")


# ------------------------------------------------------------------ settings and audit

def get_setting(db, key: str, default: str = "") -> str:
    row = db.get(Setting, key)
    return row.value if row else default


def set_setting(db, key: str, value: str) -> None:
    row = db.get(Setting, key)
    if row is None:
        db.add(Setting(key=key, value=value))
    else:
        row.value = value


def audit(db, action: str, target: str = "", detail: str = "", actor: str | None = None) -> None:
    if actor is None:
        user = getattr(g, "user", None)
        actor = user.email if user else "system"
    try:
        ip = request.remote_addr or ""
    except RuntimeError:  # outside a request
        ip = ""
    db.add(AuditLog(actor=actor, action=action, target=target, detail=detail[:2000], ip=ip))


# ------------------------------------------------------------------ assessment

def organisation(db) -> Organisation:
    return db.execute(select(Organisation)).scalar_one()


def evidence_by_question(db) -> dict[str, list[Evidence]]:
    out: dict[str, list[Evidence]] = {}
    for ev in db.execute(select(Evidence).order_by(Evidence.uploaded_at)).scalars():
        out.setdefault(ev.question_id, []).append(ev)
    return out


def build_assessment(db, catalogue: Catalogue, evidence_dir: Path, today: dt.date | None = None) -> Assessment:
    today = today or dt.date.today()
    org = organisation(db)
    responses = {r.question_id: r for r in db.execute(select(Response)).scalars()}
    evidence = evidence_by_question(db)
    engine_responses = {}
    last_update = None
    for qid in catalogue.question_ids:
        r = responses.get(qid)
        items, expired = [], []
        for ev in evidence.get(qid, []):
            if ev.valid_until and ev.valid_until < today:
                expired.append(ev)
                continue
            if ev.kind == "file" and ev.stored_name:
                items.append(str(evidence_dir / ev.stored_name))
            elif ev.kind == "link" and ev.url:
                items.append(ev.url)
        extra = []
        if expired and not items:
            extra = [f"Evidence expired on {ev.valid_until:%Y-%m-%d}: {ev.title or ev.filename or ev.url}"
                     for ev in expired]
        engine_responses[qid] = EngineResponse(
            question_id=qid,
            answer=r.answer if r else None,
            evidence=items,
            notes=r.notes if r else "",
            extra_issues=extra,
        )
        if r and (last_update is None or r.updated_at > last_update):
            last_update = r.updated_at
    return Assessment(
        entity=Entity(
            name=org.name,
            sector=org.sector or None,
            employees=org.employees,
            annual_turnover_eur=org.annual_turnover_eur,
            balance_sheet_eur=org.balance_sheet_eur,
            size_exempt=org.size_exempt,
        ),
        responses=engine_responses,
        base_dir=evidence_dir,
        assessed_on=(last_update or utcnow()).date().isoformat(),
        assessor="",
        frameworks=org.framework_ids,
    )


# ------------------------------------------------------------------ threat data

def active_threat_data(db) -> ThreatData:
    row = db.execute(
        select(ThreatDataVersion).where(ThreatDataVersion.status == "active")
        .order_by(ThreatDataVersion.reviewed_at.desc())
    ).scalars().first()
    if row:
        return ThreatData(row.data, f"approved update #{row.id}")
    return load_threat_data()


def evaluate_current(db, catalogue: Catalogue, evidence_dir: Path) -> tuple[Result, Assessment, ThreatData | None]:
    # The app keeps every framework loaded so a YAML import can store either
    # set of answers. Scoring uses only the frameworks the organisation picked.
    catalogue = narrow_catalogue(catalogue, organisation(db).framework_ids)
    assessment = build_assessment(db, catalogue, evidence_dir)
    mode = get_setting(db, "weighting", "threat")
    rank_by = get_setting(db, "rank_by", "risk")
    threat = active_threat_data(db) if mode == "threat" else None
    weights = compute_weights(catalogue, threat, mode)
    result = evaluate(catalogue, assessment, weights, mode, rank_by)
    return result, assessment, threat


def record_snapshot(db, result: Result) -> None:
    """Keep one snapshot per day: the latest state of that day."""
    today = utcnow().date()
    latest = db.execute(select(Snapshot).order_by(Snapshot.taken_at.desc())).scalars().first()
    critical_open = sum(
        1 for f in result.gaps if f.question.priority == "critical" and f.status in ("gap", "unanswered")
    )
    values = dict(
        taken_at=utcnow(),
        score_pct=result.score_pct,
        verified_pct=result.verified_pct,
        open_items=len(result.gaps),
        critical_open=critical_open,
        weighting=result.weighting,
        detail_json=json.dumps({d.domain.id: d.score_pct for d in result.domains}),
    )
    if latest and latest.taken_at.date() == today:
        for k, v in values.items():
            setattr(latest, k, v)
    else:
        db.add(Snapshot(**values))


# ------------------------------------------------------------------ threat data updates

_check_lock = threading.Lock()


def check_running() -> bool:
    return _check_lock.locked()


def run_threat_check(session_factory, catalogue: Catalogue, settings, actor: str) -> ThreatDataVersion | None:
    """Fetch sources and store the result as a pending version for an admin to review.

    Returns None if another check is already running.
    """
    if not _check_lock.acquire(blocking=False):
        return None
    db = session_factory()
    try:
        old = active_threat_data(db)
        source_dir = Path(settings.threat_source_dir) if settings.threat_source_dir else None
        try:
            data, warnings = collect(dt.date.today(), source_dir)
        except SourceError as exc:
            version = ThreatDataVersion(status="failed", error=str(exc), triggered_by=actor, has_changes=False)
            db.add(version)
            audit(db, "threat_data.check_failed", detail=str(exc), actor=actor)
            set_setting(db, "threat_last_check", utcnow().isoformat())
            db.commit()
            return version

        new = ThreatData(data, "candidate")
        report, changed = change_report(catalogue, old, new, warnings)
        # a newer check replaces any older pending one
        for pending in db.execute(
            select(ThreatDataVersion).where(ThreatDataVersion.status == "pending")
        ).scalars():
            pending.status = "superseded"
        version = ThreatDataVersion(
            status="pending" if changed else "no_change",
            data_json=json.dumps(data),
            change_report=report,
            warnings_json=json.dumps(warnings),
            has_changes=changed,
            triggered_by=actor,
        )
        db.add(version)
        set_setting(db, "threat_last_check", utcnow().isoformat())
        audit(db, "threat_data.checked", detail="changes found" if changed else "no changes", actor=actor)
        db.commit()
        return version
    except Exception:  # never let a background check crash the app
        log.exception("threat data check failed")
        db.rollback()
        return None
    finally:
        db.close()
        _check_lock.release()


def start_threat_check(app, actor: str) -> bool:
    """Run a check in a background thread. Returns False if one is already running."""
    if check_running():
        return False

    def _job():
        with app.app_context():
            run_threat_check(app.extensions["nis2_db"], app.extensions["nis2_catalogue"],
                             app.extensions["nis2_settings"], actor)

    threading.Thread(target=_job, name="threat-check", daemon=True).start()
    return True


def scheduler(app) -> None:
    """Hourly loop: start a check when automatic checks are on and the last one is old enough."""
    import time

    settings = app.extensions["nis2_settings"]
    time.sleep(300)  # let the app start before the first check
    while True:
        try:
            with app.app_context():
                db = app.extensions["nis2_db"]()
                # Env gate (e.g. off for air-gapped) and in-app toggle must both be on
                # before any outbound fetch.
                enabled = settings.threat_auto_check and get_setting(db, "threat_auto_check", "1") == "1"
                last = get_setting(db, "threat_last_check", "")
                app.extensions["nis2_db"].remove()
            due = True
            if last:
                elapsed = utcnow() - dt.datetime.fromisoformat(last)
                due = elapsed >= dt.timedelta(hours=settings.threat_check_hours)
            if enabled and due:
                start_threat_check(app, "scheduler")
        except Exception:  # pragma: no cover
            log.exception("scheduler error")
        time.sleep(3600)


def current_app_parts():
    """Database, the frameworks selected for this organisation, and settings.

    The extension holds every bundled framework so an import can store NIS2 or
    DORA answers. Screens only see the selection.
    """
    ext = current_app.extensions
    db = ext["nis2_db"]
    catalogue = narrow_catalogue(ext["nis2_catalogue"], organisation(db).framework_ids)
    return db, catalogue, ext["nis2_settings"]
