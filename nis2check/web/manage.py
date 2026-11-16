"""Command-line helpers for administrators of the web app (run inside the container)."""

from __future__ import annotations

import hashlib
import secrets
from pathlib import Path

from sqlalchemy import select

from ..assessment import load_assessment
from .auth import hash_password, password_problem
from .models import Evidence, Response, User, utcnow
from .services import audit, evaluate_current, organisation, record_snapshot


def _contained(base: Path, item: str) -> Path | None:
    """Resolve an evidence path against ``base``, or return None if it escapes.

    An assessment file may come from an outside consultant, so absolute paths and
    ``../`` traversal (which could pull in, say, the Flask secret key) must not reach
    the downloadable evidence store. ``base / item`` already yields ``item`` when it is
    absolute, so both cases fall outside ``base`` and are rejected.
    """
    candidate = (base / item).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        return None
    return candidate


def import_yaml(app, path: str | Path, actor: str = "import") -> dict:
    """Load a CLI assessment file into the web app: organisation, answers, notes and evidence.

    Evidence files that exist next to the YAML file are copied into the app; URLs are
    added as links. Existing answers for the same questions are overwritten.
    """
    db = app.extensions["nis2_db"]()
    catalogue = app.extensions["nis2_catalogue"]
    settings = app.extensions["nis2_settings"]
    assessment = load_assessment(path, catalogue)

    org = organisation(db)
    e = assessment.entity
    org.name = e.name or org.name
    org.sector, org.employees = e.sector, e.employees
    org.annual_turnover_eur, org.balance_sheet_eur = e.annual_turnover_eur, e.balance_sheet_eur
    org.size_exempt = e.size_exempt

    counts = {"answers": 0, "files": 0, "links": 0, "missing_files": 0, "rejected_files": 0}
    base_dir = assessment.base_dir.resolve()
    for qid, r in assessment.responses.items():
        if r.answer is None and not r.notes and not r.evidence:
            continue
        row = db.get(Response, qid) or Response(question_id=qid)
        row.answer, row.notes, row.updated_by, row.updated_at = r.answer, r.notes, actor, utcnow()
        db.add(row)
        counts["answers"] += 1
        for item in r.evidence:
            if item.lower().startswith(("http://", "https://")):
                db.add(Evidence(question_id=qid, kind="link", url=item, title=item, uploaded_by=actor))
                counts["links"] += 1
                continue
            src = _contained(base_dir, item)
            if src is None:
                counts["rejected_files"] += 1
                continue
            if not src.is_file():
                counts["missing_files"] += 1
                continue
            data = src.read_bytes()
            stored = secrets.token_hex(16)
            (settings.evidence_dir / stored).write_bytes(data)
            db.add(Evidence(question_id=qid, kind="file", filename=src.name, stored_name=stored,
                            size=len(data), sha256=hashlib.sha256(data).hexdigest(), title=src.name,
                            uploaded_by=actor))
            counts["files"] += 1
    audit(db, "assessment.imported", Path(path).name,
          f"{counts['answers']} answers, {counts['files']} files, {counts['links']} links"
          + (f", {counts['missing_files']} evidence files not found" if counts["missing_files"] else "")
          + (f", {counts['rejected_files']} evidence paths rejected" if counts["rejected_files"] else ""),
          actor=actor)
    db.flush()
    result, _a, _t = evaluate_current(db, catalogue, settings.evidence_dir)
    record_snapshot(db, result)
    db.commit()
    app.extensions["nis2_db"].remove()
    return counts


def create_admin(app, email: str, password: str, name: str = "") -> None:
    """Create an administrator without the browser setup page (scripted installs)."""
    problem = password_problem(password)
    if problem:
        raise ValueError(problem)
    db = app.extensions["nis2_db"]()
    email = email.strip().lower()
    if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
        raise ValueError(f"{email} already exists")
    db.add(User(email=email, name=name, role="admin", password_hash=hash_password(password)))
    audit(db, "user.created", email, "admin via command line", actor="command line")
    db.commit()
    app.extensions["nis2_db"].remove()
