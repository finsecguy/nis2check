"""Read, validate and write assessment files (YAML)."""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .applicability import SECTORS, Entity
from .controls import Catalogue
from .frameworks import framework_ids_of, parse_frameworks

ANSWER_VALUES: dict[str, float | None] = {"yes": 1.0, "partial": 0.5, "no": 0.0, "na": None}


class AssessmentError(ValueError):
    """Raised when an assessment file is invalid."""


@dataclass
class Response:
    question_id: str
    answer: str | None = None  # yes | partial | no | na | None (unanswered)
    evidence: list[str] = field(default_factory=list)
    notes: str = ""
    extra_issues: list[str] = field(default_factory=list)  # e.g. expired evidence (web app)


@dataclass
class Assessment:
    entity: Entity
    responses: dict[str, Response]
    base_dir: Path = field(default_factory=Path.cwd)
    assessed_on: str | None = None
    assessor: str = ""
    frameworks: tuple[str, ...] = ("nis2",)


def _number(value, field_name: str, cast=float):
    if value in (None, ""):
        return None
    try:
        return cast(value)
    except (TypeError, ValueError) as exc:
        raise AssessmentError(f"entity.{field_name} must be a number, got {value!r}") from exc


def _normalise_answer(raw, qid: str) -> str | None:
    if raw is None or raw == "":
        return None
    if raw is True:  # YAML turns bare yes/no into booleans
        return "yes"
    if raw is False:
        return "no"
    answer = str(raw).strip().lower()
    if answer in ("n/a", "not applicable"):
        answer = "na"
    if answer not in ANSWER_VALUES:
        raise AssessmentError(
            f"{qid}: answer must be one of yes, partial, no, na (got {raw!r})"
        )
    return answer


def parse_assessment(data: dict, catalogue: Catalogue, base_dir: Path) -> Assessment:
    if not isinstance(data, dict):
        raise AssessmentError("assessment file must be a YAML mapping")

    raw_entity = data.get("entity") or {}
    entity = Entity(
        name=str(raw_entity.get("name") or ""),
        sector=(str(raw_entity["sector"]).strip() if raw_entity.get("sector") else None),
        employees=_number(raw_entity.get("employees"), "employees", int),
        annual_turnover_eur=_number(raw_entity.get("annual_turnover_eur"), "annual_turnover_eur"),
        balance_sheet_eur=_number(raw_entity.get("balance_sheet_eur"), "balance_sheet_eur"),
        size_exempt=bool(raw_entity.get("size_exempt", False)),
    )

    known = set(catalogue.question_ids)
    raw_responses = data.get("responses") or {}
    unknown = sorted(set(raw_responses) - known)
    if unknown:
        raise AssessmentError(f"unknown question ids: {', '.join(unknown)}")

    responses: dict[str, Response] = {}
    for qid in catalogue.question_ids:
        raw = raw_responses.get(qid)
        if raw is None:
            raw = {}
        elif not isinstance(raw, dict):
            # a bare scalar answer, e.g. `Q1: no` (YAML parses to the boolean False);
            # `or {}` would have discarded it, dropping every bare-`no` to 'unanswered'
            raw = {"answer": raw}
        evidence = raw.get("evidence") or []
        if isinstance(evidence, str):
            evidence = [evidence]
        responses[qid] = Response(
            question_id=qid,
            answer=_normalise_answer(raw.get("answer"), qid),
            evidence=[str(e).strip() for e in evidence if str(e).strip()],
            notes=str(raw.get("notes") or "").strip(),
        )

    assessed_on = data.get("assessed_on")
    if "frameworks" in data:
        try:
            frameworks = parse_frameworks(data.get("frameworks"), default=None)
        except ValueError as exc:
            raise AssessmentError(str(exc)) from exc
    else:
        frameworks = framework_ids_of(catalogue)
    return Assessment(
        entity=entity,
        responses=responses,
        base_dir=base_dir,
        assessed_on=str(assessed_on) if assessed_on else None,
        assessor=str(data.get("assessor") or ""),
        frameworks=frameworks,
    )


def load_assessment(path: str | Path, catalogue: Catalogue) -> Assessment:
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text("utf-8")) or {}
    except yaml.YAMLError as exc:
        raise AssessmentError(f"{path}: invalid YAML ({exc})") from exc
    return parse_assessment(data, catalogue, path.resolve().parent)


def new_assessment(catalogue: Catalogue, name: str = "", base_dir: Path | None = None) -> Assessment:
    return Assessment(
        entity=Entity(name=name),
        responses={qid: Response(qid) for qid in catalogue.question_ids},
        base_dir=base_dir or Path.cwd(),
        assessed_on=dt.date.today().isoformat(),
        frameworks=framework_ids_of(catalogue),
    )


def _scalar(value) -> str:
    """Render a value as a YAML scalar (JSON is valid YAML for scalars)."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(int(value)) if float(value).is_integer() else str(value)
    return json.dumps(str(value), ensure_ascii=False)


def render_assessment(assessment: Assessment, catalogue: Catalogue) -> str:
    """Write an assessment as commented YAML, so it doubles as a fill-in form."""
    e = assessment.entity
    names = {"nis2": "NIS2", "dora": "DORA"}
    title = " and ".join(names.get(fw, fw) for fw in assessment.frameworks) or "NIS2"
    lines = [
        f"# {title} self-assessment",
        "#",
        "# Answer each question with: yes | partial | no | na",
        "# List evidence as file paths (relative to this file) or URLs.",
        "# Then run:  nis2check report <this file>",
        "",
        f"assessed_on: {_scalar(assessment.assessed_on)}",
        f"assessor: {_scalar(assessment.assessor)}",
        "frameworks: [" + ", ".join(assessment.frameworks) + "]",
        "",
        "entity:",
        f"  name: {_scalar(e.name)}",
        f"  # sector: one of {', '.join(sorted(SECTORS))}, or other",
        f"  sector: {_scalar(e.sector)}",
        f"  employees: {_scalar(e.employees)}",
        f"  annual_turnover_eur: {_scalar(e.annual_turnover_eur)}",
        f"  balance_sheet_eur: {_scalar(e.balance_sheet_eur)}",
        "  # size_exempt: true for DNS providers, TLD registries, trust service providers",
        f"  size_exempt: {_scalar(e.size_exempt)}",
        "",
        "responses:",
    ]
    for domain in catalogue.domains:
        lines += ["", f"  # {domain.id} | {domain.article} | {domain.title}"]
        for q in domain.questions:
            r = assessment.responses.get(q.id, Response(q.id))
            lines.append(f"  {q.id}:")
            lines.append(f"    # [{q.priority}] {q.text}")
            if q.evidence_hint:
                lines.append(f"    # Evidence: {q.evidence_hint}")
            lines.append(f"    answer: {_scalar(r.answer)}")
            if r.evidence:
                lines.append("    evidence:")
                lines += [f"      - {_scalar(item)}" for item in r.evidence]
            else:
                lines.append("    evidence: []")
            lines.append(f"    notes: {_scalar(r.notes) or chr(34) * 2}")
    return "\n".join(lines) + "\n"


def save_assessment(assessment: Assessment, catalogue: Catalogue, path: str | Path) -> None:
    Path(path).write_text(render_assessment(assessment, catalogue), "utf-8")
