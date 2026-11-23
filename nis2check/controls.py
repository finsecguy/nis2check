"""Load and validate the NIS2 control catalogue."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Iterator

import yaml

PRIORITY_WEIGHTS = {"critical": 3, "high": 2, "medium": 1}
EFFORT_COST = {"low": 1, "medium": 2, "high": 3}


class CatalogueError(ValueError):
    """Raised when the control catalogue is malformed."""


@dataclass(frozen=True)
class Question:
    id: str
    domain_id: str
    text: str
    priority: str
    evidence_hint: str
    remediation: str
    effort: str = "medium"
    attack_mitigations: tuple[str, ...] = ()
    threat_patterns: tuple[str, ...] = ()
    article: str = ""
    # Optional fields used by national-law questions. Directive questions leave them empty.
    # ``translations`` is the hook for a later translation of the directive question text.
    text_en: str = ""
    translations: tuple[tuple[str, str], ...] = ()
    source_url: str = ""
    verified: bool | None = None
    note: str = ""

    @property
    def effort_cost(self) -> int:
        return EFFORT_COST[self.effort]

    @property
    def weight(self) -> int:
        return PRIORITY_WEIGHTS[self.priority]


@dataclass(frozen=True)
class Domain:
    id: str
    article: str
    title: str
    summary: str
    questions: tuple[Question, ...]
    framework: str = "nis2"


@dataclass(frozen=True)
class Catalogue:
    version: str
    source: str
    domains: tuple[Domain, ...]

    def questions(self) -> Iterator[Question]:
        for domain in self.domains:
            yield from domain.questions

    def question(self, question_id: str) -> Question:
        for q in self.questions():
            if q.id == question_id:
                return q
        raise KeyError(question_id)

    def domain(self, domain_id: str) -> Domain:
        for d in self.domains:
            if d.id == domain_id:
                return d
        raise KeyError(domain_id)

    @property
    def question_ids(self) -> list[str]:
        return [q.id for q in self.questions()]


def _require(mapping: dict, key: str, where: str):
    if key not in mapping or mapping[key] in (None, ""):
        raise CatalogueError(f"{where}: missing required field '{key}'")
    return mapping[key]


def parse_catalogue(data: dict) -> Catalogue:
    if not isinstance(data, dict) or not isinstance(data.get("domains"), list):
        raise CatalogueError("catalogue must be a mapping with a 'domains' list")

    framework = str(data.get("framework") or "nis2").strip().lower() or "nis2"
    seen_ids: set[str] = set()
    domains: list[Domain] = []
    for d in data["domains"]:
        domain_id = _require(d, "id", "domain")
        where = f"domain {domain_id}"
        domain_framework = str(d.get("framework") or framework).strip().lower() or framework
        if domain_id in seen_ids:
            raise CatalogueError(f"duplicate id '{domain_id}'")
        seen_ids.add(domain_id)

        questions: list[Question] = []
        for q in d.get("questions") or []:
            qid = _require(q, "id", where)
            if qid in seen_ids:
                raise CatalogueError(f"duplicate id '{qid}'")
            seen_ids.add(qid)
            priority = _require(q, "priority", f"question {qid}")
            if priority not in PRIORITY_WEIGHTS:
                raise CatalogueError(
                    f"question {qid}: priority must be one of {sorted(PRIORITY_WEIGHTS)}"
                )
            effort = q.get("effort", "medium")
            if effort not in EFFORT_COST:
                raise CatalogueError(
                    f"question {qid}: effort must be one of {sorted(EFFORT_COST)}"
                )
            raw_translations = q.get("translations") or {}
            if raw_translations and not isinstance(raw_translations, dict):
                raise CatalogueError(f"question {qid}: translations must be a mapping")
            verified = q.get("verified", None)
            if verified is not None and not isinstance(verified, bool):
                raise CatalogueError(f"question {qid}: verified must be true or false")
            questions.append(
                Question(
                    id=qid,
                    domain_id=domain_id,
                    text=_require(q, "text", f"question {qid}").strip(),
                    priority=priority,
                    evidence_hint=str(q.get("evidence_hint", "")).strip(),
                    remediation=str(q.get("remediation", "")).strip(),
                    effort=effort,
                    attack_mitigations=tuple(q.get("attack_mitigations") or ()),
                    threat_patterns=tuple(q.get("threat_patterns") or ()),
                    article=str(q.get("article") or "").strip(),
                    text_en=str(q.get("text_en") or "").strip(),
                    translations=tuple(
                        (str(lang), str(value).strip())
                        for lang, value in raw_translations.items()
                        if str(value).strip()
                    ),
                    source_url=str(q.get("source_url") or "").strip(),
                    verified=verified,
                    note=" ".join(str(q.get("note") or "").split()),
                )
            )
        if not questions:
            raise CatalogueError(f"{where}: has no questions")

        domains.append(
            Domain(
                id=domain_id,
                article=_require(d, "article", where),
                title=_require(d, "title", where),
                summary=" ".join(str(d.get("summary", "")).split()),
                questions=tuple(questions),
                framework=domain_framework,
            )
        )

    return Catalogue(
        version=str(data.get("version", "")),
        source=str(data.get("source", "")),
        domains=tuple(domains),
    )


def load_catalogue(path: str | Path | None = None) -> Catalogue:
    """Load the bundled catalogue, or a custom one from ``path``."""
    if path is None:
        text = resources.files("nis2check").joinpath("data/controls.yaml").read_text("utf-8")
    else:
        text = Path(path).read_text("utf-8")
    return parse_catalogue(yaml.safe_load(text))
