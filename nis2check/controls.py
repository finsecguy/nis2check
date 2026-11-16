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

    seen_ids: set[str] = set()
    domains: list[Domain] = []
    for d in data["domains"]:
        domain_id = _require(d, "id", "domain")
        where = f"domain {domain_id}"
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
