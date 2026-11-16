"""Threat pattern taxonomy and VERIS matching rules."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import yaml


@dataclass(frozen=True)
class VerisRule:
    path: str
    any_of: tuple[str, ...] = ()
    present: bool = False

    def matches(self, record: dict) -> bool:
        value = record
        for key in self.path.split("."):
            if not isinstance(value, dict) or key not in value:
                return False
            value = value[key]
        if self.present:
            return value is not None  # in VERIS the key itself signals the category
        values = value if isinstance(value, list) else [value]
        return any(v in self.any_of for v in values)


@dataclass(frozen=True)
class Pattern:
    id: str
    name: str
    veris: tuple[VerisRule, ...]
    attack_techniques: tuple[str, ...]
    exploitation_trend: bool = False

    def matches(self, record: dict) -> bool:
        return any(rule.matches(record) for rule in self.veris)


def load_patterns(path: str | Path | None = None) -> list[Pattern]:
    if path is None:
        text = resources.files("nis2check").joinpath("data/patterns.yaml").read_text("utf-8")
    else:
        text = Path(path).read_text("utf-8")
    data = yaml.safe_load(text)
    patterns = []
    for p in data["patterns"]:
        rules = tuple(
            VerisRule(
                path=r["path"],
                any_of=tuple(r.get("any_of") or ()),
                present=bool(r.get("present", False)),
            )
            for r in p.get("veris") or []
        )
        patterns.append(
            Pattern(
                id=p["id"],
                name=p["name"],
                veris=rules,
                attack_techniques=tuple(p.get("attack_techniques") or ()),
                exploitation_trend=bool(p.get("exploitation_trend", False)),
            )
        )
    ids = [p.id for p in patterns]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate pattern ids in patterns.yaml")
    return patterns
