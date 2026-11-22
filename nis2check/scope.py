"""Indicative NIS2 scope check driven by ``data/scope.yaml``.

The thresholds and the Annex I and Annex II lists live in that file so they
can be reviewed without reading this module. The file cites Directive (EU)
2022/2555 (OJ L 333, 27.12.2022, p. 80) and Commission Recommendation
2003/361/EC (OJ L 124, 20.5.2003, p. 36).

Size, from Recommendation 2003/361/EC, Annex, Article 2, read the way NIS2
Article 2(1) uses it:

* large: 250 or more employees, or turnover above EUR 50 million and a
  balance sheet above EUR 43 million;
* medium: 50 or more employees, or turnover above EUR 10 million and a
  balance sheet above EUR 10 million, and not large;
* small or micro: below the medium ceiling.

A financial ceiling is crossed only when the figure is strictly above it
("not exceeding" in the Recommendation). Staff and financials are
alternatives: staff alone is enough, and the two financial figures count
only together. Article 2(1), second sentence, of the directive disapplies
Article 3(4) of the Recommendation's Annex.

This is a screen, not a determination. National transposition and a
designation by the competent authority can differ.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources

import yaml

OUTCOMES = ("essential", "important", "out_of_scope", "insufficient")
OUTCOME_LABELS = {
    "essential": "Essential entity",
    "important": "Important entity",
    "out_of_scope": "Out of scope",
    "insufficient": "Not enough information",
}
SIZE_LABELS = {
    "large": "Large",
    "medium": "Medium",
    "small": "Small",
    "micro": "Micro",
    "unknown": "Unknown",
}


class ScopeRulesError(ValueError):
    """Raised when the scope rules file is malformed."""


@dataclass(frozen=True)
class Reason:
    text: str
    articles: tuple[str, ...] = ()


@dataclass(frozen=True)
class SpecialCase:
    id: str
    label: str
    articles: tuple[str, ...]
    effect: str
    reason: str
    organisation_sector: str | None = None


@dataclass(frozen=True)
class Subsector:
    id: str
    title: str
    detail: str
    sector_id: str
    sector_title: str
    annex: str
    organisation_sector: str
    special_case: str | None = None
    note: str = ""


@dataclass(frozen=True)
class Sector:
    id: str
    annex: str
    title: str
    organisation_sector: str
    note: str
    subsectors: tuple[Subsector, ...]


@dataclass(frozen=True)
class ScopeRules:
    version: str
    source: str
    recommendation: str
    disclaimer: str
    size: dict
    size_notes: tuple[str, ...]
    special_cases: tuple[SpecialCase, ...]
    sectors: tuple[Sector, ...]

    def case(self, case_id: str) -> SpecialCase:
        for item in self.special_cases:
            if item.id == case_id:
                return item
        raise KeyError(case_id)

    def subsector(self, subsector_id: str) -> Subsector:
        for sector in self.sectors:
            for sub in sector.subsectors:
                if sub.id == subsector_id:
                    return sub
        raise KeyError(subsector_id)


@dataclass
class ScopeResult:
    outcome: str
    size: str
    annex: str | None
    sector_title: str
    subsector_title: str
    reasons: list[Reason] = field(default_factory=list)
    disclaimer: str = ""
    size_notes: tuple[str, ...] = ()
    organisation_sector: str | None = None
    # True when a special case puts a micro, small or unknown-size entity in
    # scope. The organisation record has a single flag for that situation.
    size_exempt: bool = False
    source: str = ""
    recommendation: str = ""

    @property
    def label(self) -> str:
        return OUTCOME_LABELS[self.outcome]

    @property
    def size_label(self) -> str:
        return SIZE_LABELS[self.size]

    @property
    def articles(self) -> list[str]:
        seen: list[str] = []
        for reason in self.reasons:
            for article in reason.articles:
                if article not in seen:
                    seen.append(article)
        return seen


def _text(value) -> str:
    return " ".join(str(value or "").split())


def _articles(value) -> tuple[str, ...]:
    if not value:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value)


def _band(data: dict, name: str) -> dict:
    band = data.get(name)
    where = f"size.{name}"
    if not isinstance(band, dict):
        raise ScopeRulesError(f"{where} must be a mapping")
    out = {}
    for key in ("employees_at_least", "turnover_eur_above", "balance_sheet_eur_above"):
        if key not in band:
            raise ScopeRulesError(f"{where}: missing '{key}'")
        try:
            out[key] = int(band[key])
        except (TypeError, ValueError) as exc:
            raise ScopeRulesError(f"{where}.{key} must be an integer") from exc
    return out


def load_scope_rules() -> ScopeRules:
    """Load and validate the bundled scope rules."""
    text = resources.files("nis2check").joinpath("data/scope.yaml").read_text(encoding="utf-8")
    return parse_scope_rules(yaml.safe_load(text))


@lru_cache(maxsize=1)
def cached_scope_rules() -> ScopeRules:
    return load_scope_rules()


def parse_scope_rules(data: dict) -> ScopeRules:
    if not isinstance(data, dict):
        raise ScopeRulesError("scope rules must be a mapping")
    effects = {
        "essential_any_size", "important_any_size", "important_if_annex",
        "telecom", "local_public_admin",
    }
    size = data.get("size") or {}
    if not isinstance(size, dict):
        raise ScopeRulesError("size must be a mapping")
    bands = {name: _band(size, name) for name in ("large", "medium", "micro")}

    cases: list[SpecialCase] = []
    seen: set[str] = set()
    for raw in data.get("special_cases") or []:
        case_id = str(raw.get("id") or "")
        if not case_id or case_id in seen:
            raise ScopeRulesError(f"special case id missing or duplicated: {case_id!r}")
        seen.add(case_id)
        effect = str(raw.get("effect") or "")
        if effect not in effects:
            raise ScopeRulesError(f"special case {case_id}: unknown effect {effect!r}")
        cases.append(SpecialCase(
            id=case_id,
            label=_text(raw.get("label")),
            articles=_articles(raw.get("articles")),
            effect=effect,
            reason=_text(raw.get("reason")),
            organisation_sector=(str(raw["organisation_sector"]) if raw.get("organisation_sector") else None),
        ))
    by_id = {case.id: case for case in cases}

    sectors: list[Sector] = []
    sub_ids: set[str] = set()
    for raw in data.get("sectors") or []:
        sector_id = str(raw.get("id") or "")
        annex = str(raw.get("annex") or "")
        if annex not in ("I", "II"):
            raise ScopeRulesError(f"sector {sector_id}: annex must be I or II")
        org_sector = str(raw.get("organisation_sector") or "")
        if not sector_id or not org_sector:
            raise ScopeRulesError("each sector needs an id and an organisation_sector")
        note = _text(raw.get("note"))
        subs: list[Subsector] = []
        for sub in raw.get("subsectors") or []:
            sub_id = str(sub.get("id") or "")
            if not sub_id or sub_id in sub_ids:
                raise ScopeRulesError(f"subsector id missing or duplicated: {sub_id!r}")
            sub_ids.add(sub_id)
            linked = sub.get("special_case")
            if linked is not None and linked not in by_id:
                raise ScopeRulesError(f"subsector {sub_id}: unknown special case {linked!r}")
            subs.append(Subsector(
                id=sub_id,
                title=_text(sub.get("title")),
                detail=_text(sub.get("detail")),
                sector_id=sector_id,
                sector_title=_text(raw.get("title")),
                annex=annex,
                organisation_sector=org_sector,
                special_case=(str(linked) if linked else None),
                note=note,
            ))
        if not subs:
            raise ScopeRulesError(f"sector {sector_id}: has no subsectors")
        sectors.append(Sector(
            id=sector_id,
            annex=annex,
            title=_text(raw.get("title")),
            organisation_sector=org_sector,
            note=note,
            subsectors=tuple(subs),
        ))

    notes = tuple(_text(item) for item in (data.get("size_notes") or []) if _text(item))
    return ScopeRules(
        version=str(data.get("version", "")),
        source=_text(data.get("source")),
        recommendation=_text(data.get("recommendation")),
        disclaimer=_text(data.get("disclaimer")),
        size=bands,
        size_notes=notes,
        special_cases=tuple(cases),
        sectors=tuple(sectors),
    )


def _eur(amount: int) -> str:
    if amount % 1_000_000 == 0:
        return f"EUR {amount // 1_000_000} million"
    return f"EUR {amount:,}"


def _meets(band: dict, employees: int | None, turnover: float | None, balance: float | None) -> bool:
    """Staff at or above the floor, or both financial figures strictly above it."""
    if employees is not None and employees >= band["employees_at_least"]:
        return True
    financials = turnover is not None and balance is not None
    return bool(
        financials
        and turnover > band["turnover_eur_above"]
        and balance > band["balance_sheet_eur_above"]
    )


def enterprise_size(
    rules: ScopeRules,
    employees: int | None,
    turnover: float | None,
    balance: float | None,
) -> str:
    """large, medium, small, micro, or unknown.

    Unknown when there is no staff figure and the two financial figures are
    not both present. One financial figure on its own never crosses a ceiling.
    """
    if employees is None and (turnover is None or balance is None):
        return "unknown"
    if _meets(rules.size["large"], employees, turnover, balance):
        return "large"
    if _meets(rules.size["medium"], employees, turnover, balance):
        return "medium"
    if _meets(rules.size["micro"], employees, turnover, balance):
        return "small"
    return "micro"


def _size_sentence(rules: ScopeRules, size: str) -> Reason:
    large, medium = rules.size["large"], rules.size["medium"]
    text = (
        f"Size under Recommendation 2003/361/EC: {SIZE_LABELS[size].lower()}. "
        f"Medium means {medium['employees_at_least']} or more employees, or "
        f"turnover and balance sheet both above {_eur(medium['turnover_eur_above'])}. "
        f"Large means {large['employees_at_least']} or more employees, or turnover above "
        f"{_eur(large['turnover_eur_above'])} and a balance sheet above "
        f"{_eur(large['balance_sheet_eur_above'])}."
    )
    return Reason(text, ("Recommendation 2003/361/EC, Annex, Art. 2",))


def assess_scope(
    subsector_id: str | None = None,
    employees: int | None = None,
    annual_turnover_eur: float | None = None,
    balance_sheet_eur: float | None = None,
    special_case_ids: list[str] | None = None,
    rules: ScopeRules | None = None,
) -> ScopeResult:
    """Classify an entity as out of scope, important, or essential.

    ``insufficient`` means a listed sector was chosen but the size figures
    needed to apply the size-cap, or to tell a medium electronic-communications
    provider from a small one, were not given.
    """
    rules = rules or cached_scope_rules()
    sub = None
    if subsector_id:
        try:
            sub = rules.subsector(subsector_id)
        except KeyError as exc:
            raise ScopeRulesError(f"unknown subsector {subsector_id!r}") from exc

    chosen: list[SpecialCase] = []
    seen: set[str] = set()
    for case_id in special_case_ids or []:
        if case_id in seen:
            continue
        seen.add(case_id)
        try:
            chosen.append(rules.case(case_id))
        except KeyError as exc:
            raise ScopeRulesError(f"unknown special case {case_id!r}") from exc
    if sub and sub.special_case and sub.special_case not in seen:
        chosen.append(rules.case(sub.special_case))

    size = enterprise_size(rules, employees, annual_turnover_eur, balance_sheet_eur)
    reasons: list[Reason] = [_size_sentence(rules, size)]
    if employees is None and (annual_turnover_eur is None) != (balance_sheet_eur is None):
        reasons.append(Reason(
            "Turnover and the balance sheet are read together. One of them on its own "
            "does not cross a financial ceiling, so the size above uses the staff figure only.",
            ("Recommendation 2003/361/EC, Annex, Art. 2",),
        ))

    # Size-cap first (Art. 2(1), Art. 3(1)(a), Art. 3(2)). Special cases then
    # raise the result. They do not lower a large Annex I entity back to important:
    # Art. 3(1)(a) already makes that entity essential.
    cap_in_scope = False
    cap_essential = False
    cap_needs_size = False
    if sub is None:
        reasons.append(Reason(
            "No Annex I or Annex II sector was selected. The size-cap rule in Art. 2(1) "
            "applies only to entities of a type listed in those annexes.",
            ("Art. 2(1)",),
        ))
    else:
        reasons.append(Reason(
            f"Annex {sub.annex}, {sub.sector_title}, {sub.title}. {sub.detail}",
            (f"Annex {sub.annex}", "Art. 2(1)"),
        ))
        if size == "unknown":
            cap_needs_size = True
            reasons.append(Reason(
                "On the size-cap rule, the number of employees, or both the annual turnover "
                "and the balance sheet total, is still needed.",
                ("Art. 2(1)",),
            ))
        elif size == "large" and sub.annex == "I":
            cap_in_scope = True
            cap_essential = True
            reasons.append(Reason(
                "On the size-cap rule, a large entity in an Annex I sector exceeds the "
                "medium-sized ceiling and is an essential entity.",
                ("Art. 2(1)", "Art. 3(1)(a)"),
            ))
        elif size in ("medium", "large"):
            cap_in_scope = True
            reasons.append(Reason(
                f"On the size-cap rule, a {size} entity in an Annex {sub.annex} sector is in "
                "scope and is an important entity. A Member State may still identify it as essential.",
                ("Art. 2(1)", "Art. 3(2)", "Art. 3(1)(e)"),
            ))
        else:
            reasons.append(Reason(
                "On the size-cap rule alone the entity is below the medium-sized ceiling, so "
                "Art. 2(1) does not bring it into scope. A case that applies regardless of size "
                "can still do so, and customers that are in scope can pass Art. 21(2)(d) "
                "supply-chain duties down to a supplier.",
                ("Art. 2(1)", "Art. 21(2)(d)"),
            ))

    forced_essential = False
    forced_in_scope = False
    telecom_needs_size = False
    for case in chosen:
        articles = case.articles
        if case.effect == "essential_any_size":
            forced_essential = True
            forced_in_scope = True
            reasons.append(Reason(case.reason, articles))
        elif case.effect == "important_any_size":
            forced_in_scope = True
            reasons.append(Reason(case.reason, articles))
        elif case.effect == "important_if_annex":
            if sub is not None:
                forced_in_scope = True
                reasons.append(Reason(case.reason, articles))
            else:
                reasons.append(Reason(
                    case.reason + " No Annex I or II type was selected, so this case does not "
                    "bring the entity into scope on its own.",
                    articles,
                ))
        elif case.effect == "telecom":
            forced_in_scope = True
            reasons.append(Reason(case.reason, articles))
            if size in ("medium", "large"):
                forced_essential = True
                if size == "medium":
                    reasons.append(Reason(
                        "The provider is medium-sized, so it is an essential entity.",
                        ("Art. 2(2)(a)(i)", "Art. 3(1)(c)"),
                    ))
                else:
                    reasons.append(Reason(
                        "The provider is large. It is an essential entity as a large Annex I "
                        "entity; Art. 3(1)(c) is the provision that names the medium-sized "
                        "providers in this category.",
                        ("Art. 2(2)(a)(i)", "Art. 3(1)(a)", "Art. 3(1)(c)"),
                    ))
            elif size == "unknown":
                telecom_needs_size = True
                reasons.append(Reason(
                    "The provider is in scope at any size. It is essential when it is "
                    "medium-sized or large, and important when it is smaller, so the size "
                    "figures are still needed.",
                    ("Art. 3(1)(c)", "Art. 3(2)"),
                ))
            else:
                reasons.append(Reason(
                    "The provider is below the medium-sized ceiling. It stays in scope and is "
                    "an important entity.",
                    ("Art. 2(2)(a)(i)", "Art. 3(2)"),
                ))
        elif case.effect == "local_public_admin":
            reasons.append(Reason(case.reason, articles))
        else:  # pragma: no cover - parse_scope_rules rejects unknown effects
            raise ScopeRulesError(f"unknown effect {case.effect}")

    if sub and sub.note:
        reasons.append(Reason(sub.note, ("Art. 4",)))

    # A large Annex I entity is essential even where a special case, read alone,
    # would only have made a smaller entity important (Art. 3(1)(a)).
    annex_i_could_be_large = sub is not None and sub.annex == "I" and size == "unknown"
    if forced_essential or cap_essential:
        outcome = "essential"
    elif telecom_needs_size or (cap_needs_size and not forced_in_scope) or (
        annex_i_could_be_large and forced_in_scope
    ):
        outcome = "insufficient"
    elif cap_in_scope or forced_in_scope:
        outcome = "important"
    else:
        outcome = "out_of_scope"
    regardless = forced_in_scope

    org_sector = None
    if sub is not None:
        org_sector = sub.organisation_sector
    elif chosen:
        org_sector = next((case.organisation_sector for case in chosen if case.organisation_sector), None)

    return ScopeResult(
        outcome=outcome,
        size=size,
        annex=(sub.annex if sub else None),
        sector_title=(sub.sector_title if sub else ""),
        subsector_title=(sub.title if sub else ""),
        reasons=reasons,
        disclaimer=rules.disclaimer,
        size_notes=rules.size_notes,
        organisation_sector=org_sector,
        size_exempt=bool(regardless and size in ("micro", "small", "unknown")),
        source=rules.source,
        recommendation=rules.recommendation,
    )
