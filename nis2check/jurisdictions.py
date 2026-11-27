"""National-law overlays for Slovakia, Czechia, Hungary and Poland.

``eu`` is the default and has no overlay: the assessment stays on the Directive
text alone. A country file maps each Directive citation the catalogue and the
scope rules already use to a national provision, and adds questions that have
no Directive equivalent.

``verified`` is true only when the paragraph number and its title were read in
the official consolidated text. A false flag is kept on the report so an
unchecked citation is not filed as if it had been confirmed.
"""

from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path

import yaml

from .controls import PRIORITY_WEIGHTS, EFFORT_COST, Catalogue, CatalogueError, Domain, Question, _require

COUNTRY_CODES = ("eu", "sk", "cz", "hu", "pl")
NATIONAL_CODES = ("sk", "cz", "hu", "pl")
LANGUAGES = ("en", "sk", "cs", "hu", "pl")
COUNTRY_LANGUAGE = {"eu": "en", "sk": "sk", "cz": "cs", "hu": "hu", "pl": "pl"}

# Citations the scope engine builds in code, in addition to the strings stored
# in controls.yaml and scope.yaml. A country file may map them. Any other key
# is rejected.
_ENGINE_ARTICLES = (
    "Art. 2",
    "Art. 3",
    "Art. 2(1)",
    "Art. 3(1)(a)",
    "Art. 4",
    "Art. 2(5)(b)",
    "Annex I",
    "Annex II",
)


class JurisdictionError(CatalogueError):
    """Raised when a country file is malformed."""


@dataclass(frozen=True)
class Law:
    name: str
    number: str
    in_force: str
    competent_authority: str
    csirt: str
    reporting_channel_url: str
    source_url: str
    citation_label: str
    note: str = ""


@dataclass(frozen=True)
class EntityTerm:
    """How the national law names one Directive category."""

    directive: str
    national: str
    note: str = ""


@dataclass(frozen=True)
class ArticleRef:
    article: str
    ref: str
    title: str
    source_url: str
    verified: bool
    note: str = ""
    evidence_quote: str = ""
    checked_against: str = ""
    status: str = ""


@dataclass(frozen=True)
class Deadline:
    id: str
    description: str
    description_en: str
    source_url: str
    date: dt.date | None = None
    relative: str = ""
    verified: bool = False
    note: str = ""
    evidence_quote: str = ""
    checked_against: str = ""

    def label(self, lang: str) -> str:
        if lang == "en" and self.description_en:
            return self.description_en
        return self.description


@dataclass(frozen=True)
class SectorAuthority:
    sector: str
    authority: str
    csirt: str
    note: str = ""


@dataclass(frozen=True)
class Notice:
    id: str
    text: str
    text_en: str
    source_url: str = ""
    status: str = ""
    scored: bool = False

    def label(self, lang: str) -> str:
        if lang == "en" and self.text_en:
            return self.text_en
        return self.text


@dataclass(frozen=True)
class ClockRules:
    """Overrides against the Directive's 24 h / 72 h / one month clocks.

    Unset fields keep the Directive figure. ``further_days`` replaces the
    one-month further final report when the national law counts in days.
    """

    early_hours: int | None = None
    notification_hours: int | None = None
    final_days: int | None = None
    further_days: int | None = None
    source_url: str = ""
    note: str = ""
    verified: bool = False
    evidence_quote: str = ""
    checked_against: str = ""


@dataclass(frozen=True)
class Jurisdiction:
    code: str
    language: str
    law: Law
    entity_terms: dict[str, EntityTerm]
    article_map: dict[str, ArticleRef]
    extras: tuple[Question, ...]
    deadlines: tuple[Deadline, ...]
    sector_authorities: dict[str, SectorAuthority]
    notices: tuple[Notice, ...]
    clocks: ClockRules
    domain_title: str

    @property
    def domain_id(self) -> str:
        return f"NAT-{self.code.upper()}"

    def article(self, key: str) -> ArticleRef | None:
        return self.article_map.get(key)

    def term_for(self, classification: str) -> str:
        """National name for ``essential`` or ``important``. Empty when unmapped."""
        term = self.entity_terms.get(classification)
        return term.national if term else ""

    def authority_for(self, sector: str | None) -> tuple[str, str]:
        """Competent authority and CSIRT for a scope sector, else the law-level pair."""
        row = self.sector_authorities.get(sector or "")
        if row and (row.authority or row.csirt):
            return row.authority or self.law.competent_authority, row.csirt or self.law.csirt
        return self.law.competent_authority, self.law.csirt

    def upcoming_deadlines(self, today: dt.date | None = None) -> list[Deadline]:
        """Dated deadlines that are still ahead, plus rules with no calendar date."""
        today = today or dt.date.today()
        chosen = []
        for item in self.deadlines:
            if item.date is None or item.date >= today:
                chosen.append(item)
        return chosen


def question_text(question: Question, lang: str) -> str:
    """Text for ``lang``.

    National extras carry a local ``text`` and an English ``text_en``.
    Directive questions stay English until a ``translations`` entry is added.
    """
    for code, value in question.translations:
        if code == lang and value:
            return value
    if lang == "en" and question.text_en:
        return question.text_en
    return question.text


def cited_articles() -> set[str]:
    """Directive citations stored on the NIS2 catalogue and in the scope rules.

    Domain ``article`` fields in controls.yaml, and every string in an
    ``articles`` list in scope.yaml. Comment prose is not a citation.
    """
    controls = yaml.safe_load(
        resources.files("nis2check").joinpath("data/controls.yaml").read_text("utf-8")
    )
    scope = yaml.safe_load(
        resources.files("nis2check").joinpath("data/scope.yaml").read_text("utf-8")
    )
    found: set[str] = set()
    for domain in controls.get("domains") or []:
        article = str(domain.get("article") or "").strip()
        if article:
            found.add(article)
    _collect_article_lists(scope, found)
    return found


def _collect_article_lists(node, found: set[str]) -> None:
    if isinstance(node, dict):
        articles = node.get("articles")
        if isinstance(articles, list):
            for item in articles:
                text = str(item).strip()
                if text:
                    found.add(text)
        for value in node.values():
            _collect_article_lists(value, found)
    elif isinstance(node, list):
        for item in node:
            _collect_article_lists(item, found)


def scope_sectors() -> set[str]:
    """``organisation_sector`` ids the scope rules already use."""
    scope = yaml.safe_load(
        resources.files("nis2check").joinpath("data/scope.yaml").read_text("utf-8")
    )
    found: set[str] = set()

    def walk(node) -> None:
        if isinstance(node, dict):
            sector = node.get("organisation_sector")
            if isinstance(sector, str) and sector.strip():
                found.add(sector.strip())
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(scope)
    return found


def _allowed_articles() -> set[str]:
    return cited_articles() | set(_ENGINE_ARTICLES)


def _bool(value, where: str) -> bool:
    if not isinstance(value, bool):
        raise JurisdictionError(f"{where}: verified must be true or false")
    return value


def _clocks(raw, where: str) -> ClockRules:
    if not raw:
        return ClockRules()
    if not isinstance(raw, dict):
        raise JurisdictionError(f"{where}: incident_clocks must be a mapping")

    def hours(key: str) -> int | None:
        if key not in raw or raw[key] in (None, ""):
            return None
        value = raw[key]
        if not isinstance(value, int) or value <= 0:
            raise JurisdictionError(f"{where}: {key} must be a positive number of hours or days")
        return value

    return ClockRules(
        early_hours=hours("early_hours"),
        notification_hours=hours("notification_hours"),
        final_days=hours("final_days"),
        further_days=hours("further_days"),
        source_url=str(raw.get("source_url") or "").strip(),
        note=" ".join(str(raw.get("note") or "").split()),
        verified=_bool(raw.get("verified", False), f"{where} incident_clocks"),
        evidence_quote=" ".join(str(raw.get("evidence_quote") or "").split()),
        checked_against=" ".join(str(raw.get("checked_against") or "").split()),
    )


def parse_jurisdiction(data: dict, code: str | None = None) -> Jurisdiction:
    if not isinstance(data, dict):
        raise JurisdictionError("jurisdiction file must be a mapping")
    file_code = str(_require(data, "code", "jurisdiction")).strip().lower()
    if code and file_code != code:
        raise JurisdictionError(f"jurisdiction code is {file_code}, expected {code}")
    if file_code not in NATIONAL_CODES:
        raise JurisdictionError(f"unknown jurisdiction code '{file_code}'")
    where = f"jurisdiction {file_code}"
    language = str(data.get("language") or COUNTRY_LANGUAGE[file_code]).strip().lower()
    if language not in LANGUAGES:
        raise JurisdictionError(f"{where}: language must be one of {', '.join(LANGUAGES)}")

    law_raw = data.get("law")
    if not isinstance(law_raw, dict):
        raise JurisdictionError(f"{where}: missing law")
    law = Law(
        name=str(_require(law_raw, "name", where)).strip(),
        number=str(_require(law_raw, "number", where)).strip(),
        in_force=str(_require(law_raw, "in_force", where)).strip(),
        competent_authority=str(_require(law_raw, "competent_authority", where)).strip(),
        csirt=str(_require(law_raw, "csirt", where)).strip(),
        reporting_channel_url=str(law_raw.get("reporting_channel_url") or "").strip(),
        source_url=str(_require(law_raw, "source_url", where)).strip(),
        citation_label=str(_require(law_raw, "citation_label", where)).strip(),
        note=" ".join(str(law_raw.get("note") or "").split()),
    )

    terms_raw = data.get("entity_terms")
    if not isinstance(terms_raw, dict):
        raise JurisdictionError(f"{where}: missing entity_terms")
    terms: dict[str, EntityTerm] = {}
    for kind in ("essential", "important"):
        raw = terms_raw.get(kind)
        if not isinstance(raw, dict):
            raise JurisdictionError(f"{where}: entity_terms.{kind} is required")
        national = str(_require(raw, "national", f"{where} entity_terms.{kind}")).strip()
        terms[kind] = EntityTerm(
            directive=kind,
            national=national,
            note=" ".join(str(raw.get("note") or "").split()),
        )

    allowed = _allowed_articles()
    required = cited_articles()
    article_map: dict[str, ArticleRef] = {}
    raw_map = data.get("article_map")
    if not isinstance(raw_map, dict) or not raw_map:
        raise JurisdictionError(f"{where}: article_map is required")
    for key, raw in raw_map.items():
        article = str(key).strip()
        if article not in allowed:
            raise JurisdictionError(f"{where}: unknown article key '{article}'")
        if not isinstance(raw, dict):
            raise JurisdictionError(f"{where}: article_map '{article}' must be a mapping")
        source = str(raw.get("source_url") or "").strip()
        if not source:
            raise JurisdictionError(f"{where}: article '{article}' is missing source_url")
        if article in article_map:
            raise JurisdictionError(f"{where}: duplicate article key '{article}'")
        article_map[article] = ArticleRef(
            article=article,
            ref=str(raw.get("ref") or "").strip(),
            title=" ".join(str(raw.get("title") or "").split()),
            source_url=source,
            verified=_bool(raw.get("verified", False), f"{where} article '{article}'"),
            note=" ".join(str(raw.get("note") or "").split()),
            evidence_quote=" ".join(str(raw.get("evidence_quote") or "").split()),
            checked_against=" ".join(str(raw.get("checked_against") or "").split()),
            status=str(raw.get("status") or "").strip(),
        )
    required = required | {"Art. 2", "Art. 3"}
    missing = sorted(required - set(article_map))
    if missing:
        raise JurisdictionError(
            f"{where}: article_map is missing {', '.join(missing)}"
        )

    seen: set[str] = set()
    extras: list[Question] = []
    prefix = f"{file_code}-"
    for raw in data.get("national_extras") or []:
        if not isinstance(raw, dict):
            raise JurisdictionError(f"{where}: a national extra must be a mapping")
        qid = str(_require(raw, "id", where)).strip()
        if not qid.startswith(prefix):
            raise JurisdictionError(f"{where}: question id '{qid}' must start with '{prefix}'")
        if qid in seen:
            raise JurisdictionError(f"{where}: duplicate question id '{qid}'")
        seen.add(qid)
        priority = _require(raw, "priority", f"question {qid}")
        if priority not in PRIORITY_WEIGHTS:
            raise JurisdictionError(
                f"question {qid}: priority must be one of {sorted(PRIORITY_WEIGHTS)}"
            )
        effort = raw.get("effort", "medium")
        if effort not in EFFORT_COST:
            raise JurisdictionError(
                f"question {qid}: effort must be one of {sorted(EFFORT_COST)}"
            )
        verified = raw.get("verified", False)
        extra_source = str(raw.get("source_url") or "").strip()
        if not extra_source:
            raise JurisdictionError(f"question {qid}: missing source_url")
        extras.append(
            Question(
                id=qid,
                domain_id=f"NAT-{file_code.upper()}",
                text=str(_require(raw, "text", f"question {qid}")).strip(),
                priority=priority,
                evidence_hint=str(raw.get("evidence_hint") or "").strip(),
                remediation=str(raw.get("remediation") or "").strip(),
                effort=effort,
                article=str(raw.get("article") or "").strip(),
                text_en=str(raw.get("text_en") or "").strip(),
                source_url=extra_source,
                verified=_bool(verified, f"question {qid}"),
                note=" ".join(str(raw.get("note") or "").split()),
                evidence_quote=" ".join(str(raw.get("evidence_quote") or "").split()),
                checked_against=" ".join(str(raw.get("checked_against") or "").split()),
            )
        )
    if not extras:
        raise JurisdictionError(f"{where}: national_extras is empty")

    deadlines: list[Deadline] = []
    deadline_ids: set[str] = set()
    for raw in data.get("deadlines") or []:
        if not isinstance(raw, dict):
            raise JurisdictionError(f"{where}: a deadline must be a mapping")
        did = str(_require(raw, "id", f"{where} deadline")).strip()
        if did in deadline_ids:
            raise JurisdictionError(f"{where}: duplicate deadline id '{did}'")
        deadline_ids.add(did)
        source = str(raw.get("source_url") or "").strip()
        if not source:
            raise JurisdictionError(f"{where}: deadline '{did}' is missing source_url")
        raw_date = raw.get("date") or ""
        parsed_date = None
        if str(raw_date).strip():
            try:
                parsed_date = dt.date.fromisoformat(str(raw_date).strip())
            except ValueError as exc:
                raise JurisdictionError(
                    f"{where}: deadline '{did}' date must be YYYY-MM-DD"
                ) from exc
        deadlines.append(
            Deadline(
                id=did,
                description=str(_require(raw, "description", f"{where} deadline {did}")).strip(),
                description_en=str(raw.get("description_en") or "").strip(),
                source_url=source,
                date=parsed_date,
                relative=" ".join(str(raw.get("relative") or "").split()),
                verified=_bool(raw.get("verified", False), f"{where} deadline '{did}'"),
                note=" ".join(str(raw.get("note") or "").split()),
                evidence_quote=" ".join(str(raw.get("evidence_quote") or "").split()),
                checked_against=" ".join(str(raw.get("checked_against") or "").split()),
            )
        )

    known_sectors = scope_sectors()
    sectors: dict[str, SectorAuthority] = {}
    raw_sectors = data.get("sector_authorities") or {}
    if raw_sectors and not isinstance(raw_sectors, dict):
        raise JurisdictionError(f"{where}: sector_authorities must be a mapping")
    for key, raw in raw_sectors.items():
        sector = str(key).strip()
        if sector not in known_sectors:
            raise JurisdictionError(f"{where}: unknown sector '{sector}'")
        if not isinstance(raw, dict):
            raise JurisdictionError(f"{where}: sector '{sector}' must be a mapping")
        sectors[sector] = SectorAuthority(
            sector=sector,
            authority=str(raw.get("authority") or "").strip(),
            csirt=str(raw.get("csirt") or "").strip(),
            note=" ".join(str(raw.get("note") or "").split()),
        )

    notices: list[Notice] = []
    for raw in data.get("notices") or []:
        if not isinstance(raw, dict):
            raise JurisdictionError(f"{where}: a notice must be a mapping")
        nid = str(_require(raw, "id", f"{where} notice")).strip()
        notices.append(
            Notice(
                id=nid,
                text=str(_require(raw, "text", f"{where} notice {nid}")).strip(),
                text_en=str(raw.get("text_en") or "").strip(),
                source_url=str(raw.get("source_url") or "").strip(),
                status=str(raw.get("status") or "").strip(),
                scored=bool(raw.get("scored", False)),
            )
        )

    return Jurisdiction(
        code=file_code,
        language=language,
        law=law,
        entity_terms=terms,
        article_map=article_map,
        extras=tuple(extras),
        deadlines=tuple(deadlines),
        sector_authorities=sectors,
        notices=tuple(notices),
        clocks=_clocks(data.get("incident_clocks"), where),
        domain_title=str(data.get("domain_title") or f"National requirements ({file_code.upper()})").strip(),
    )


def load_jurisdiction(code: str, path: str | Path | None = None) -> Jurisdiction:
    code = code.strip().lower()
    if path is None:
        text = (
            resources.files("nis2check")
            .joinpath(f"data/jurisdictions/{code}.yaml")
            .read_text("utf-8")
        )
    else:
        text = Path(path).read_text("utf-8")
    return parse_jurisdiction(yaml.safe_load(text), code)


@lru_cache(maxsize=8)
def _cached(code: str) -> Jurisdiction:
    return load_jurisdiction(code)


def experimental_countries() -> frozenset[str]:
    """Countries named in ``NIS2_EXPERIMENTAL_COUNTRIES`` may be offered with blocked citations."""
    raw = os.environ.get("NIS2_EXPERIMENTAL_COUNTRIES", "")
    return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())


def references_acceptable(jurisdiction: Jurisdiction) -> bool:
    """True when every citation is verified, or blocked and the country is experimental.

    A blocked citation is never treated as verified. It can be offered only when
    the country code is listed in ``NIS2_EXPERIMENTAL_COUNTRIES``.
    """
    experimental = jurisdiction.code in experimental_countries()
    for ref in jurisdiction.article_map.values():
        if ref.verified is True:
            if not ref.evidence_quote.strip():
                return False
            continue
        if experimental and ref.status == "blocked":
            continue
        return False
    for question in jurisdiction.extras:
        if question.verified is not True or not question.evidence_quote.strip():
            return False
    for deadline in jurisdiction.deadlines:
        if deadline.verified is not True or not deadline.evidence_quote.strip():
            return False
    clocks = jurisdiction.clocks
    if clocks.source_url and (clocks.verified is not True or not clocks.evidence_quote.strip()):
        return False
    return True


def get_jurisdiction(code: str | None) -> Jurisdiction | None:
    """The overlay for ``sk``, ``cz``, ``hu`` or ``pl``. ``eu`` and unknown codes are None.

    A country that is not fully verified is not offered, unless it is listed in
    ``NIS2_EXPERIMENTAL_COUNTRIES`` and every citation that is not verified is
    marked ``blocked``.
    """
    if not code:
        return None
    normalised = str(code).strip().lower()
    if normalised in ("", "eu"):
        return None
    if normalised not in NATIONAL_CODES:
        return None
    loaded = _cached(normalised)
    if references_acceptable(loaded):
        return loaded
    return None


def with_national(catalogue: Catalogue, jurisdiction: Jurisdiction | None) -> Catalogue:
    """Append the country's extra questions as one domain. ``None`` leaves the catalogue."""
    if jurisdiction is None:
        return catalogue
    if any(domain.id == jurisdiction.domain_id for domain in catalogue.domains):
        return catalogue
    clash = [
        question.id
        for question in jurisdiction.extras
        if question.id in set(catalogue.question_ids)
    ]
    if clash:
        raise JurisdictionError(f"national question ids already exist: {', '.join(clash)}")
    domain = Domain(
        id=jurisdiction.domain_id,
        article=jurisdiction.law.citation_label,
        title=jurisdiction.domain_title,
        summary=(
            f"Obligations in {jurisdiction.law.name} that do not have a one-to-one "
            f"article in Directive (EU) 2022/2555."
        ),
        questions=jurisdiction.extras,
        framework="nis2",
    )
    return Catalogue(
        version=catalogue.version,
        source=catalogue.source,
        domains=catalogue.domains + (domain,),
    )


def format_citation(directive_article: str, jurisdiction: Jurisdiction | None, question: Question | None = None) -> list[dict]:
    """Pieces to print for one finding: the Directive citation and the national one.

    Each piece is ``{"text", "unverified", "note"}``. An empty national ref is
    omitted. ``unverified`` is true when the country file says the citation was
    not confirmed against the official consolidated text.
    """
    pieces: list[dict] = []
    article = (directive_article or "").strip()
    national_question = bool(question and question.domain_id.startswith("NAT-"))
    directive = article.startswith("Art.") or article.startswith("Annex")
    if article and not national_question:
        text = f"NIS2 {article}" if jurisdiction and directive else article
        pieces.append({"text": text, "unverified": False, "note": ""})
    if jurisdiction is None:
        return pieces
    entry = jurisdiction.article_map.get(article) if directive and not national_question else None
    if entry and entry.ref:
        pieces.append({
            "text": f"{entry.ref} {jurisdiction.law.citation_label}",
            "unverified": not entry.verified,
            "note": entry.note,
        })
    elif national_question and question and question.article:
        pieces.append({
            "text": f"{question.article} {jurisdiction.law.citation_label}",
            "unverified": question.verified is False,
            "note": question.note,
        })
    elif entry and not entry.verified:
        pieces.append({
            "text": jurisdiction.law.citation_label,
            "unverified": True,
            "note": entry.note,
        })
    return pieces
