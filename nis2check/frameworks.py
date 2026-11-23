"""Which regulation an assessment covers.

The scoring, evidence and report code all take a catalogue. NIS2 and DORA are
two catalogues. Selecting both concatenates them; question ids do not overlap.
"""

from __future__ import annotations

from importlib import resources

import yaml

from .controls import Catalogue, CatalogueError, parse_catalogue

FRAMEWORK_IDS = ("nis2", "dora")

_FILES = {
    "nis2": "data/controls.yaml",
    "dora": "data/dora.yaml",
}

_LABELS = {"nis2": "NIS2", "dora": "DORA"}

# Shown wherever someone could treat the two regimes as the same duty.
# DORA recital 16: this Regulation constitutes lex specialis with regard to Directive
# (EU) 2022/2555. Art. 1(2) limits that to financial entities identified as essential
# or important under national rules transposing NIS2 Art. 3. NIS2 Art. 4 then sets
# the relevant provisions aside where the sector-specific requirements are at least
# equivalent. NIS2 recital 28 names which DORA rules apply instead.
LEX_SPECIALIS = (
    "For a financial entity identified as essential or important under national rules "
    "transposing Article 3 of Directive (EU) 2022/2555, Regulation (EU) 2022/2554 is a "
    "sector-specific Union legal act for the purposes of Article 4 of that Directive "
    "(DORA Article 1(2)) and constitutes lex specialis with regard to the Directive "
    "(DORA recital 16). Where those requirements are at least equivalent in effect, the "
    "relevant provisions of the Directive, including supervision and enforcement, do not "
    "apply (NIS2 Article 4). Recital 28 of the Directive states that the DORA rules on ICT "
    "risk management, management of ICT-related incidents and major ICT-related incident "
    "reporting, digital operational resilience testing, information-sharing arrangements "
    "and ICT third-party risk apply instead, and that Member States should not apply the "
    "cybersecurity risk-management and reporting obligations of the Directive, or its "
    "supervision and enforcement, to financial entities covered by DORA. "
    "This note is indicative and is not legal advice."
)

# The size and sector check in this app implements the NIS2 rules only.
DORA_SCOPE_NOTE = (
    "The size and sector outcome is the NIS2 applicability check. It does not decide "
    "whether DORA applies. DORA applies to the financial entities referred to in "
    "Article 2(1), points (a) to (t), of Regulation (EU) 2022/2554, subject to the "
    "exclusions in Article 2(3) and (4)."
)

_cache: dict[str, Catalogue] = {}


def framework_label(ids: tuple[str, ...]) -> str:
    """Human label, in catalogue order: 'NIS2', 'DORA', or 'NIS2 and DORA'."""
    return " and ".join(_LABELS.get(i, i) for i in ids) or "NIS2"


def parse_frameworks(value, *, default: tuple[str, ...] | None = ("nis2",)) -> tuple[str, ...]:
    """Normalise a form value, CLI flag or YAML list to known framework ids.

    ``default`` is used when the value is missing or empty. Pass ``default=None``
    to reject an empty selection instead.
    """
    if value is None:
        if default is None:
            raise ValueError("select at least one framework")
        return tuple(default)
    if isinstance(value, str):
        parts = [p.strip().lower() for p in value.replace(";", ",").split(",")]
    elif isinstance(value, (list, tuple)):
        parts = [str(p).strip().lower() for p in value]
    else:
        raise ValueError("frameworks must be a list or a comma-separated string")
    parts = [p for p in parts if p]
    if not parts:
        if default is None:
            raise ValueError("select at least one framework")
        return tuple(default)
    unknown = [p for p in parts if p not in FRAMEWORK_IDS]
    if unknown:
        known = ", ".join(FRAMEWORK_IDS)
        raise ValueError(f"unknown framework: {', '.join(unknown)}. Known values: {known}")
    return tuple(fid for fid in FRAMEWORK_IDS if fid in parts)


def bundled(framework_id: str) -> Catalogue:
    """The bundled catalogue for one framework. Parsed once per process."""
    if framework_id not in _FILES:
        raise CatalogueError(f"unknown framework '{framework_id}'")
    cat = _cache.get(framework_id)
    if cat is None:
        text = resources.files("nis2check").joinpath(_FILES[framework_id]).read_text("utf-8")
        cat = parse_catalogue(yaml.safe_load(text))
        _cache[framework_id] = cat
    return cat


def load_bundled_catalogue(ids: tuple[str, ...]) -> Catalogue:
    """One catalogue containing exactly the requested frameworks, NIS2 first."""
    if not ids:
        raise CatalogueError("select at least one framework")
    unknown = [i for i in ids if i not in _FILES]
    if unknown:
        raise CatalogueError(f"unknown framework: {', '.join(unknown)}")
    cats = [bundled(i) for i in ids]
    if len(cats) == 1:
        return cats[0]
    return _combine(cats)


def _combine(cats: list[Catalogue]) -> Catalogue:
    seen: set[str] = set()
    domains = []
    for cat in cats:
        for domain in cat.domains:
            clash = [i for i in (domain.id, *(q.id for q in domain.questions)) if i in seen]
            if clash:
                raise CatalogueError(f"duplicate id across frameworks: {', '.join(clash)}")
            seen.update((domain.id, *(q.id for q in domain.questions)))
            domains.append(domain)
    return Catalogue(
        version="+".join(c.version for c in cats if c.version),
        source="; ".join(c.source for c in cats if c.source),
        domains=tuple(domains),
    )


def framework_ids_of(catalogue: Catalogue) -> tuple[str, ...]:
    ids: list[str] = []
    for domain in catalogue.domains:
        if domain.framework not in ids:
            ids.append(domain.framework)
    return tuple(ids) or ("nis2",)


def narrow_catalogue(catalogue: Catalogue, ids: tuple[str, ...]) -> Catalogue:
    """Drop domains whose framework is not selected.

    A selection that is only bundled frameworks is rebuilt from those files, so
    the report source line stays 'Directive (EU) 2022/2555 (NIS2)' rather than
    the merged label.
    """
    wanted = set(ids)
    domains = tuple(d for d in catalogue.domains if d.framework in wanted)
    if len(domains) == len(catalogue.domains):
        return catalogue
    present = tuple(fid for fid in FRAMEWORK_IDS if fid in wanted and any(d.framework == fid for d in domains))
    # Preserve a non-bundled order (a custom catalogue) by following ``ids``.
    if not present:
        present = tuple(dict.fromkeys(d.framework for d in domains))
    if not present:
        raise CatalogueError("none of the selected frameworks are in this catalogue")
    if set(present) <= set(FRAMEWORK_IDS) and all(d.framework in FRAMEWORK_IDS for d in domains):
        return load_bundled_catalogue(present)
    return Catalogue(version=catalogue.version, source=catalogue.source, domains=domains)
