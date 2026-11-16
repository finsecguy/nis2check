"""Indicative NIS2 scope check (size-cap rule, Annex I and Annex II sectors).

This is a first screen, not legal advice. National transposition laws and
designations by the competent authority can change the outcome.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Annex I: sectors of high criticality
ANNEX_I = {
    "energy": "Energy",
    "transport": "Transport",
    "banking": "Banking",
    "financial_market_infrastructure": "Financial market infrastructures",
    "health": "Health",
    "drinking_water": "Drinking water",
    "waste_water": "Waste water",
    "digital_infrastructure": "Digital infrastructure",
    "ict_service_management": "ICT service management (B2B)",
    "public_administration": "Public administration",
    "space": "Space",
}

# Annex II: other critical sectors
ANNEX_II = {
    "postal_courier": "Postal and courier services",
    "waste_management": "Waste management",
    "chemicals": "Manufacture, production and distribution of chemicals",
    "food": "Production, processing and distribution of food",
    "manufacturing": "Manufacturing (medical devices, electronics, machinery, vehicles, etc.)",
    "digital_providers": "Digital providers (marketplaces, search engines, social networks)",
    "research": "Research organisations",
}

SECTORS = {**ANNEX_I, **ANNEX_II}


@dataclass
class Entity:
    name: str = ""
    sector: str | None = None
    employees: int | None = None
    annual_turnover_eur: float | None = None
    balance_sheet_eur: float | None = None
    size_exempt: bool = False  # e.g. DNS, TLD registry, trust service provider


@dataclass
class Applicability:
    size: str  # large | medium | small | unknown
    annex: str | None  # "I" | "II" | None
    in_scope: bool | None  # None = cannot tell
    classification: str | None  # essential | important | None
    notes: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.in_scope is None:
            return "Needs review"
        if not self.in_scope:
            return "Likely out of scope"
        if self.classification:
            return f"Likely in scope ({self.classification} entity)"
        return "Likely in scope"


def size_class(
    employees: int | None,
    turnover: float | None = None,
    balance: float | None = None,
) -> str:
    """Enterprise size per Commission Recommendation 2003/361/EC.

    Large: 250+ staff, or turnover > EUR 50m and balance sheet > EUR 43m.
    Medium: 50+ staff, or turnover > EUR 10m and balance sheet > EUR 10m.
    """
    if employees is None and (turnover is None or balance is None):
        return "unknown"
    financials = turnover is not None and balance is not None
    if (employees is not None and employees >= 250) or (
        financials and turnover > 50_000_000 and balance > 43_000_000
    ):
        return "large"
    if (employees is not None and employees >= 50) or (
        financials and turnover > 10_000_000 and balance > 10_000_000
    ):
        return "medium"
    return "small"


def assess_applicability(entity: Entity) -> Applicability:
    size = size_class(entity.employees, entity.annual_turnover_eur, entity.balance_sheet_eur)
    sector = entity.sector
    annex = "I" if sector in ANNEX_I else "II" if sector in ANNEX_II else None
    notes: list[str] = []

    if sector and sector not in SECTORS:
        notes.append(f"Unknown sector '{sector}'. Use one of: {', '.join(sorted(SECTORS))}.")

    if sector == "public_administration":
        notes.append(
            "Public administration scope is set by national law, not by company size."
        )
        return Applicability(size, annex, None, None, notes)

    if entity.size_exempt:
        notes.append(
            "Marked as size-exempt (e.g. DNS provider, TLD registry, trust service "
            "provider): in scope regardless of size. Confirm classification with the "
            "national authority."
        )
        return Applicability(size, annex, True if annex else None, None, notes)

    if annex is None:
        if sector is None:
            notes.append("No sector given; cannot determine scope.")
            return Applicability(size, None, None, None, notes)
        notes.append("Sector is not listed in NIS2 Annex I or II.")
        notes.append(
            "Organisations outside scope are still often asked NIS2 questions by "
            "in-scope customers through supply chain requirements."
        )
        return Applicability(size, None, False, None, notes)

    if size == "unknown":
        notes.append("Provide employees or turnover and balance sheet to check the size cap.")
        return Applicability(size, annex, None, None, notes)

    if size == "small":
        notes.append(
            "Below the medium-enterprise threshold, so normally out of scope unless "
            "designated by the national authority."
        )
        notes.append(
            "Small suppliers to in-scope entities are still affected through "
            "Art. 21(2)(d) supply chain requirements."
        )
        return Applicability(size, annex, False, None, notes)

    classification = "essential" if annex == "I" and size == "large" else "important"
    notes.append(
        f"{size.capitalize()} enterprise in an Annex {annex} sector "
        f"({SECTORS[sector]})."
    )
    if classification == "important" and annex == "I":
        notes.append("Member States may still designate it as essential.")
    if sector in ("banking", "financial_market_infrastructure"):
        notes.append(
            "Financial entities: DORA (Regulation (EU) 2022/2554) applies as sector-"
            "specific law for ICT risk management and incident reporting (NIS2 Art. 4)."
        )
    return Applicability(size, annex, True, classification, notes)
