"""Weighting engine: how much each control counts in scores and rankings.

Two strategies:

static
    The regulatory baseline from the catalogue: critical 3, high 2, medium 1.

threat
    The baseline, raised by up to 50% for controls that counter common threats:

        exposure(control) = sum of adjusted prevalence of the threat patterns it counters
        multiplier        = 1 + 0.5 x exposure / max exposure across all controls
        weight            = baseline x multiplier

    Threat data can only raise a weight, never lower it below the regulatory
    baseline, because every NIS2 control is a legal requirement regardless of how
    often the threat it addresses shows up in incident data.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .controls import Catalogue, Question
from .threat.data import ThreatData

MAX_UPLIFT = 0.5
MODES = ("static", "threat")


@dataclass
class WeightInfo:
    weight: float
    base: int
    multiplier: float = 1.0
    exposure: float = 0.0
    patterns: list[str] = field(default_factory=list)
    via: dict[str, str] = field(default_factory=dict)  # pattern -> "ATT&CK M1032" / "catalogue"

    def rationale(self, threat: ThreatData | None = None) -> str:
        if not self.patterns:
            return f"Regulatory baseline {self.base} (no linked threat pattern)."
        parts = []
        for pid in self.patterns:
            info = threat.patterns.get(pid, {}) if threat else {}
            name = info.get("name", pid)
            share = info.get("adjusted_prevalence")
            share_txt = ""
            if share is not None:
                share_txt = f" {share * 100:.1f}%" if share < 0.1 else f" {share * 100:.0f}%"
                share_txt += " of incidents"
            parts.append(f"{name}{share_txt} ({self.via.get(pid, '')})")
        return (
            f"Baseline {self.base} x {self.multiplier:.2f} = {self.weight:.2f}. "
            f"Counters: " + "; ".join(parts) + "."
        )


def _share(share: float) -> str:
    return f"{share * 100:.1f}%" if share < 0.1 else f"{share * 100:.0f}%"


def plain_reason(info: WeightInfo, threat: ThreatData | None) -> str | None:
    """One sentence for non-specialists: why this control counts more than its baseline."""
    if not info.patterns or not threat or info.multiplier <= 1.005:
        return None
    parts = []
    for pid in info.patterns[:3]:
        p = threat.patterns.get(pid, {})
        name = p.get("name", pid)
        name = name[0].lower() + name[1:] if len(name) > 1 and name[1].islower() else name
        share = p.get("adjusted_prevalence")
        parts.append(f"{name} ({_share(share)} of recorded incidents)" if share is not None else name)
    listed = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]
    return f"This counts more in your score because it protects against {listed}."


def linked_patterns(q: Question, threat: ThreatData) -> dict[str, str]:
    """Patterns a control counters, and how the link was established."""
    via: dict[str, str] = {}
    for pid, info in threat.patterns.items():
        shared = sorted(set(q.attack_mitigations) & set(info.get("attack_mitigations", [])))
        if shared:
            via[pid] = "ATT&CK " + ", ".join(shared)
    for pid in q.threat_patterns:
        if pid in threat.patterns and pid not in via:
            via[pid] = "catalogue"
    return via


def compute_weights(
    catalogue: Catalogue, threat: ThreatData | None = None, mode: str = "threat"
) -> dict[str, WeightInfo]:
    if mode not in MODES:
        raise ValueError(f"weighting mode must be one of {MODES}")
    if mode == "static" or threat is None:
        return {q.id: WeightInfo(weight=float(q.weight), base=q.weight) for q in catalogue.questions()}

    links = {q.id: linked_patterns(q, threat) for q in catalogue.questions()}
    exposure = {
        qid: sum(threat.patterns[p].get("adjusted_prevalence", 0.0) for p in via)
        for qid, via in links.items()
    }
    max_exposure = max(exposure.values()) or 1.0

    weights = {}
    for q in catalogue.questions():
        e = exposure[q.id]
        multiplier = round(1 + MAX_UPLIFT * e / max_exposure, 3)
        weights[q.id] = WeightInfo(
            weight=round(q.weight * multiplier, 2),
            base=q.weight,
            multiplier=multiplier,
            exposure=round(e, 4),
            patterns=sorted(links[q.id], key=lambda p: -threat.patterns[p].get("adjusted_prevalence", 0)),
            via=links[q.id],
        )
    return weights
