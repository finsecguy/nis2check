"""Score an assessment and produce the gap analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .applicability import Applicability, assess_applicability
from .assessment import ANSWER_VALUES, Assessment, Response
from .controls import Catalogue, Domain, Question
from .weighting import WeightInfo

MATURITY_BANDS = [
    (90, "Strong"),
    (70, "Substantial"),
    (40, "Partial"),
    (0, "Low"),
]


def maturity(pct: float | None) -> str:
    if pct is None:
        return "Not assessed"
    for threshold, label in MATURITY_BANDS:
        if pct >= threshold:
            return label
    return "Low"


@dataclass
class Finding:
    question: Question
    response: Response
    status: str  # met | partial | gap | unanswered | na
    evidence_issues: list[str] = field(default_factory=list)
    weight_info: WeightInfo | None = None

    @property
    def weight(self) -> float:
        return self.weight_info.weight if self.weight_info else float(self.question.weight)

    @property
    def score(self) -> float | None:
        """Self-assessed score (unanswered counts as 0)."""
        if self.status == "na":
            return None
        return ANSWER_VALUES.get(self.response.answer) or 0.0

    @property
    def verified_score(self) -> float | None:
        """Score that only counts answers backed by usable evidence."""
        if self.score is None:
            return None
        return 0.0 if self.evidence_issues else self.score

    @property
    def priority_score(self) -> float:
        """Risk reduction from closing the gap: control weight x missing coverage."""
        if self.score is None:
            return 0.0
        return round(self.weight * (1.0 - self.score), 3)

    @property
    def value(self) -> float:
        """Risk reduction per unit of effort (low 1, medium 2, high 3)."""
        return round(self.priority_score / self.question.effort_cost, 3)


@dataclass
class DomainResult:
    domain: Domain
    findings: list[Finding]

    @property
    def score_pct(self) -> float | None:
        return _weighted_pct(self.findings, verified=False)

    @property
    def verified_pct(self) -> float | None:
        return _weighted_pct(self.findings, verified=True)

    @property
    def maturity(self) -> str:
        return maturity(self.score_pct)

    @property
    def counts(self) -> dict[str, int]:
        out = {k: 0 for k in ("met", "partial", "gap", "unanswered", "na")}
        for f in self.findings:
            out[f.status] += 1
        return out


@dataclass
class Result:
    domains: list[DomainResult]
    applicability: Applicability
    weighting: str = "static"
    rank_by: str = "risk"  # risk | value

    @property
    def findings(self) -> list[Finding]:
        return [f for d in self.domains for f in d.findings]

    @property
    def score_pct(self) -> float | None:
        return _weighted_pct(self.findings, verified=False)

    @property
    def verified_pct(self) -> float | None:
        return _weighted_pct(self.findings, verified=True)

    @property
    def maturity(self) -> str:
        return maturity(self.score_pct)

    @property
    def gaps(self) -> list[Finding]:
        """Open items, most important first."""
        open_items = [f for f in self.findings if f.status in ("gap", "partial", "unanswered")]
        if self.rank_by == "value":
            return sorted(open_items, key=lambda f: (-f.value, -f.priority_score))
        return sorted(open_items, key=lambda f: (-f.priority_score, f.question.effort_cost))

    @property
    def evidence_issues(self) -> list[Finding]:
        return [f for f in self.findings if f.evidence_issues]

    @property
    def counts(self) -> dict[str, int]:
        out = {k: 0 for k in ("met", "partial", "gap", "unanswered", "na")}
        for d in self.domains:
            for k, v in d.counts.items():
                out[k] += v
        return out


def _weighted_pct(findings: list[Finding], verified: bool) -> float | None:
    total = earned = 0.0
    for f in findings:
        score = f.verified_score if verified else f.score
        if score is None:
            continue
        total += f.weight
        earned += f.weight * score
    if total == 0:
        return None
    return round(100 * earned / total, 1)


def _is_url(item: str) -> bool:
    return item.lower().startswith(("http://", "https://"))


def check_evidence(response: Response, base_dir: Path) -> list[str]:
    """Return problems with the evidence behind a yes/partial answer."""
    if response.answer not in ("yes", "partial"):
        return []
    if not response.evidence:
        return list(response.extra_issues) + ["No evidence recorded"]
    issues = list(response.extra_issues)
    for item in response.evidence:
        if _is_url(item):
            continue
        path = Path(item)
        if not path.is_absolute():
            path = base_dir / path
        if not path.exists():
            issues.append(f"Evidence file not found: {item}")
    return issues


def _status(response: Response) -> str:
    return {
        None: "unanswered",
        "yes": "met",
        "partial": "partial",
        "no": "gap",
        "na": "na",
    }[response.answer]


def evaluate(
    catalogue: Catalogue,
    assessment: Assessment,
    weights: dict[str, WeightInfo] | None = None,
    weighting: str = "static",
    rank_by: str = "risk",
) -> Result:
    if rank_by not in ("risk", "value"):
        raise ValueError("rank_by must be 'risk' or 'value'")
    domains = []
    for domain in catalogue.domains:
        findings = []
        for q in domain.questions:
            response = assessment.responses.get(q.id) or Response(q.id)
            findings.append(
                Finding(
                    question=q,
                    response=response,
                    status=_status(response),
                    evidence_issues=check_evidence(response, assessment.base_dir),
                    weight_info=(weights or {}).get(q.id),
                )
            )
        domains.append(DomainResult(domain, findings))
    return Result(
        domains=domains,
        applicability=assess_applicability(assessment.entity),
        weighting=weighting if weights else "static",
        rank_by=rank_by,
    )
