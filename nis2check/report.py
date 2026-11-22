"""Render results as an HTML/PDF report, CSV gap register, JSON, or terminal summary."""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape
from markupsafe import Markup, escape

from . import __version__
from .applicability import SECTORS
from .assessment import Assessment
from .controls import Catalogue
from .frameworks import DORA_SCOPE_NOTE, LEX_SPECIALIS, framework_label
from .scoring import Finding, Result

STATUS_LABELS = {
    "met": "Met",
    "partial": "Partially met",
    "gap": "Not met",
    "unanswered": "Not assessed",
    "na": "N/A",
}

PRIORITY_LABELS = {"critical": "Critical", "high": "High", "medium": "Medium"}

CSV_COLUMNS = [
    "Rank", "Ref", "Legal reference", "Domain", "Control", "Priority", "Status", "RAG",
    "Effort", "Weight", "Risk reduction", "Risk reduction per effort", "Quadrant",
    "Recommended action", "Evidence issue", "Owner", "Target date", "Weight rationale",
    "Assessor notes",
]

QUADRANTS = {
    ("high", "low"): "Quick win",
    ("high", "high"): "Major project",
    ("low", "low"): "Fill-in",
    ("low", "high"): "Schedule later",
}


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0f}%"


def rag(value: float | None) -> str:
    """Red / Amber / Green rating used across the report."""
    if value is None:
        return "grey"
    if value >= 70:
        return "green"
    if value >= 40:
        return "amber"
    return "red"


def finding_rag(f: Finding) -> str:
    if f.status == "na":
        return "grey"
    if f.priority_score >= 2:
        return "red"
    if f.priority_score > 0:
        return "amber"
    return "green"


def gap_median(gaps: list[Finding]) -> float:
    """Median risk-reduction score across the open items, used as the impact threshold."""
    scores = sorted(g.priority_score for g in gaps)
    return scores[len(scores) // 2] if scores else 0


def quadrant(f: Finding, median: float) -> str:
    """Impact vs effort quadrant. Impact is high when the risk reduction is at or
    above ``median`` (the median of all open items); effort is low only for 'low' effort.

    ``median`` is computed once by the caller via ``gap_median`` rather than per finding,
    so rendering a report is linear in the number of gaps instead of quadratic."""
    impact = "high" if f.priority_score >= median and f.priority_score > 0 else "low"
    effort = "low" if f.question.effort == "low" else "high"
    return QUADRANTS[(impact, effort)]


def effort_matrix(result: Result) -> dict[str, list[Finding]]:
    gaps = result.gaps
    median = gap_median(gaps)
    out: dict[str, list[Finding]] = {name: [] for name in QUADRANTS.values()}
    for f in gaps:
        out[quadrant(f, median)].append(f)
    return out


def heat_map(result: Result) -> list[dict]:
    """Rows: priority. Columns: status. Cells: count and severity colour."""
    columns = ["gap", "unanswered", "partial", "met"]
    rows = []
    for priority, weight in (("critical", 3), ("high", 2), ("medium", 1)):
        cells = []
        for status in columns:
            count = sum(
                1 for f in result.findings
                if f.question.priority == priority and f.status == status
            )
            score = {"gap": 0.0, "unanswered": 0.0, "partial": 0.5, "met": 1.0}[status]
            severity = weight * (1 - score)
            colour = "red" if severity >= 2 else "amber" if severity >= 1 else (
                "yellow" if severity > 0 else "green")
            cells.append({"count": count, "colour": colour})
        rows.append({"label": PRIORITY_LABELS[priority], "cells": cells})
    return rows


def _lower_first(text: str) -> str:
    """Lowercase the first letter for mid-sentence use, but keep acronyms like HR."""
    if len(text) > 1 and text[1].islower():
        return text[0].lower() + text[1:]
    return text


def _framework_ids(result: Result) -> tuple[str, ...]:
    ids: list[str] = []
    for domain in result.domains:
        if domain.domain.framework not in ids:
            ids.append(domain.domain.framework)
    return tuple(ids) or ("nis2",)


def _domain_article(result: Result, domain_id: str) -> str:
    return next(d.domain.article for d in result.domains if d.domain.id == domain_id)


def _legal_reference(result: Result, finding: Finding) -> str:
    return finding.question.article or _domain_article(result, finding.question.domain_id)


def _domain_title(result: Result, domain_id: str) -> str:
    return next(d.domain.title for d in result.domains if d.domain.id == domain_id)


def executive_summary(result: Result, assessment: Assessment) -> list[Markup]:
    """Plain-language summary paragraphs for the first page.

    Paragraphs contain <b> markup, so every user-supplied value is escaped.
    """
    return [Markup(p) for p in _summary_text(result, assessment)]


def _summary_text(result: Result, assessment: Assessment) -> list[str]:
    name = escape(assessment.entity.name or "The organisation")
    a = result.applicability
    c = result.counts
    applicable = c["met"] + c["partial"] + c["gap"] + c["unanswered"]

    if a.in_scope is True and a.classification:
        scope = (
            f"is likely within the scope of NIS2 as an <b>{a.classification} entity</b> "
            f"({a.size} enterprise, Annex {a.annex} sector)"
        )
    elif a.in_scope is True:
        scope = "is likely within the scope of NIS2"
    elif a.in_scope is False:
        scope = (
            "appears to fall outside the direct scope of NIS2, although in-scope customers "
            "may still require NIS2-aligned controls through their supply chain obligations"
        )
    else:
        scope = "could not be conclusively classified; scope requires further review"

    ids = _framework_ids(result)
    if ids == ("dora",):
        opening = (
            f"{name} was assessed against Regulation (EU) 2022/2554 (DORA), Articles 5 to 45, "
            f"covering ICT risk management, incident reporting, resilience testing, ICT third-party "
            f"risk and information sharing. Based on the information provided, the organisation {scope}. "
            f"That scope check is the NIS2 test and does not decide whether DORA applies."
        )
    elif "dora" in ids and "nis2" in ids:
        opening = (
            f"{name} was assessed against Directive (EU) 2022/2555 (NIS2), Articles 20, 21 and 23, "
            f"and against Regulation (EU) 2022/2554 (DORA), Articles 5 to 45. "
            f"Based on the information provided, the organisation {scope}."
        )
    else:
        opening = (
            f"{name} was assessed against the cybersecurity risk-management, governance and "
            f"incident reporting requirements of Directive (EU) 2022/2555 (NIS2), Articles 20, 21 "
            f"and 23. Based on the information provided, the organisation {scope}."
        )
    paras = [opening]

    overall = (
        f"Overall compliance is assessed at <b>{_pct(result.score_pct)}</b> "
        f"(maturity: {result.maturity.lower()}). Of {applicable} applicable controls, "
        f"{c['met']} are met, {c['partial']} partially met, {c['gap']} not met"
    )
    overall += f" and {c['unanswered']} not yet assessed." if c["unanswered"] else "."
    if result.verified_pct is not None and result.score_pct and result.verified_pct < result.score_pct:
        overall += (
            f" Only <b>{_pct(result.verified_pct)}</b> is supported by evidence, so the position "
            f"should be treated as indicative until the {len(result.evidence_issues)} evidence "
            f"gaps are closed."
        )
    paras.append(overall)

    scored = [d for d in result.domains if d.score_pct is not None]
    weakest = sorted(scored, key=lambda d: d.score_pct)[:3]
    if weakest and weakest[0].score_pct < 70:
        parts = [
            f"{escape(_lower_first(d.domain.title))} ({escape(d.domain.article)}, {_pct(d.score_pct)})"
            for d in weakest
        ]
        text = "The weakest areas are " + ", ".join(parts[:-1]) + f" and {parts[-1]}." if len(parts) > 1 \
            else f"The weakest area is {parts[0]}."
        critical_open = [
            f for f in result.gaps if f.question.priority == "critical" and f.status in ("gap", "unanswered")
        ]
        if critical_open:
            text += (
                f" {len(critical_open)} critical control{'s are' if len(critical_open) != 1 else ' is'} "
                f"not met or not assessed; these should be addressed first (see section 4)."
            )
        paras.append(text)

    quick = effort_matrix(result)["Quick win"] if result.gaps else []
    if quick:
        ids = ", ".join(escape(f.question.id) for f in quick[:6])
        paras.append(
            f"{len(quick)} open item{'s are' if len(quick) != 1 else ' is'} high impact and low effort "
            f"(quick wins): {ids}{', and others' if len(quick) > 6 else ''}. Closing these first gives "
            f"the fastest reduction in risk (see section 3.3)."
        )
    return paras


def gap_rows(result: Result, threat=None) -> list[dict]:
    gaps = result.gaps
    median = gap_median(gaps)
    rows = []
    for i, f in enumerate(gaps, 1):
        rows.append({
            "Rank": i,
            "Ref": f.question.id,
            "Legal reference": _legal_reference(result, f),
            "Domain": _domain_title(result, f.question.domain_id),
            "Control": f.question.text,
            "Priority": PRIORITY_LABELS[f.question.priority],
            "Status": STATUS_LABELS[f.status],
            "RAG": finding_rag(f).capitalize(),
            "Effort": f.question.effort.capitalize(),
            "Weight": f.weight,
            "Risk reduction": f.priority_score,
            "Risk reduction per effort": f.value,
            "Quadrant": quadrant(f, median),
            "Recommended action": f.question.remediation,
            "Evidence issue": "; ".join(f.evidence_issues),
            "Owner": "",
            "Target date": "",
            "Weight rationale": f.weight_info.rationale(threat) if f.weight_info else "",
            "Assessor notes": f.response.notes,
        })
    return rows


def render_csv(result: Result, threat=None) -> str:
    """Gap register for Excel. UTF-8 with BOM so Excel shows accents correctly."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    writer.writerows(gap_rows(result, threat))
    return "﻿" + buf.getvalue()


def fonts_css_uri() -> str:
    """file:// URI of the bundled font stylesheet, for PDF rendering."""
    from importlib import resources
    return Path(str(resources.files("nis2check").joinpath("web/static/fonts/fonts.css"))).resolve().as_uri()


def render_html(
    result: Result, assessment: Assessment, catalogue: Catalogue, top: int = 10, threat=None,
    embedded: bool = False, font_css: str | None = None,
) -> str:
    """Render the report.

    ``embedded`` drops the download toolbar and script (web app view, PDF).
    ``font_css`` links the bundled fonts; without it the report falls back to system fonts.
    """
    env = Environment(
        loader=PackageLoader("nis2check", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["pct"] = _pct
    env.filters["rag"] = rag
    report_median = gap_median(result.gaps)
    env.globals.update(
        quadrant=lambda f: quadrant(f, report_median),
        finding_rag=finding_rag,
        status_label=STATUS_LABELS,
        priority_label=PRIORITY_LABELS,
    )
    slug = "".join(ch if ch.isalnum() else "-" for ch in (assessment.entity.name or "nis2")).strip("-")
    ids = _framework_ids(result)
    label = framework_label(ids)
    cover = {
        ("dora",): "Articles 5 to 45 of Regulation (EU) 2022/2554 (DORA)",
    }.get(ids)
    if cover is None and "dora" in ids and "nis2" in ids:
        cover = "Directive (EU) 2022/2555 (NIS2) and Regulation (EU) 2022/2554 (DORA)"
    elif cover is None:
        cover = "Articles 20, 21 and 23 of Directive (EU) 2022/2555"
    return env.get_template("report.html.j2").render(
        result=result,
        assessment=assessment,
        catalogue=catalogue,
        summary=executive_summary(result, assessment),
        heat=heat_map(result),
        matrix=effort_matrix(result),
        threat=threat if result.weighting == "threat" else None,
        uplifted=sorted(
            (f for f in result.findings if f.weight_info and f.weight - f.weight_info.base >= 0.01),
            key=lambda f: -f.weight_info.multiplier,
        ),
        top_gaps=result.gaps[:top],
        csv_data=render_csv(result, threat),
        embedded=embedded,
        font_css=font_css,
        file_slug=f"{label.replace(' ', '-')}-gap-register-{slug[:40]}",
        kicker=f"{label} gap assessment",
        measures=f"{label} measures",
        cover_line=cover,
        show_lex="dora" in ids,
        lex_specialis=LEX_SPECIALIS,
        dora_scope_note=DORA_SCOPE_NOTE,
        sector_label=SECTORS.get(assessment.entity.sector or "", assessment.entity.sector),
        report_date=assessment.assessed_on or dt.date.today().isoformat(),
        generated=dt.datetime.now().strftime("%d %b %Y"),
        version=__version__,
    )


def write_pdf(html: str, path: str | Path) -> None:
    """Render the HTML report to PDF. Needs the optional 'pdf' extra (WeasyPrint)."""
    try:
        from weasyprint import HTML
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise RuntimeError(
            "PDF export needs WeasyPrint. Install it with: pip install 'nis2check[pdf]'"
        ) from exc
    HTML(string=html).write_pdf(str(path))


def to_dict(result: Result, assessment: Assessment, catalogue: Catalogue, threat=None) -> dict:
    a = result.applicability
    gaps = result.gaps
    gaps_median = gap_median(gaps)
    return {
        "tool": {"name": "nis2check", "version": __version__},
        "catalogue": {"source": catalogue.source, "version": catalogue.version},
        "entity": {
            "name": assessment.entity.name,
            "sector": assessment.entity.sector,
            "employees": assessment.entity.employees,
        },
        "assessed_on": assessment.assessed_on,
        "assessor": assessment.assessor,
        "applicability": {
            "label": a.label,
            "size": a.size,
            "annex": a.annex,
            "in_scope": a.in_scope,
            "classification": a.classification,
            "notes": a.notes,
        },
        "weighting": {
            "mode": result.weighting,
            "rank_by": result.rank_by,
            "threat_data": (threat.version_label if threat and result.weighting == "threat" else None),
        },
        "summary": {
            "score_pct": result.score_pct,
            "evidence_backed_pct": result.verified_pct,
            "maturity": result.maturity,
            "counts": result.counts,
        },
        "domains": [
            {
                "id": d.domain.id,
                "article": d.domain.article,
                "title": d.domain.title,
                "score_pct": d.score_pct,
                "evidence_backed_pct": d.verified_pct,
                "maturity": d.maturity,
                "rag": rag(d.score_pct),
                "counts": d.counts,
            }
            for d in result.domains
        ],
        "gaps": [
            {
                "id": f.question.id,
                "article": f.question.article or _domain_article(result, f.question.domain_id),
                "question": f.question.text,
                "priority": f.question.priority,
                "status": f.status,
                "priority_score": f.priority_score,
                "weight": f.weight,
                "effort": f.question.effort,
                "risk_reduction_per_effort": f.value,
                "quadrant": quadrant(f, gaps_median),
                "rationale": f.weight_info.rationale(threat) if f.weight_info else None,
                "remediation": f.question.remediation,
            }
            for f in gaps
        ],
        "evidence_issues": [
            {"id": f.question.id, "issues": f.evidence_issues} for f in result.evidence_issues
        ],
    }


def render_json(result: Result, assessment: Assessment, catalogue: Catalogue, threat=None) -> str:
    return json.dumps(to_dict(result, assessment, catalogue, threat), indent=2, ensure_ascii=False)


def render_summary(result: Result, assessment: Assessment, top: int = 5) -> str:
    c = result.counts
    name = assessment.entity.name or "Unnamed organisation"
    lines = [
        f"{framework_label(_framework_ids(result))} gap report: {name}",
        f"Scope:          {result.applicability.label}",
        f"Score:          {_pct(result.score_pct)} ({result.maturity})",
        f"Evidence-backed:{_pct(result.verified_pct):>5}",
        f"Controls:       {c['met']} met, {c['partial']} partial, {c['gap']} gaps, "
        f"{c['unanswered']} unanswered, {c['na']} n/a",
        "",
        "Domains:",
    ]
    for d in result.domains:
        lines.append(f"  {d.domain.id:<5} {d.domain.article:<15} {_pct(d.score_pct):>5}  {d.domain.title}")
    if result.gaps:
        lines += ["", f"Top {min(top, len(result.gaps))} gaps:"]
        for f in result.gaps[:top]:
            lines.append(f"  [{f.question.priority:<8}] {f.question.id}: {f.question.text}")
    if result.evidence_issues:
        lines += ["", f"Evidence issues: {len(result.evidence_issues)} answers lack usable evidence"]
    return "\n".join(lines)
