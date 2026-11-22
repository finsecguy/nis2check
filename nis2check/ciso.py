"""Export an assessment in the formats CISO Assistant imports.

CISO Assistant (intuitem/ciso-assistant-community) loads a framework from a
library YAML, then imports an audit from a CSV. The community app loads the
YAML in the library screen. The community CLI imports the CSV with
``import-compliance-assessments``; the same file is the Pro data-wizard
template. Both files use ref_ids from this assessment, so they do not fill
an audit that was opened on intuitem's own DORA or NIS2 library.

The CSV columns are the ones ``_reconcile_compliance_requirements`` reads:
``ref_id`` (matched first), ``urn``, ``assessable``, ``compliance_result``,
``score``, ``requirement_progress`` and ``observations``. A non-empty
``assessable`` cell is required or the row is skipped. An empty ``score``
leaves the requirement unscored, which is what we want for "not assessed"
and "not applicable".
"""

from __future__ import annotations

import csv
import io
import zipfile
import yaml

from .assessment import Assessment
from .controls import Catalogue, CatalogueError
from .scoring import Finding, Result

# Names are what `clica import-compliance-assessments --framework` matches.
FRAMEWORK_NAMES = {
    "nis2": "NIS2 (nis2check gap assessment)",
    "dora": "DORA (nis2check gap assessment)",
}

_IMPORTANCE = {"critical": "mandatory", "high": "recommended", "medium": "nice_to_have"}

# answer -> (compliance_result, score, requirement_progress)
# score "" is left blank so CISO Assistant does not treat it as zero.
_RESULTS = {
    "yes": ("compliant", "100", "done"),
    "partial": ("partially_compliant", "50", "in_progress"),
    "no": ("non_compliant", "0", "to_do"),
    "na": ("not_applicable", "", "done"),
    None: ("not_assessed", "", "to_do"),
}

_CSV_COLUMNS = (
    "urn",
    "assessable",
    "ref_id",
    "name",
    "description",
    "compliance_result",
    "requirement_progress",
    "score",
    "observations",
)

_PUBLISHED = "2022-12-14"  # date of both Directive (EU) 2022/2555 and Regulation (EU) 2022/2554


def framework_ref(framework_id: str) -> str:
    return f"nis2check-{framework_id}"


def _urn_node(framework_id: str, ref: str) -> str:
    safe = ref.strip().lower().replace(" ", "-")
    return f"urn:intuitem:risk:req_node:{framework_ref(framework_id)}:{safe}"


def _framework_meta(framework_id: str, catalogue: Catalogue) -> tuple[str, str]:
    """Source line and catalogue version of one framework.

    Bundled NIS2 and DORA keep their own source even when the assessment
    catalogue is the merged one. A custom catalogue falls back to itself.
    """
    try:
        from .frameworks import bundled
        cat = bundled(framework_id)
    except CatalogueError:
        cat = catalogue
    return cat.source, cat.version


def library_document(catalogue: Catalogue, framework_id: str) -> dict:
    """One CISO Assistant library containing a single framework."""
    domains = [d for d in catalogue.domains if d.framework == framework_id]
    if not domains:
        raise ValueError(f"no {framework_id} questions in this catalogue")
    ref = framework_ref(framework_id)
    name = FRAMEWORK_NAMES.get(framework_id, framework_id)
    source, version = _framework_meta(framework_id, catalogue)
    nodes: list[dict] = []
    for domain in domains:
        parent = _urn_node(framework_id, domain.id)
        nodes.append({
            "urn": parent,
            "assessable": False,
            "depth": 1,
            "ref_id": domain.id,
            "name": domain.title,
            "description": f"{domain.article}. {domain.summary}".strip(),
        })
        for question in domain.questions:
            article = question.article or domain.article
            nodes.append({
                "urn": _urn_node(framework_id, question.id),
                "assessable": True,
                "depth": 2,
                "parent_urn": parent,
                "ref_id": question.id,
                "name": question.text,
                "description": f"{article}. Suggested evidence: {question.evidence_hint}".strip(),
                "annotation": question.remediation,
                "typical_evidence": question.evidence_hint,
                "importance": _IMPORTANCE[question.priority],
                "weight": question.weight,
            })
    return {
        "urn": f"urn:intuitem:risk:library:{ref}",
        "locale": "en",
        "ref_id": ref,
        "name": name,
        "description": (
            f"{source}. Question set and weights are nis2check's own gap assessment "
            f"(catalogue v{version}). This is not the DORA or NIS2 library "
            "shipped by intuitem, and its ref_ids will not match an audit opened on those libraries."
        ),
        "copyright": "Question text is original to nis2check (MIT). Article numbers identify the duty; they are not a copy of the legislation.",
        "version": 1,
        "publication_date": _PUBLISHED,
        "provider": "European Union",
        "packager": "nis2check",
        "objects": {
            "framework": {
                "urn": f"urn:intuitem:risk:framework:{ref}",
                "ref_id": ref,
                "name": name,
                "description": source or name,
                "min_score": 0,
                "max_score": 100,
                "scores_definition": [
                    {"score": 0, "name": "Not in place", "description": "The measure is missing."},
                    {"score": 50, "name": "Partial", "description": "The measure is partly in place."},
                    {"score": 100, "name": "In place", "description": "The measure is in place."},
                ],
                "requirement_nodes": nodes,
            }
        },
    }


def render_library_yaml(catalogue: Catalogue, framework_id: str) -> str:
    return yaml.safe_dump(
        library_document(catalogue, framework_id),
        sort_keys=False,
        allow_unicode=True,
        width=100,
    )


def _observations(finding: Finding) -> str:
    parts = []
    if finding.response.notes:
        parts.append(finding.response.notes)
    if finding.response.evidence:
        parts.append("Evidence: " + "; ".join(finding.response.evidence))
    if finding.evidence_issues:
        parts.append("Evidence issue: " + "; ".join(finding.evidence_issues))
    return "\n".join(parts)


def assessment_rows(result: Result, framework_id: str) -> list[dict]:
    rows = []
    for domain_result in result.domains:
        domain = domain_result.domain
        if domain.framework != framework_id:
            continue
        for finding in domain_result.findings:
            result_name, score, progress = _RESULTS[finding.response.answer]
            rows.append({
                "urn": _urn_node(framework_id, finding.question.id),
                "assessable": "x",
                "ref_id": finding.question.id,
                "name": finding.question.text,
                "description": finding.question.article or domain.article,
                "compliance_result": result_name,
                "requirement_progress": progress,
                "score": score,
                "observations": _observations(finding),
            })
    return rows


def render_assessment_csv(result: Result, framework_id: str) -> str:
    """UTF-8 without a BOM: a BOM would stick to the first header and break the match."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(assessment_rows(result, framework_id))
    return buf.getvalue()


def selected_frameworks(result: Result) -> tuple[str, ...]:
    ids: list[str] = []
    for domain_result in result.domains:
        fw = domain_result.domain.framework
        if fw not in ids:
            ids.append(fw)
    return tuple(ids)


def import_instructions(frameworks: tuple[str, ...]) -> str:
    lines = [
        "CISO Assistant import",
        "",
        "These files are nis2check's question set and this assessment's answers.",
        "They are not the DORA or NIS2 libraries shipped by intuitem. Loading them",
        "does not fill an audit that was opened on those libraries, because the",
        "requirement ids are different.",
        "",
        "1. In CISO Assistant, load each library YAML (Catalog, Libraries).",
        "2. Import the matching compliance-assessment CSV.",
        "   Community edition: the clica CLI, from the cli/ directory of",
        "   intuitem/ciso-assistant-community, once a folder and a perimeter exist.",
        "   Pro: the same CSV in the data import wizard.",
        "",
        "   uv run clica.py import-compliance-assessments \\",
        "     --file <framework>-compliance-assessment.csv \\",
        "     --framework \"<framework name below>\" \\",
        "     --perimeter \"Your perimeter\"",
        "",
        "Framework name to pass to --framework:",
    ]
    for fw in frameworks:
        lines.append(f"  {fw}: {FRAMEWORK_NAMES.get(fw, fw)}")
    lines += [
        "",
        "Answer mapping: yes = compliant and score 100, partial = partially_compliant",
        "and score 50, no = non_compliant and score 0, na = not_applicable (no score),",
        "unanswered = not_assessed (no score).",
        "",
        "CISO Assistant averages the requirement scores in its own way. nis2check's",
        "headline figure is a weighted average and can differ.",
        "",
    ]
    return "\n".join(lines)


def export_zip(result: Result, catalogue: Catalogue, assessment: Assessment | None = None) -> bytes:
    """Library YAML plus a compliance-assessment CSV for each selected framework."""
    del assessment  # the result already carries the answers and the selected domains
    frameworks = selected_frameworks(result)
    if not frameworks:
        raise ValueError("this assessment has no frameworks to export")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("IMPORT.txt", import_instructions(frameworks))
        for fw in frameworks:
            archive.writestr(f"{fw}-library.yaml", render_library_yaml(catalogue, fw))
            archive.writestr(f"{fw}-compliance-assessment.csv", render_assessment_csv(result, fw))
    return buf.getvalue()
