"""Working self-assessment a Slovak operator can use when preparing an NBU filing.

This is not the official form and it does not submit anything to the authority.
"""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, select_autoescape

from .assessment import Assessment
from .controls import Catalogue
from .jurisdictions import Jurisdiction, question_text
from .report import NOT_LEGAL_ADVICE, STATUS_LABELS
from .scoring import Result


def render_sk_self_assessment(
    result: Result, assessment: Assessment, catalogue: Catalogue, jurisdiction: Jurisdiction,
) -> str:
    env = Environment(
        loader=PackageLoader("nis2check", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    rows = []
    for domain in result.domains:
        entry = jurisdiction.article(domain.domain.article)
        domain_note = entry.note if entry else ""
        first = True
        for finding in domain.findings:
            response = assessment.responses.get(finding.question.id)
            rows.append({
                "domain_note": domain_note if first else "",
                "domain": domain.domain.title,
                "id": finding.question.id,
                "article": finding.question.article or domain.domain.article,
                "text": question_text(finding.question, "sk"),
                "text_en": question_text(finding.question, "en"),
                "status": STATUS_LABELS.get(finding.status, finding.status),
                "remediation": finding.question.remediation,
                "due": response.remediation_due if response else "",
                "notes": response.notes if response else "",
                "gap": finding.status in ("gap", "partial", "unanswered"),
            })
            first = False
    gaps = [row for row in rows if row["gap"]]
    return env.get_template("self_assessment_sk.html.j2").render(
        assessment=assessment,
        result=result,
        law=jurisdiction.law,
        rows=rows,
        gaps=gaps,
        not_legal_advice=NOT_LEGAL_ADVICE,
    )
