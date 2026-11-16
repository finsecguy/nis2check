from pathlib import Path

import pytest

from nis2check.assessment import AssessmentError, parse_assessment
from nis2check.controls import CatalogueError, load_catalogue, parse_catalogue
from nis2check.scoring import evaluate, maturity

CATALOGUE = load_catalogue()


def make(responses: dict, tmp_path: Path, entity: dict | None = None):
    data = {"entity": entity or {"name": "T"}, "responses": responses}
    return evaluate(CATALOGUE, parse_assessment(data, CATALOGUE, tmp_path))


def all_answered(value: str, evidence: list[str] | None = None) -> dict:
    return {
        qid: {"answer": value, "evidence": evidence or []} for qid in CATALOGUE.question_ids
    }


def test_bundled_catalogue_covers_all_article_21_measures():
    articles = {d.article for d in CATALOGUE.domains}
    for letter in "abcdefghij":
        assert f"Art. 21(2)({letter})" in articles
    assert {"Art. 20", "Art. 23"} <= articles


def test_question_ids_are_unique():
    ids = CATALOGUE.question_ids
    assert len(ids) == len(set(ids))


def test_empty_assessment_scores_zero(tmp_path):
    result = make({}, tmp_path)
    assert result.score_pct == 0
    assert result.counts["unanswered"] == len(CATALOGUE.question_ids)


def test_all_yes_with_url_evidence_scores_100(tmp_path):
    result = make(all_answered("yes", ["https://example.com/doc"]), tmp_path)
    assert result.score_pct == 100
    assert result.verified_pct == 100
    assert result.maturity == "Strong"
    assert result.gaps == []


def test_yes_without_evidence_lowers_evidence_backed_score(tmp_path):
    result = make(all_answered("yes"), tmp_path)
    assert result.score_pct == 100
    assert result.verified_pct == 0
    assert len(result.evidence_issues) == len(CATALOGUE.question_ids)


def test_partial_counts_half(tmp_path):
    result = make(all_answered("partial", ["https://x.test"]), tmp_path)
    assert result.score_pct == 50


def test_bare_no_shorthand_is_a_gap(tmp_path):
    # YAML turns a bare `no` into the boolean False; it must read as a gap, not unanswered
    qid = CATALOGUE.question_ids[0]
    a = parse_assessment({"responses": {qid: False}}, CATALOGUE, tmp_path)
    assert a.responses[qid].answer == "no"
    b = parse_assessment({"responses": {qid: True}}, CATALOGUE, tmp_path)
    assert b.responses[qid].answer == "yes"
    result = make({qid: False}, tmp_path)
    assert result.counts["gap"] == 1 and result.counts["unanswered"] == len(CATALOGUE.question_ids) - 1


def test_na_is_excluded_from_score(tmp_path):
    responses = all_answered("na")
    responses["GOV-01"] = {"answer": "yes", "evidence": ["https://x.test"]}
    result = make(responses, tmp_path)
    assert result.score_pct == 100
    assert result.domains[0].score_pct == 100
    assert result.domains[1].score_pct is None


def test_existing_and_missing_evidence_files(tmp_path):
    (tmp_path / "policy.md").write_text("ok")
    result = make(
        {
            "RISK-01": {"answer": "yes", "evidence": ["policy.md"]},
            "RISK-02": {"answer": "yes", "evidence": ["missing.pdf"]},
        },
        tmp_path,
    )
    by_id = {f.question.id: f for f in result.findings}
    assert by_id["RISK-01"].evidence_issues == []
    assert by_id["RISK-02"].evidence_issues == ["Evidence file not found: missing.pdf"]


def test_gaps_sorted_by_priority(tmp_path):
    responses = {
        "EFF-02": {"answer": "no"},  # medium -> 1
        "MFA-02": {"answer": "no"},  # critical -> 3
        "HYG-01": {"answer": "partial", "evidence": ["https://x"]},  # high partial -> 1
    }
    gaps = make(responses, tmp_path).gaps
    assert gaps[0].question.priority == "critical"
    assert gaps[0].priority_score == 3


def test_yaml_booleans_are_accepted(tmp_path):
    result = make({"GOV-01": {"answer": True}, "GOV-02": {"answer": False}}, tmp_path)
    statuses = {f.question.id: f.status for f in result.findings}
    assert statuses["GOV-01"] == "met"
    assert statuses["GOV-02"] == "gap"


def test_invalid_answer_rejected(tmp_path):
    with pytest.raises(AssessmentError):
        make({"GOV-01": {"answer": "maybe"}}, tmp_path)


def test_unknown_question_rejected(tmp_path):
    with pytest.raises(AssessmentError):
        make({"XYZ-99": {"answer": "yes"}}, tmp_path)


def test_bad_catalogue_rejected():
    with pytest.raises(CatalogueError):
        parse_catalogue({"domains": [{"id": "A", "article": "x", "title": "t",
                                      "questions": [{"id": "A-1", "text": "q", "priority": "urgent"}]}]})


@pytest.mark.parametrize("pct, label", [(95, "Strong"), (70, "Substantial"), (40, "Partial"), (10, "Low"), (None, "Not assessed")])
def test_maturity_bands(pct, label):
    assert maturity(pct) == label
