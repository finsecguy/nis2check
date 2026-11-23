"""Evidence stored next to a legal claim has to be present and non-empty."""

import csv
from pathlib import Path

from nis2check.controls import load_catalogue
from nis2check.frameworks import bundled
from nis2check.scope import load_scope_rules

ROOT = Path(__file__).resolve().parent.parent
CLAIMS = ROOT / "docs" / "verification" / "claims.csv"


def test_bundled_directives_carry_a_quote_when_verified():
    for catalogue in (load_catalogue(), bundled("dora")):
        for domain in catalogue.domains:
            assert domain.verified is True, domain.id
            assert domain.evidence_quote and domain.checked_against
            for question in domain.questions:
                assert question.verified is True, question.id
                assert question.evidence_quote and question.checked_against


def test_scope_rules_carry_a_quote_when_verified():
    rules = load_scope_rules()
    assert rules.size_verified is True
    assert rules.size_evidence_quote and rules.size_checked_against
    for case in rules.special_cases:
        assert case.verified is True and case.evidence_quote and case.checked_against
    for sector in rules.sectors:
        assert sector.verified is True and sector.evidence_quote
        for sub in sector.subsectors:
            assert sub.verified is True and sub.evidence_quote and sub.checked_against


def test_verified_claim_rows_have_a_quote_and_a_source_url():
    with CLAIMS.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows, "claims.csv has no rows"
    for row in rows:
        if row["status"] == "verified":
            assert row["evidence_quote"].strip(), row["id"]
            assert row["source_url"].strip(), row["id"]
        assert row["status"] in {"verified", "corrected", "removed", "blocked"}
