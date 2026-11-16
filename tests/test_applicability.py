import pytest

from nis2check.applicability import Entity, assess_applicability, size_class


@pytest.mark.parametrize(
    "employees, turnover, balance, expected",
    [
        (10, None, None, "small"),
        (49, 5_000_000, 5_000_000, "small"),
        (50, None, None, "medium"),
        (20, 12_000_000, 11_000_000, "medium"),  # financial threshold alone
        (20, 12_000_000, 5_000_000, "small"),  # both financials must exceed
        (250, None, None, "large"),
        (100, 60_000_000, 50_000_000, "large"),
        (None, None, None, "unknown"),
    ],
)
def test_size_class(employees, turnover, balance, expected):
    assert size_class(employees, turnover, balance) == expected


def test_large_annex_i_is_essential():
    a = assess_applicability(Entity(sector="energy", employees=300))
    assert a.in_scope is True
    assert a.classification == "essential"


def test_medium_annex_i_is_important():
    a = assess_applicability(Entity(sector="transport", employees=85))
    assert (a.in_scope, a.classification, a.annex) == (True, "important", "I")


def test_annex_ii_is_important_even_when_large():
    a = assess_applicability(Entity(sector="food", employees=1000))
    assert a.classification == "important"


def test_small_is_out_of_scope_with_supply_chain_note():
    a = assess_applicability(Entity(sector="health", employees=12))
    assert a.in_scope is False
    assert any("supply chain" in n for n in a.notes)


def test_unlisted_sector_out_of_scope():
    a = assess_applicability(Entity(sector="other", employees=500))
    assert a.in_scope is False


def test_missing_sector_needs_review():
    a = assess_applicability(Entity(employees=500))
    assert a.in_scope is None
    assert a.label == "Needs review"


def test_public_administration_needs_review():
    assert assess_applicability(Entity(sector="public_administration", employees=5)).in_scope is None


def test_size_exempt_in_scope_when_small():
    a = assess_applicability(Entity(sector="digital_infrastructure", employees=3, size_exempt=True))
    assert a.in_scope is True


def test_banking_mentions_dora():
    a = assess_applicability(Entity(sector="banking", employees=400))
    assert any("DORA" in n for n in a.notes)
