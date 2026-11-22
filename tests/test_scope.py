"""Scope wizard: thresholds and Annex lists from data/scope.yaml.

The titles and ceilings are checked against Directive (EU) 2022/2555
(OJ L 333, 27.12.2022, p. 80) and Recommendation 2003/361/EC
(OJ L 124, 20.5.2003, p. 36).
"""

import pytest

from nis2check.scope import (
    assess_scope, cached_scope_rules, enterprise_size, load_scope_rules, scope_for_organisation,
)

# Annex headings, in the order printed in the directive.
ANNEX_I = [
    "Energy",
    "Transport",
    "Banking",
    "Financial market infrastructures",
    "Health",
    "Drinking water",
    "Waste water",
    "Digital infrastructure",
    "ICT service management (business-to-business)",
    "Public administration",
    "Space",
]
ANNEX_II = [
    "Postal and courier services",
    "Waste management",
    "Manufacture, production and distribution of chemicals",
    "Production, processing and distribution of food",
    "Manufacturing",
    "Digital providers",
    "Research",
]
# Subsector and type-of-entity names that the annex uses as the second column
# or, where a sector has no subsector, the type of entity.
NAMED_IN_ANNEX = [
    "Electricity",
    "District heating and cooling",
    "Oil",
    "Gas",
    "Hydrogen",
    "Air",
    "Rail",
    "Water",
    "Road",
    "DNS service providers, excluding operators of root name servers",
    "TLD name registries",
    "Cloud computing service providers",
    "Data centre service providers",
    "Content delivery network providers",
    "Trust service providers",
    "Providers of public electronic communications networks",
    "Providers of publicly available electronic communications services",
    "Managed service providers",
    "Managed security service providers",
    "Manufacture of medical devices and in vitro diagnostic medical devices",
    "Manufacture of computer, electronic and optical products",
    "Manufacture of electrical equipment",
    "Manufacture of machinery and equipment n.e.c.",
    "Manufacture of motor vehicles, trailers and semi-trailers",
    "Manufacture of other transport equipment",
    "Providers of online marketplaces",
    "Providers of online search engines",
    "Providers of social networking services platforms",
]


def test_rules_match_the_directive_annexes_and_the_recommendation():
    rules = load_scope_rules()
    assert [s.title for s in rules.sectors if s.annex == "I"] == ANNEX_I
    assert [s.title for s in rules.sectors if s.annex == "II"] == ANNEX_II
    titles = {sub.title for sector in rules.sectors for sub in sector.subsectors}
    missing = [name for name in NAMED_IN_ANNEX if name not in titles]
    assert missing == []
    assert rules.size["medium"] == {
        "employees_at_least": 50,
        "turnover_eur_above": 10_000_000,
        "balance_sheet_eur_above": 10_000_000,
    }
    assert rules.size["large"] == {
        "employees_at_least": 250,
        "turnover_eur_above": 50_000_000,
        "balance_sheet_eur_above": 43_000_000,
    }
    assert "not legal advice" in rules.disclaimer.lower()
    assert "national transposition" in rules.disclaimer.lower()


@pytest.mark.parametrize(
    "employees, turnover, balance, expected",
    [
        (None, None, None, "unknown"),
        (None, 60_000_000, None, "unknown"),  # one financial figure is not enough
        (9, 2_000_000, 2_000_000, "micro"),  # "not exceeding" EUR 2 million
        (9, 2_000_000.01, 2_000_000.01, "small"),
        (49, 10_000_000, 10_000_000, "small"),  # both ceilings, not above them
        (49, 10_000_000.01, 10_000_000, "small"),  # both must be above
        (20, 12_000_000, 5_000_000, "small"),
        (49, 10_000_000.01, 10_000_000.01, "medium"),
        (50, 1, 1, "medium"),
        (249, 50_000_000, 43_000_000, "medium"),  # not exceeding the large ceilings
        (249, 60_000_000, 43_000_000, "medium"),  # balance sheet still at the ceiling
        (249, 50_000_000.01, 43_000_000.01, "large"),
        (250, 1, 1, "large"),
        (None, 60_000_000, 50_000_000, "large"),
        (100, 60_000_000, 40_000_000, "medium"),  # staff, not the financial pair
    ],
)
def test_size_boundaries(employees, turnover, balance, expected):
    assert enterprise_size(cached_scope_rules(), employees, turnover, balance) == expected


def test_large_annex_i_is_essential():
    result = assess_scope("electricity", employees=300)
    assert result.outcome == "essential"
    assert result.annex == "I"
    assert "Art. 3(1)(a)" in result.articles
    assert "Art. 2(1)" in result.articles


def test_medium_annex_i_is_important():
    result = assess_scope("air", employees=80)
    assert (result.outcome, result.annex) == ("important", "I")
    assert "Art. 3(2)" in result.articles


def test_large_annex_ii_stays_important():
    result = assess_scope("food_business", employees=1000)
    assert result.outcome == "important"
    assert result.annex == "II"


def test_below_medium_is_out_of_scope():
    result = assess_scope("healthcare_providers", employees=12)
    assert result.outcome == "out_of_scope"
    assert any("Art. 21(2)(d)" in reason.articles for reason in result.reasons)


def test_exact_medium_and_large_ceilings():
    at_medium = assess_scope("food_business", employees=49, annual_turnover_eur=10_000_000, balance_sheet_eur=10_000_000)
    over_medium = assess_scope("food_business", employees=49, annual_turnover_eur=10_000_000.01, balance_sheet_eur=10_000_000.01)
    at_large = assess_scope("electricity", employees=249, annual_turnover_eur=50_000_000, balance_sheet_eur=43_000_000)
    over_large = assess_scope("electricity", employees=249, annual_turnover_eur=50_000_000.01, balance_sheet_eur=43_000_000.01)
    assert at_medium.outcome == "out_of_scope"
    assert over_medium.outcome == "important"
    assert at_large.outcome == "important"
    assert over_large.outcome == "essential"


def test_missing_size_is_not_a_classification():
    result = assess_scope("electricity")
    assert result.outcome == "insufficient"


def test_no_sector_is_out_of_scope():
    result = assess_scope(employees=500)
    assert result.outcome == "out_of_scope"


@pytest.mark.parametrize("case", ["dns_provider", "tld_registry", "qualified_trust", "critical_entity"])
def test_essential_regardless_of_size(case):
    result = assess_scope(employees=3, special_case_ids=[case])
    assert result.outcome == "essential"
    assert result.size_exempt is True


def test_dns_subsector_implies_the_special_case():
    result = assess_scope("dns", employees=3)
    assert result.outcome == "essential"
    assert "Art. 3(1)(b)" in result.articles


def test_small_unqualified_trust_provider_is_important():
    result = assess_scope("trust_services", employees=4)
    assert result.outcome == "important"
    assert "Art. 3(1)(b)" in result.articles


def test_large_unqualified_trust_provider_is_essential_as_annex_i():
    result = assess_scope("trust_services", employees=400)
    assert result.outcome == "essential"
    assert "Art. 3(1)(a)" in result.articles


@pytest.mark.parametrize(
    "employees, outcome",
    [(3, "important"), (80, "essential"), (400, "essential"), (None, "insufficient")],
)
def test_public_electronic_communications_follows_size(employees, outcome):
    result = assess_scope(employees=employees, special_case_ids=["public_electronic_communications"])
    assert result.outcome == outcome


def test_sole_provider_needs_an_annex_type():
    bare = assess_scope(employees=3, special_case_ids=["sole_provider"])
    listed = assess_scope("food_business", employees=3, special_case_ids=["sole_provider"])
    assert bare.outcome == "out_of_scope"
    assert listed.outcome == "important"
    assert "Art. 2(2)(b)" in listed.articles


def test_public_administration_levels():
    central = assess_scope("central_government", employees=5)
    regional_small = assess_scope("regional_administration", employees=5)
    regional_large = assess_scope("regional_administration", employees=300)
    local = assess_scope(employees=5, special_case_ids=["public_admin_local"])
    assert central.outcome == "essential"
    assert "Art. 3(1)(d)" in central.articles
    assert regional_small.outcome == "important"
    assert regional_large.outcome == "essential"
    assert local.outcome == "out_of_scope"
    assert "Art. 2(5)(a)" in local.articles


def test_domain_registration_is_important_at_any_size():
    result = assess_scope(employees=2, special_case_ids=["domain_registration"])
    assert result.outcome == "important"
    assert "Art. 2(4)" in result.articles


def test_domain_registration_does_not_hide_a_large_annex_i_activity():
    result = assess_scope("electricity", employees=300, special_case_ids=["domain_registration"])
    assert result.outcome == "essential"


def test_organisation_record_uses_the_wizard_engine():
    rules = cached_scope_rules()
    medium_dns = scope_for_organisation("dns", 80, None, None, [], rules=rules)
    assert medium_dns.outcome == assess_scope("dns", employees=80, rules=rules).outcome == "essential"
    large_energy = scope_for_organisation(None, 300, None, None, [], sector="energy", rules=rules)
    assert large_energy.outcome == assess_scope("electricity", employees=300, rules=rules).outcome == "essential"
    # A coarse "digital infrastructure" sector is not assumed to be a DNS provider.
    plain = scope_for_organisation(None, 80, None, None, [], sector="digital_infrastructure", rules=rules)
    assert plain.outcome == assess_scope(employees=80, rules=rules).outcome == "out_of_scope"


def test_banking_mentions_dora():
    result = assess_scope("credit_institutions", employees=400)
    assert result.outcome == "essential"
    assert any("DORA" in reason.text for reason in result.reasons)
    assert "Art. 4" in result.articles
