"""Country files: validation, and a national ref for every citation the app already uses."""

from pathlib import Path

import pytest
import yaml

from nis2check.controls import load_catalogue
from nis2check.jurisdictions import (
    JurisdictionError,
    cited_articles,
    get_jurisdiction,
    load_jurisdiction,
    parse_jurisdiction,
    with_national,
)

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "nis2check" / "data" / "jurisdictions"


def test_eu_has_no_overlay_and_unknown_codes_are_ignored():
    catalogue = load_catalogue()
    assert get_jurisdiction("eu") is None
    assert get_jurisdiction(None) is None
    assert get_jurisdiction("de") is None
    assert with_national(catalogue, None) is catalogue
    assert with_national(catalogue, get_jurisdiction("EU")) is catalogue


def test_cited_articles_are_mapped_for_every_country():
    cited = cited_articles()
    assert "Art. 20" in cited
    assert "Art. 21(2)(a)" in cited
    assert "Art. 23" in cited
    assert "Art. 2(1)" not in cited  # that string is built by the scope engine, not stored as a citation
    for code in ("sk", "cz", "hu", "pl"):
        jurisdiction = load_jurisdiction(code)
        missing = cited - set(jurisdiction.article_map)
        assert not missing, f"{code} is missing {sorted(missing)}"
        assert "Art. 2" in jurisdiction.article_map
        assert "Art. 3" in jurisdiction.article_map
        for article, ref in jurisdiction.article_map.items():
            assert ref.source_url, article


def test_unknown_article_key_fails(tmp_path):
    data = yaml.safe_load((DATA / "sk.yaml").read_text(encoding="utf-8"))
    data["article_map"]["Art. 99"] = {
        "ref": "§ 1",
        "title": "Nope",
        "source_url": "https://example.invalid",
        "verified": False,
    }
    with pytest.raises(JurisdictionError, match="unknown article key"):
        parse_jurisdiction(data, "sk")


def test_duplicate_question_id_and_missing_source_fail():
    data = yaml.safe_load((DATA / "cz.yaml").read_text(encoding="utf-8"))
    data["national_extras"].append(dict(data["national_extras"][0]))
    with pytest.raises(JurisdictionError, match="duplicate question id"):
        parse_jurisdiction(data, "cz")

    data = yaml.safe_load((DATA / "cz.yaml").read_text(encoding="utf-8"))
    data["article_map"]["Art. 20"].pop("source_url")
    with pytest.raises(JurisdictionError, match="source_url"):
        parse_jurisdiction(data, "cz")


def test_deadlines_and_sector_authorities_load():
    poland = load_jurisdiction("pl")
    dated = [item for item in poland.deadlines if item.date is not None]
    assert any(item.date.isoformat() == "2027-04-03" for item in dated)
    assert "energy" in poland.sector_authorities
    assert poland.sector_authorities["energy"].authority == ""
    assert any(note.status == "under_review" and note.scored is False for note in poland.notices)

    data = yaml.safe_load((DATA / "pl.yaml").read_text(encoding="utf-8"))
    data["sector_authorities"]["not_a_sector"] = {"authority": "X", "csirt": "Y"}
    with pytest.raises(JurisdictionError, match="unknown sector"):
        parse_jurisdiction(data, "pl")


def test_hungary_and_poland_citations_are_unverified():
    for code in ("hu", "pl"):
        jurisdiction = load_jurisdiction(code)
        assert all(ref.verified is False for ref in jurisdiction.article_map.values())
        assert all(question.verified is False for question in jurisdiction.extras)


def test_slovakia_keeps_verified_paragraphs_it_confirmed():
    slovakia = load_jurisdiction("sk")
    reporting = slovakia.article("Art. 23")
    assert reporting is not None
    assert reporting.verified is True
    assert reporting.ref.startswith("§ 24")
    assert slovakia.clocks.further_days == 30
    assert slovakia.clocks.verified is True
    hygiene = slovakia.article("Art. 21(2)(g)")
    assert hygiene.ref == "§ 20 ods. 4 písm. i)"
    assert hygiene.verified is True
    assert "no explicit cyber hygiene" in hygiene.note
    governance = slovakia.article("Art. 20")
    assert governance.ref == "§ 20 ods. 4 písm. h)"
    assert "§ 19" not in governance.ref
    czechia = load_jurisdiction("cz")
    assert czechia.law.number.startswith("264/2025")
    verified = sorted(key for key, ref in czechia.article_map.items() if ref.verified)
    assert verified == ["Art. 21(2)(c)", "Art. 23"]
    continuity = czechia.article("Art. 21(2)(c)")
    assert continuity.ref == "§ 14 odst. 1 písm. a) bod 13"
    assert "continuity only" in continuity.note
    reporting_cz = czechia.article("Art. 23")
    assert reporting_cz.ref == "§ 15 a § 16"
    assert reporting_cz.verified is True


def test_national_domain_is_appended_once():
    catalogue = load_catalogue()
    slovakia = get_jurisdiction("sk")
    extended = with_national(catalogue, slovakia)
    assert extended.domain("NAT-SK").title == "National requirements (SK)"
    assert extended.question_ids[: len(catalogue.question_ids)] == catalogue.question_ids
    assert "sk-reg-01" in extended.question_ids
    again = with_national(extended, slovakia)
    assert again is extended
