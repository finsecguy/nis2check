import datetime as dt
import json
from pathlib import Path

import pytest
import yaml

from nis2check.cli import main
from nis2check.controls import load_catalogue
from nis2check.threat import compute, sources
from nis2check.threat.data import ThreatData, load_threat_data
from nis2check.threat.patterns import load_patterns
from nis2check.threat.update import change_report, collect
from nis2check.weighting import MAX_UPLIFT, compute_weights

FIX = Path(__file__).resolve().parent / "fixtures" / "threat"
TODAY = dt.date(2026, 11, 15)
PATTERNS = load_patterns()
CATALOGUE = load_catalogue()


@pytest.fixture
def records():
    return json.loads((FIX / "vcdb.json").read_text())


# ------------------------------------------------------------ VCDB

def test_collapse_campaigns(records):
    counted = [r for r in records if r["security_incident"] in compute.COUNTED_STATUSES]
    events, collapsed = compute.collapse_campaigns(counted)
    labels = {c["label"]: c["records"] for c in collapsed}
    assert labels["campaign CAMP-1"] == 3
    assert any("Mass exploitation" in k and v == 6 for k, v in labels.items())
    # short generic summaries ("DoS attack") are distinct incidents and are not collapsed
    assert sum(1 for e in events if e["summary"] == "DoS attack") == 6


def test_vcdb_prevalence(records):
    v = compute.vcdb_prevalence(records, PATTERNS, TODAY, window_years=5, min_sample=3)
    assert v["window"] == {"from_year": 2022, "to_year": 2026}
    assert v["sample_size"] == 13  # near miss excluded, campaigns counted once
    p = v["patterns"]
    assert p["credential_abuse"]["count"] == 2
    assert p["vuln_exploitation"]["count"] == 1
    assert p["denial_of_service"]["count"] == 6
    assert p["supply_chain"]["count"] == 1
    assert p["ransomware"]["share"] == round(1 / 13, 4)


def test_window_widens_until_min_sample(records):
    v = compute.vcdb_prevalence(records, PATTERNS, TODAY, 5, min_sample=14, max_years=15)
    assert v["window"]["from_year"] == 2012
    assert v["sample_size"] == 14
    assert not v["below_min_sample"]

    capped = compute.vcdb_prevalence(records, PATTERNS, TODAY, 5, min_sample=14, max_years=10)
    assert capped["below_min_sample"]


# ------------------------------------------------------------ ATT&CK

def test_attack_links_include_subtechniques_and_skip_revoked():
    bundle = json.loads((FIX / "enterprise-attack.json").read_text())
    links = compute.attack_links(bundle, PATTERNS)["links"]
    assert links["ransomware"] == ["M1053"]          # revoked M1051 -> T1486 ignored
    assert links["phishing"] == ["M1017"]            # via sub-technique T1566.001
    assert links["credential_abuse"] == ["M1032"]
    assert links["vuln_exploitation"] == ["M1051"]   # deprecated M1099 ignored
    assert links["error"] == []


# ------------------------------------------------------------ trend

def test_kev_indicator():
    kev = json.loads((FIX / "kev.json").read_text())
    ind = compute.kev_indicator(kev, TODAY)
    assert (ind["current"], ind["previous"]) == (5, 4)
    assert ind["ratio"] == 1.25
    assert ind["ransomware_share"] == 0.4


@pytest.mark.parametrize("ratios, expected", [
    ([1.0], 1.0), ([2.0], 1.25), ([0.5], 0.8), ([1.1, 0.9], 1.0), ([], 1.0),
])
def test_trend_factor_is_clamped(ratios, expected):
    assert compute.trend_factor(*[{"ratio": r} for r in ratios]) == expected


def test_trend_factor_ignores_missing_sources():
    assert compute.trend_factor(None, {"ratio": 1.1}) == 1.1


# ------------------------------------------------------------ collect / sources

def test_collect_from_source_dir():
    data, warnings = collect(TODAY, FIX, window_years=5, min_sample=3)
    assert warnings == []
    assert data["exploitation_trend"]["factor"] == 1.25  # avg(1.25, 1.5) clamped
    vuln = data["patterns"]["vuln_exploitation"]
    assert vuln["adjusted_prevalence"] == round(vuln["prevalence"] * 1.25, 4)
    assert data["patterns"]["ransomware"]["adjusted_prevalence"] == data["patterns"]["ransomware"]["prevalence"]
    assert data["sources"]["mitre_attack"]["version"] == "99.0"
    assert data["sources"]["cisa_kev"]["version"] == "2026.11.14"
    assert all(s["status"] == "ok" for s in data["sources"].values())


def test_optional_sources_can_fail(tmp_path):
    for name in ("vcdb.json", "enterprise-attack.json"):
        (tmp_path / name).write_text((FIX / name).read_text())
    data, warnings = collect(TODAY, tmp_path, min_sample=3)
    assert len(warnings) == 2
    assert data["exploitation_trend"]["factor"] == 1.0
    assert data["sources"]["cisa_kev"]["status"] == "unavailable"


def test_required_source_failure_raises(tmp_path):
    with pytest.raises(sources.SourceError):
        collect(TODAY, tmp_path)


# ------------------------------------------------------------ weighting

def test_static_weights_are_the_baseline():
    w = compute_weights(CATALOGUE, None, "static")
    assert all(w[q.id].weight == q.weight for q in CATALOGUE.questions())


def test_threat_weights_never_below_baseline_and_capped():
    w = compute_weights(CATALOGUE, load_threat_data(), "threat")
    for q in CATALOGUE.questions():
        assert q.weight <= w[q.id].weight <= round(q.weight * (1 + MAX_UPLIFT), 2)
    assert max(x.multiplier for x in w.values()) == pytest.approx(1 + MAX_UPLIFT)


def test_controls_without_threat_links_keep_baseline():
    w = compute_weights(CATALOGUE, load_threat_data(), "threat")
    assert w["GOV-01"].patterns == []
    assert w["GOV-01"].weight == 3


def test_mfa_linked_through_attack():
    w = compute_weights(CATALOGUE, load_threat_data(), "threat")["MFA-01"]
    assert "credential_abuse" in w.patterns
    assert w.via["credential_abuse"] == "ATT&CK M1032"
    assert "M1032" in w.rationale(load_threat_data())


def test_bundled_catalogue_mitigations_exist_in_threat_data():
    known = set(load_threat_data().raw["attack_mitigation_names"])
    used = {m for q in CATALOGUE.questions() for m in q.attack_mitigations}
    assert used <= known, used - known


# ------------------------------------------------------------ change report and CLI

def test_change_report_flags_large_moves():
    data, _ = collect(TODAY, FIX, min_sample=3)
    new = ThreatData(data, "new")
    old_raw = json.loads(json.dumps(data))
    old_raw["patterns"]["denial_of_service"]["adjusted_prevalence"] = 0.0
    report, changed = change_report(CATALOGUE, ThreatData(old_raw, "old"), new, [])
    assert changed
    assert "FLAG" in report
    assert "Denial of service" in report

    same, changed = change_report(CATALOGUE, new, new, [])
    assert not changed
    assert "No control weights changed." in same


def test_update_threat_data_cli(tmp_path):
    out, md = tmp_path / "threat.yaml", tmp_path / "change.md"
    args = ["update-threat-data", "-o", str(out), "--source-dir", str(FIX),
            "--change-report", str(md), "--min-sample", "3", "--date", "2026-11-15"]
    assert main(args) == 0
    data = yaml.safe_load(out.read_text())
    assert data["generated"] == "2026-11-15"
    assert "## Threat data update" in md.read_text()

    before = out.read_text()
    assert main(args) == 0  # no changes on a second run
    assert out.read_text() == before


def test_report_uses_custom_threat_data(tmp_path):
    out = tmp_path / "threat.yaml"
    main(["update-threat-data", "-o", str(out), "--source-dir", str(FIX), "--min-sample", "3",
          "--date", "2026-11-15"])
    example = Path(__file__).resolve().parent.parent / "examples" / "acme-assessment.yaml"
    js = tmp_path / "r.json"
    assert main(["report", str(example), "-o", str(tmp_path / "r.html"), "--threat-data", str(out),
                 "--json", str(js), "-q"]) == 0
    weighting = json.loads(js.read_text())["weighting"]
    assert weighting["mode"] == "threat"
    assert "2026-11-15" in weighting["threat_data"]


def test_rank_by_value_prefers_low_effort(tmp_path):
    example = Path(__file__).resolve().parent.parent / "examples" / "acme-assessment.yaml"
    js = tmp_path / "r.json"
    main(["report", str(example), "-o", str(tmp_path / "r.html"), "--rank-by", "value", "--json", str(js), "-q"])
    gaps = json.loads(js.read_text())["gaps"]
    values = [g["risk_reduction_per_effort"] for g in gaps]
    assert values == sorted(values, reverse=True)
