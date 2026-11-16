"""Turn raw source data into threat_data: prevalence, ATT&CK links and exploitation trend."""

from __future__ import annotations

import datetime as dt
from collections import defaultdict

from .patterns import Pattern

COUNTED_STATUSES = {"Confirmed", "Suspected"}
TREND_MIN, TREND_MAX = 0.8, 1.25
CAMPAIGN_MIN = 5
CAMPAIGN_SUMMARY_MIN_CHARS = 30  # shorter summaries are generic labels, not campaigns


# ---------------------------------------------------------------- VCDB

def collapse_campaigns(records: list[dict], min_group: int = CAMPAIGN_MIN) -> tuple[list[dict], list[dict]]:
    """Count each campaign once.

    Mass-exploitation campaigns are coded as one VCDB record per victim (MOVEit in
    2023 produced several hundred identical records). Counting them separately
    would let one campaign dominate the prevalence figures, so records are grouped:

    - records with the same ``campaign_id`` form one event;
    - otherwise, ``min_group`` or more records in the same year with an identical
      summary of at least 30 characters form one event. Short generic summaries
      (for example "ATM skimmer") are left alone because they describe separate
      incidents, not one campaign.

    Returns (deduplicated records, list of collapsed groups).
    """
    by_campaign: dict[str, list[dict]] = defaultdict(list)
    by_summary: dict[tuple, list[dict]] = defaultdict(list)
    singles: list[dict] = []
    for r in records:
        if r.get("campaign_id"):
            by_campaign[str(r["campaign_id"])].append(r)
            continue
        summary = " ".join(str(r.get("summary") or "").lower().split())
        year = (r.get("timeline") or {}).get("incident", {}).get("year")
        if len(summary) >= CAMPAIGN_SUMMARY_MIN_CHARS:
            by_summary[(year, summary)].append(r)
        else:
            singles.append(r)

    kept, collapsed = list(singles), []
    for key, group in by_campaign.items():
        kept.append(group[0])
        if len(group) > 1:
            collapsed.append({"label": f"campaign {key}", "records": len(group)})
    for (year, summary), group in by_summary.items():
        if len(group) >= min_group:
            kept.append(group[0])
            collapsed.append({"label": f"{year}: {group[0].get('summary', '').strip()[:80]}",
                              "records": len(group)})
        else:
            kept.extend(group)
    collapsed.sort(key=lambda c: -c["records"])
    return kept, collapsed


def vcdb_prevalence(
    records: list[dict],
    patterns: list[Pattern],
    today: dt.date,
    window_years: int = 5,
    min_sample: int = 300,
    max_years: int = 10,
) -> dict:
    """Share of incident events in a recent window that match each pattern.

    Campaigns are collapsed first (see ``collapse_campaigns``). The window covers
    the last ``window_years`` calendar years; if it holds fewer than ``min_sample``
    events it is widened one year at a time, up to ``max_years``, so small samples
    do not produce noisy weights.
    """
    counted = [r for r in records if r.get("security_incident") in COUNTED_STATUSES]
    events, collapsed = collapse_campaigns(counted)

    by_year: dict[int, list[dict]] = defaultdict(list)
    for r in events:
        year = (r.get("timeline") or {}).get("incident", {}).get("year")
        if isinstance(year, int):
            by_year[year].append(r)

    end = today.year
    years = window_years
    while True:
        start = end - years + 1
        sample = [r for y in range(start, end + 1) for r in by_year.get(y, [])]
        if len(sample) >= min_sample or years >= max_years:
            break
        years += 1

    total = len(sample)
    result = {
        "window": {"from_year": start, "to_year": end},
        "sample_size": total,
        "incidents_per_year": {y: len(by_year.get(y, [])) for y in range(start, end + 1)},
        "below_min_sample": total < min_sample,
        "campaigns_collapsed": collapsed[:10],
        "patterns": {},
    }
    for p in patterns:
        count = sum(1 for r in sample if p.matches(r))
        result["patterns"][p.id] = {
            "count": count,
            "share": round(count / total, 4) if total else 0.0,
        }
    return result


# ---------------------------------------------------------------- ATT&CK

def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _live(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def attack_links(bundle: dict, patterns: list[Pattern]) -> dict:
    """For each pattern, the ATT&CK mitigations that mitigate its techniques."""
    objects = bundle.get("objects", [])
    mitigations = {
        o["id"]: (_attack_id(o), o.get("name", ""))
        for o in objects if o.get("type") == "course-of-action" and _live(o)
    }
    techniques = {
        o["id"]: _attack_id(o)
        for o in objects if o.get("type") == "attack-pattern" and _live(o)
    }
    mitigates: dict[str, set[str]] = defaultdict(set)  # technique ID -> mitigation IDs
    for o in objects:
        if (
            o.get("type") == "relationship"
            and o.get("relationship_type") == "mitigates"
            and _live(o)
            and o.get("source_ref") in mitigations
            and o.get("target_ref") in techniques
        ):
            tech = techniques[o["target_ref"]]
            mit = mitigations[o["source_ref"]][0]
            if tech and mit:
                mitigates[tech].add(mit)

    links = {}
    for p in patterns:
        found: set[str] = set()
        for tech, mits in mitigates.items():
            if any(tech == t or tech.startswith(t + ".") for t in p.attack_techniques):
                found |= mits
        links[p.id] = sorted(found)

    return {
        "links": links,
        "mitigation_names": dict(sorted(v for v in mitigations.values() if v[0])),
    }


# ---------------------------------------------------------------- exploitation trend

def windows(today: dt.date) -> tuple[tuple[dt.date, dt.date], tuple[dt.date, dt.date]]:
    """Last 365 days and the 365 days before that."""
    current = (today - dt.timedelta(days=365), today)
    previous = (today - dt.timedelta(days=730), today - dt.timedelta(days=366))
    return current, previous


def kev_indicator(kev: dict, today: dt.date) -> dict:
    (c_start, c_end), (p_start, p_end) = windows(today)
    current = previous = ransomware = 0
    for v in kev.get("vulnerabilities", []):
        try:
            added = dt.date.fromisoformat(str(v.get("dateAdded"))[:10])
        except ValueError:
            continue
        if c_start <= added <= c_end:
            current += 1
            if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known":
                ransomware += 1
        elif p_start <= added <= p_end:
            previous += 1
    return {
        "current": current,
        "previous": previous,
        "ratio": round(current / previous, 3) if previous else None,
        "ransomware_share": round(ransomware / current, 3) if current else None,
    }


def euvd_indicator(counts: dict) -> dict:
    current, previous = counts["current"], counts["previous"]
    return {
        "current": current,
        "previous": previous,
        "ratio": round(current / previous, 3) if previous else None,
    }


def trend_factor(*indicators: dict | None) -> float:
    """Average year-on-year ratio of the available sources, clamped to [0.8, 1.25]."""
    ratios = [i["ratio"] for i in indicators if i and i.get("ratio")]
    if not ratios:
        return 1.0
    avg = sum(ratios) / len(ratios)
    return round(min(TREND_MAX, max(TREND_MIN, avg)), 3)


# ---------------------------------------------------------------- assemble

def build_threat_data(
    patterns: list[Pattern],
    vcdb: dict,
    attack: dict,
    kev: dict | None,
    euvd: dict | None,
    sources: dict,
    today: dt.date,
) -> dict:
    factor = trend_factor(kev, euvd)
    out_patterns = {}
    for p in patterns:
        share = vcdb["patterns"][p.id]["share"]
        adjusted = round(min(1.0, share * factor), 4) if p.exploitation_trend else share
        out_patterns[p.id] = {
            "name": p.name,
            "incidents": vcdb["patterns"][p.id]["count"],
            "prevalence": share,
            "adjusted_prevalence": adjusted,
            "attack_techniques": list(p.attack_techniques),
            "attack_mitigations": attack["links"].get(p.id, []),
        }
    return {
        "schema": 1,
        "generated": today.isoformat(),
        "method": {
            "prevalence": "Share of confirmed or suspected VCDB incident events in the window that match the "
                          "pattern, with each campaign counted once",
            "trend": "vuln_exploitation prevalence x average year-on-year change in newly exploited "
                     f"vulnerabilities (CISA KEV, ENISA EUVD), clamped to [{TREND_MIN}, {TREND_MAX}]",
        },
        "vcdb": {k: vcdb[k] for k in ("window", "sample_size", "incidents_per_year", "below_min_sample",
                                       "campaigns_collapsed")},
        "exploitation_trend": {"factor": factor, "cisa_kev": kev, "enisa_euvd": euvd},
        "patterns": out_patterns,
        "attack_mitigation_names": attack.get("mitigation_names", {}),
        "sources": sources,
    }
