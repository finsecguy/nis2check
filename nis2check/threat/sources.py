"""Fetch raw threat data from public sources, or read it from a local directory.

Every fetcher returns ``(data, meta)``. ``meta`` records where the data came from,
when, and which version, so each report can be traced back to its inputs.

Offline use and tests: pass ``source_dir`` containing any of
``vcdb.json.zip`` (or ``vcdb.json``), ``enterprise-attack.json``, ``kev.json``
and ``euvd.json`` (``{"current": <int>, "previous": <int>}``).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from .. import __version__

VCDB_URL = "https://raw.githubusercontent.com/vz-risk/VCDB/master/data/joined/vcdb.json.zip"
ATTACK_INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EUVD_SEARCH_URLS = (
    "https://euvdservices.enisa.europa.eu/api/search",
    "https://euvdservices.enisa.europa.eu/api/vulnerabilities",  # older alias
)

TIMEOUT = 120


class SourceError(RuntimeError):
    """A source could not be fetched or parsed."""


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": f"nis2check/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 (fixed https URLs)
            return resp.read()
    except Exception as exc:  # network errors, HTTP errors, timeouts
        raise SourceError(f"{url}: {exc}") from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_vcdb_bytes(raw: bytes, name: str) -> list[dict]:
    if name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            records: list[dict] = []
            for member in zf.namelist():
                if member.endswith(".json"):
                    records.extend(json.loads(zf.read(member)))
            return records
    return json.loads(raw)


def get_vcdb(source_dir: Path | None = None) -> tuple[list[dict], dict]:
    if source_dir:
        for name in ("vcdb.json.zip", "vcdb.json"):
            path = source_dir / name
            if path.exists():
                raw = path.read_bytes()
                data = _load_vcdb_bytes(raw, name)
                return data, {"url": str(path), "retrieved": _now(), "sha256": _sha256(raw)}
        raise SourceError(f"{source_dir}: no vcdb.json.zip or vcdb.json")
    raw = _get(VCDB_URL)
    try:
        data = _load_vcdb_bytes(raw, VCDB_URL)
    except (zipfile.BadZipFile, json.JSONDecodeError) as exc:
        raise SourceError(f"VCDB: could not parse download ({exc})") from exc
    return data, {"url": VCDB_URL, "retrieved": _now(), "sha256": _sha256(raw)}


def get_attack(source_dir: Path | None = None) -> tuple[dict, dict]:
    if source_dir:
        path = source_dir / "enterprise-attack.json"
        if not path.exists():
            raise SourceError(f"{path} not found")
        raw = path.read_bytes()
        data = json.loads(raw)
        return data, {"url": str(path), "retrieved": _now(), "version": _attack_version(data)}
    index = json.loads(_get(ATTACK_INDEX_URL))
    try:
        enterprise = next(c for c in index["collections"] if c["name"] == "Enterprise ATT&CK")
        latest = enterprise["versions"][0]
    except (KeyError, StopIteration, IndexError) as exc:
        raise SourceError("ATT&CK index: unexpected format") from exc
    raw = _get(latest["url"])
    return json.loads(raw), {
        "url": latest["url"],
        "retrieved": _now(),
        "version": str(latest["version"]),
    }


def _attack_version(bundle: dict) -> str:
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            return str(obj.get("x_mitre_version", "unknown"))
    return "unknown"


def get_kev(source_dir: Path | None = None) -> tuple[dict, dict]:
    if source_dir:
        path = source_dir / "kev.json"
        if not path.exists():
            raise SourceError(f"{path} not found")
        data = json.loads(path.read_bytes())
        url = str(path)
    else:
        data = json.loads(_get(KEV_URL))
        url = KEV_URL
    if "vulnerabilities" not in data:
        raise SourceError("KEV: unexpected format")
    return data, {
        "url": url,
        "retrieved": _now(),
        "version": str(data.get("catalogVersion", "unknown")),
    }


def get_euvd_counts(
    current: tuple[dt.date, dt.date],
    previous: tuple[dt.date, dt.date],
    source_dir: Path | None = None,
) -> tuple[dict, dict]:
    """Number of exploited vulnerabilities in EUVD for two date windows."""
    if source_dir:
        path = source_dir / "euvd.json"
        if not path.exists():
            raise SourceError(f"{path} not found")
        data = json.loads(path.read_bytes())
        return {"current": int(data["current"]), "previous": int(data["previous"])}, {
            "url": str(path), "retrieved": _now(),
        }

    last_error: Exception | None = None
    for base in EUVD_SEARCH_URLS:
        try:
            counts = {
                label: _euvd_total(base, start, end)
                for label, (start, end) in (("current", current), ("previous", previous))
            }
            return counts, {"url": base, "retrieved": _now()}
        except SourceError as exc:
            last_error = exc
    raise SourceError(f"EUVD: {last_error}")


def _euvd_total(base: str, start: dt.date, end: dt.date) -> int:
    query = urllib.parse.urlencode(
        {"exploited": "true", "fromDate": start.isoformat(), "toDate": end.isoformat(),
         "size": 1, "page": 0}
    )
    data = json.loads(_get(f"{base}?{query}"))
    if not isinstance(data, dict) or "total" not in data:
        raise SourceError(f"{base}: response has no 'total'")
    return int(data["total"])
