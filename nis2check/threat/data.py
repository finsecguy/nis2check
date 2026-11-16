"""Load threat_data.yaml (bundled snapshot or a custom file)."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import yaml


@dataclass
class ThreatData:
    raw: dict
    path: str

    @property
    def generated(self) -> str:
        return str(self.raw.get("generated", "unknown"))

    @property
    def patterns(self) -> dict[str, dict]:
        return self.raw.get("patterns", {})

    @property
    def sources(self) -> dict[str, dict]:
        return self.raw.get("sources", {})

    @property
    def vcdb(self) -> dict:
        return self.raw.get("vcdb", {})

    @property
    def trend(self) -> dict:
        return self.raw.get("exploitation_trend", {})

    def mitigation_name(self, mid: str) -> str:
        return self.raw.get("attack_mitigation_names", {}).get(mid, mid)

    @property
    def version_label(self) -> str:
        attack = self.sources.get("mitre_attack", {}).get("version", "?")
        window = self.vcdb.get("window", {})
        return (f"threat data of {self.generated}: VCDB {window.get('from_year', '?')}-"
                f"{window.get('to_year', '?')}, ATT&CK v{attack}")


def load_threat_data(path: str | Path | None = None) -> ThreatData:
    if path is None:
        ref = resources.files("nis2check").joinpath("data/threat_data.yaml")
        return ThreatData(yaml.safe_load(ref.read_text("utf-8")), "bundled snapshot")
    path = Path(path)
    return ThreatData(yaml.safe_load(path.read_text("utf-8")), str(path))
