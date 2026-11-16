"""Configuration from environment variables.

Everything has a safe default so `docker compose up` works with no settings at
all. See .env.example for the full list.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _list(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [x.strip().lower() for x in raw.split(",") if x.strip()]


@dataclass
class OIDCProvider:
    key: str            # "entra" | "google"
    label: str          # button text
    client_id: str
    client_secret: str
    discovery_url: str


@dataclass
class Settings:
    data_dir: Path
    secret_key: str
    base_url: str = ""
    secure_cookies: bool = False
    behind_proxy: bool = False  # trust X-Forwarded-* from one reverse proxy
    local_login: bool = True
    oidc_providers: list[OIDCProvider] = field(default_factory=list)
    oidc_allowed_domains: list[str] = field(default_factory=list)
    oidc_auto_provision: bool = False
    oidc_default_role: str = "viewer"
    max_upload_mb: int = 25
    threat_auto_check: bool = True
    threat_check_hours: int = 24 * 7
    threat_source_dir: str | None = None  # offline mirror of the sources (tests, air-gapped installs)

    @property
    def db_url(self) -> str:
        return f"sqlite:///{self.data_dir / 'nis2check.db'}"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"


def _secret_key(data_dir: Path) -> str:
    """Use NIS2_SECRET_KEY, or generate one and keep it in the data volume."""
    if os.environ.get("NIS2_SECRET_KEY"):
        return os.environ["NIS2_SECRET_KEY"]
    path = data_dir / ".secret_key"
    if path.exists():
        return path.read_text().strip()
    key = secrets.token_urlsafe(48)
    path.write_text(key)
    path.chmod(0o600)
    return key


def _providers() -> list[OIDCProvider]:
    providers = []
    if os.environ.get("NIS2_ENTRA_CLIENT_ID"):
        tenant = os.environ.get("NIS2_ENTRA_TENANT_ID", "").strip()
        if not tenant:
            raise ValueError(
                "NIS2_ENTRA_TENANT_ID is required with NIS2_ENTRA_CLIENT_ID "
                "(your Microsoft Entra directory (tenant) ID)."
            )
        providers.append(OIDCProvider(
            key="entra",
            label="Sign in with Microsoft",
            client_id=os.environ["NIS2_ENTRA_CLIENT_ID"],
            client_secret=os.environ.get("NIS2_ENTRA_CLIENT_SECRET", ""),
            discovery_url=f"https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration",
        ))
    if os.environ.get("NIS2_GOOGLE_CLIENT_ID"):
        providers.append(OIDCProvider(
            key="google",
            label="Sign in with Google",
            client_id=os.environ["NIS2_GOOGLE_CLIENT_ID"],
            client_secret=os.environ.get("NIS2_GOOGLE_CLIENT_SECRET", ""),
            discovery_url="https://accounts.google.com/.well-known/openid-configuration",
        ))
    return providers


def load_settings(**overrides) -> Settings:
    data_dir = Path(overrides.pop("data_dir", None) or os.environ.get("NIS2_DATA_DIR", "./data")).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "evidence").mkdir(exist_ok=True)
    role = os.environ.get("NIS2_SSO_DEFAULT_ROLE", "viewer").lower()
    settings = Settings(
        data_dir=data_dir,
        secret_key=_secret_key(data_dir),
        base_url=os.environ.get("NIS2_BASE_URL", "").rstrip("/"),
        secure_cookies=_bool("NIS2_SECURE_COOKIES", False),
        behind_proxy=_bool("NIS2_BEHIND_PROXY", False),
        local_login=_bool("NIS2_LOCAL_LOGIN", True),
        oidc_providers=_providers(),
        oidc_allowed_domains=_list("NIS2_SSO_ALLOWED_DOMAINS"),
        oidc_auto_provision=_bool("NIS2_SSO_AUTO_PROVISION", False),
        oidc_default_role=role if role in ("viewer", "assessor") else "viewer",
        max_upload_mb=int(os.environ.get("NIS2_MAX_UPLOAD_MB", "25")),
        threat_auto_check=_bool("NIS2_THREAT_AUTO_CHECK", True),
        threat_check_hours=int(os.environ.get("NIS2_THREAT_CHECK_HOURS", str(24 * 7))),
        threat_source_dir=os.environ.get("NIS2_THREAT_SOURCE_DIR") or None,
    )
    for key, value in overrides.items():
        setattr(settings, key, value)
    return settings
