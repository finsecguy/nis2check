"""Database models (SQLite via SQLAlchemy)."""

from __future__ import annotations

import datetime as dt
import json

from sqlalchemy import (
    Boolean, Date, DateTime, Float, Integer, String, Text, create_engine, event, inspect, select, text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, scoped_session, sessionmaker

ROLES = ("admin", "assessor", "viewer")
ROLE_LABELS = {
    "admin": "Administrator",
    "assessor": "Assessor",
    "viewer": "Viewer",
}


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    role: Mapped[str] = mapped_column(String(20), default="viewer")
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    sso_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Empty follows the organisation country. One of en, sk, cs, hu, pl.
    language: Mapped[str | None] = mapped_column(String(8), nullable=True)
    # Rotated on login, logout, password change and password reset so an old cookie stops working.
    session_token: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    last_login: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)

    # Flask-Login style helpers
    @property
    def is_authenticated(self) -> bool:
        return True

    def can(self, action: str) -> bool:
        if not self.active:
            return False
        if action == "view":
            return True
        if action == "edit":
            return self.role in ("admin", "assessor")
        if action == "admin":
            return self.role == "admin"
        return False


class Organisation(Base):
    __tablename__ = "organisation"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    sector: Mapped[str | None] = mapped_column(String(64), nullable=True)
    employees: Mapped[int | None] = mapped_column(Integer, nullable=True)
    annual_turnover_eur: Mapped[float | None] = mapped_column(Float, nullable=True)
    balance_sheet_eur: Mapped[float | None] = mapped_column(Float, nullable=True)
    size_exempt: Mapped[bool] = mapped_column(Boolean, default=False)
    # The scope wizard's subsector and ticked cases. The organisation page
    # re-runs that same check from these, rather than the coarse sector alone.
    subsector_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    special_cases: Mapped[str] = mapped_column(Text, default="")
    # Comma-separated framework ids. NULL on a database created before this column
    # means NIS2, which is what those installs were assessing.
    frameworks: Mapped[str | None] = mapped_column(String(32), nullable=True, default="nis2")
    # eu, sk, cz, hu or pl. NULL on a database from before this column means the Directive only.
    country: Mapped[str | None] = mapped_column(String(8), nullable=True, default="eu")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    @property
    def special_case_ids(self) -> list[str]:
        return [part for part in (self.special_cases or "").split(",") if part]

    @property
    def framework_ids(self) -> tuple[str, ...]:
        from ..frameworks import parse_frameworks
        return parse_frameworks(self.frameworks)

    @property
    def country_code(self) -> str:
        from ..jurisdictions import COUNTRY_CODES
        code = (self.country or "eu").strip().lower()
        return code if code in COUNTRY_CODES else "eu"


class Response(Base):
    __tablename__ = "responses"
    question_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    answer: Mapped[str | None] = mapped_column(String(10), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    remediation_due: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    updated_by: Mapped[str] = mapped_column(String(255), default="")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(primary_key=True)
    question_id: Mapped[str] = mapped_column(String(20), index=True)
    kind: Mapped[str] = mapped_column(String(10))  # file | link
    title: Mapped[str] = mapped_column(String(255), default="")
    filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    stored_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    url: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    valid_until: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    uploaded_by: Mapped[str] = mapped_column(String(255), default="")
    uploaded_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class Snapshot(Base):
    """Score at a point in time, for the trend chart on the dashboard."""
    __tablename__ = "snapshots"
    id: Mapped[int] = mapped_column(primary_key=True)
    taken_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, index=True)
    score_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    verified_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    open_items: Mapped[int] = mapped_column(Integer, default=0)
    critical_open: Mapped[int] = mapped_column(Integer, default=0)
    weighting: Mapped[str] = mapped_column(String(20), default="threat")
    detail_json: Mapped[str] = mapped_column(Text, default="{}")

    @property
    def detail(self) -> dict:
        return json.loads(self.detail_json or "{}")


class ThreatDataVersion(Base):
    __tablename__ = "threat_data_versions"
    id: Mapped[int] = mapped_column(primary_key=True)
    fetched_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|active|rejected|superseded|failed
    data_json: Mapped[str] = mapped_column(Text, default="{}")
    change_report: Mapped[str] = mapped_column(Text, default="")
    warnings_json: Mapped[str] = mapped_column(Text, default="[]")
    error: Mapped[str] = mapped_column(Text, default="")
    has_changes: Mapped[bool] = mapped_column(Boolean, default=True)
    triggered_by: Mapped[str] = mapped_column(String(255), default="scheduler")
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)

    @property
    def data(self) -> dict:
        return json.loads(self.data_json or "{}")

    @property
    def warnings(self) -> list[str]:
        return json.loads(self.warnings_json or "[]")


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(255), default="")
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(255), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    ip: Mapped[str] = mapped_column(String(64), default="")


DEFAULT_SETTINGS = {
    "weighting": "threat",
    "rank_by": "risk",
    "threat_auto_check": "1",
    "threat_last_check": "",
}


def _sync_columns(engine) -> None:
    """Add columns that exist on a model but not yet in the database.

    create_all() makes missing tables but never alters existing ones, so after an
    upgrade a new column would be absent on installs that already have the table.
    This adds each one with ALTER TABLE ADD COLUMN (nullable; the ORM supplies the
    default on write), which covers how the schema evolves here. A change SQLite
    cannot do this way (rename, drop, retype) would need a real migration tool.
    """
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    additions: list[str] = []
    for table in Base.metadata.sorted_tables:
        if table.name not in tables:
            continue
        have = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in have:
                continue
            coltype = col.type.compile(dialect=engine.dialect)
            additions.append(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {coltype}')
    if additions:
        with engine.begin() as conn:
            for ddl in additions:
                conn.execute(text(ddl))


def make_session(db_url: str) -> scoped_session:
    engine = create_engine(db_url, connect_args={"check_same_thread": False}, future=True)

    @event.listens_for(engine, "connect")
    def _pragmas(conn, _record):  # pragma: no cover - sqlite tuning
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(engine)
    _sync_columns(engine)
    session = scoped_session(sessionmaker(bind=engine, expire_on_commit=False, future=True))
    s = session()
    for key, value in DEFAULT_SETTINGS.items():
        if s.get(Setting, key) is None:
            s.add(Setting(key=key, value=value))
    if s.execute(select(Organisation)).scalar_one_or_none() is None:
        s.add(Organisation(name=""))
    s.commit()
    session.remove()
    return session
