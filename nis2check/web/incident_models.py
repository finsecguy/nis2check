"""Incident tables. Imported before create_all so an existing database gains them."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base, utcnow


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255), default="")
    # When the entity became aware. Naive UTC, matching the rest of the app.
    detected_at: Mapped[dt.datetime] = mapped_column(DateTime, index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class IncidentReport(Base):
    """One Art. 23(4) stage. Intermediate reports can repeat; the others are one each."""

    __tablename__ = "incident_reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(Integer, index=True)
    stage: Mapped[str] = mapped_column(String(32))
    submitted_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    suspected_unlawful: Mapped[str] = mapped_column(String(16), default="")
    cross_border: Mapped[str] = mapped_column(String(16), default="")
    severity_impact: Mapped[str] = mapped_column(Text, default="")
    indicators: Mapped[str] = mapped_column(Text, default="")
    root_cause: Mapped[str] = mapped_column(Text, default="")
    mitigation: Mapped[str] = mapped_column(Text, default="")
    body: Mapped[str] = mapped_column(Text, default="")
    ongoing: Mapped[bool] = mapped_column(Boolean, default=False)
    handling_completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
