"""Owner and due date for a gap, used by the board report."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import Date, String
from sqlalchemy.orm import Mapped, mapped_column

from .models import Base


class GapAction(Base):
    __tablename__ = "gap_actions"
    question_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    owner: Mapped[str] = mapped_column(String(255), default="")
    due_on: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
