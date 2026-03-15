from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from driftwatch.app.models.base import Base
from driftwatch.app.core.utils import utcnow


def new_id() -> str:
    return str(uuid.uuid4())


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    os_family: Mapped[str] = mapped_column(String(32), index=True)
    os_version: Mapped[str] = mapped_column(String(255), default="")
    architecture: Mapped[str] = mapped_column(String(64), default="")
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scans: Mapped[list["Scan"]] = relationship(back_populates="host")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)
    os_family: Mapped[str] = mapped_column(String(32), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="completed")
    summary_json: Mapped[dict] = mapped_column(JSON, default=dict)

    host: Mapped["Host"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan")
    evidence_entries: Mapped[list["Evidence"]] = relationship(back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    category: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)
    rule_name: Mapped[str] = mapped_column(String(128), index=True)
    source_module: Mapped[str] = mapped_column(String(128), default="")
    os_family: Mapped[str] = mapped_column(String(32), index=True)
    confidence: Mapped[str] = mapped_column(String(32), default="medium")
    suggested_action: Mapped[str] = mapped_column(Text, default="")
    explanation: Mapped[str] = mapped_column(Text, default="")

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    evidence_entries: Mapped[list["Evidence"]] = relationship(back_populates="finding")
    notes: Mapped[list["FindingNote"]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        order_by="FindingNote.created_at.desc()",
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id"), nullable=True, index=True)
    collector_name: Mapped[str] = mapped_column(String(128), index=True)
    record_type: Mapped[str] = mapped_column(String(64), index=True)
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict)

    scan: Mapped["Scan"] = relationship(back_populates="evidence_entries")
    finding: Mapped["Finding"] = relationship(back_populates="evidence_entries")


class BaselineItem(Base):
    __tablename__ = "baselines"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)
    baseline_type: Mapped[str] = mapped_column(String(64), index=True)
    item_key: Mapped[str] = mapped_column(String(255), index=True)
    item_hash: Mapped[str] = mapped_column(String(64), index=True)
    data_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value_json: Mapped[object] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class FindingNote(Base):
    __tablename__ = "finding_notes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    author: Mapped[str] = mapped_column(String(128), default="local-analyst")
    note_text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    finding: Mapped["Finding"] = relationship(back_populates="notes")


class DemoMarker(Base):
    __tablename__ = "demo_markers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    active: Mapped[bool] = mapped_column(Boolean, default=False)
