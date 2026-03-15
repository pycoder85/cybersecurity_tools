from __future__ import annotations

import csv
import json
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

from sqlalchemy import select
from sqlalchemy.orm import Session

from driftwatch.app.models.entities import Finding, Scan


def _serialize_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _serialize_json_blob(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=_serialize_value)


def serialize_finding(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "timestamp": _serialize_value(finding.timestamp),
        "host_id": finding.host_id,
        "scan_id": finding.scan_id,
        "category": finding.category,
        "severity": finding.severity,
        "status": finding.status,
        "title": finding.title,
        "description": finding.description,
        "evidence": finding.evidence_json,
        "rule_name": finding.rule_name,
        "source_module": finding.source_module,
        "os_family": finding.os_family,
        "confidence": finding.confidence,
        "suggested_action": finding.suggested_action,
        "explanation": finding.explanation,
    }


def serialize_scan(scan: Scan) -> dict[str, Any]:
    return {
        "id": scan.id,
        "host_id": scan.host_id,
        "os_family": scan.os_family,
        "started_at": _serialize_value(scan.started_at),
        "completed_at": _serialize_value(scan.completed_at),
        "status": scan.status,
        "summary": scan.summary_json,
    }


def _finding_rows_for_csv(findings: list[Finding]) -> list[dict[str, Any]]:
    return [
        {
            "id": finding.id,
            "timestamp": _serialize_value(finding.timestamp),
            "host_id": finding.host_id,
            "scan_id": finding.scan_id,
            "category": finding.category,
            "severity": finding.severity,
            "status": finding.status,
            "title": finding.title,
            "description": finding.description,
            "rule_name": finding.rule_name,
            "source_module": finding.source_module,
            "os_family": finding.os_family,
            "confidence": finding.confidence,
            "suggested_action": finding.suggested_action,
            "explanation": finding.explanation,
            "evidence_json": _serialize_json_blob(finding.evidence_json),
        }
        for finding in findings
    ]


def _scan_rows_for_csv(scans: list[Scan]) -> list[dict[str, Any]]:
    return [
        {
            "id": scan.id,
            "host_id": scan.host_id,
            "os_family": scan.os_family,
            "started_at": _serialize_value(scan.started_at),
            "completed_at": _serialize_value(scan.completed_at),
            "status": scan.status,
            "summary_json": _serialize_json_blob(scan.summary_json),
        }
        for scan in scans
    ]


def _writer_for_path(output: str | None) -> tuple[TextIO, bool]:
    if not output or output == "-":
        return sys.stdout, False
    path = Path(output).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("w", encoding="utf-8", newline=""), True


def _write_json(rows: list[dict[str, Any]], output: str | None) -> None:
    handle, should_close = _writer_for_path(output)
    try:
        json.dump(rows, handle, indent=2, default=_serialize_value)
        handle.write("\n")
    finally:
        if should_close:
            handle.close()


def _write_csv(rows: list[dict[str, Any]], output: str | None) -> None:
    handle, should_close = _writer_for_path(output)
    try:
        fieldnames = list(rows[0].keys()) if rows else []
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if fieldnames:
            writer.writeheader()
            writer.writerows(rows)
        else:
            handle.write("")
    finally:
        if should_close:
            handle.close()


def filtered_findings(
    session: Session,
    severity: str | None = None,
    category: str | None = None,
    status: str | None = None,
) -> list[Finding]:
    query = select(Finding).order_by(Finding.timestamp.desc())
    if severity:
        query = query.where(Finding.severity == severity)
    if category:
        query = query.where(Finding.category == category)
    if status:
        query = query.where(Finding.status == status)
    return session.execute(query).scalars().all()


def filtered_scans(
    session: Session,
    status: str | None = None,
    os_family: str | None = None,
) -> list[Scan]:
    query = select(Scan).order_by(Scan.started_at.desc())
    if status:
        query = query.where(Scan.status == status)
    if os_family:
        query = query.where(Scan.os_family == os_family)
    return session.execute(query).scalars().all()


def render_export_payload(
    export_target: str,
    export_format: str,
    findings: Sequence[Finding] | None = None,
    scans: Sequence[Scan] | None = None,
) -> str:
    if export_target == "findings":
        if export_format == "json":
            return json.dumps([serialize_finding(finding) for finding in findings or []], indent=2, default=_serialize_value) + "\n"
        rows = _finding_rows_for_csv(list(findings or []))
    else:
        if export_format == "json":
            return json.dumps([serialize_scan(scan) for scan in scans or []], indent=2, default=_serialize_value) + "\n"
        rows = _scan_rows_for_csv(list(scans or []))

    from io import StringIO

    buffer = StringIO()
    fieldnames = list(rows[0].keys()) if rows else []
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    if fieldnames:
        writer.writeheader()
        writer.writerows(rows)
    return buffer.getvalue()


def export_findings(
    session: Session,
    output: str | None,
    export_format: str,
    severity: str | None = None,
    category: str | None = None,
    status: str | None = None,
) -> int:
    findings = filtered_findings(session, severity=severity, category=category, status=status)
    if export_format == "json":
        _write_json([serialize_finding(finding) for finding in findings], output)
    else:
        _write_csv(_finding_rows_for_csv(findings), output)
    return len(findings)


def export_scans(
    session: Session,
    output: str | None,
    export_format: str,
    status: str | None = None,
    os_family: str | None = None,
) -> int:
    scans = filtered_scans(session, status=status, os_family=os_family)
    if export_format == "json":
        _write_json([serialize_scan(scan) for scan in scans], output)
    else:
        _write_csv(_scan_rows_for_csv(scans), output)
    return len(scans)
