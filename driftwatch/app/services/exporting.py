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
from driftwatch.app.core.utils import utcnow_iso
from driftwatch.app.models.entities import Evidence, Host


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


def serialize_evidence(evidence: Evidence) -> dict[str, Any]:
    return {
        "id": evidence.id,
        "created_at": _serialize_value(evidence.created_at),
        "host_id": evidence.host_id,
        "scan_id": evidence.scan_id,
        "finding_id": evidence.finding_id,
        "collector_name": evidence.collector_name,
        "record_type": evidence.record_type,
        "payload": evidence.payload_json,
    }


def serialize_host(host: Host | None) -> dict[str, Any] | None:
    if host is None:
        return None
    return {
        "id": host.id,
        "hostname": host.hostname,
        "os_family": host.os_family,
        "os_version": host.os_version,
        "architecture": host.architecture,
        "metadata": host.metadata_json,
        "created_at": _serialize_value(host.created_at),
        "last_seen_at": _serialize_value(host.last_seen_at),
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


def _evidence_rows_for_csv(evidence_rows: list[Evidence]) -> list[dict[str, Any]]:
    return [
        {
            "id": item.id,
            "created_at": _serialize_value(item.created_at),
            "host_id": item.host_id,
            "scan_id": item.scan_id,
            "finding_id": item.finding_id,
            "collector_name": item.collector_name,
            "record_type": item.record_type,
            "payload_json": _serialize_json_blob(item.payload_json),
        }
        for item in evidence_rows
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


def filtered_evidence(
    session: Session,
    collector_name: str | None = None,
    record_type: str | None = None,
    scan_id: str | None = None,
    finding_id: str | None = None,
) -> list[Evidence]:
    query = select(Evidence).order_by(Evidence.created_at.desc())
    if collector_name:
        query = query.where(Evidence.collector_name == collector_name)
    if record_type:
        query = query.where(Evidence.record_type == record_type)
    if scan_id:
        query = query.where(Evidence.scan_id == scan_id)
    if finding_id:
        query = query.where(Evidence.finding_id == finding_id)
    return session.execute(query).scalars().all()


def render_export_payload(
    export_target: str,
    export_format: str,
    findings: Sequence[Finding] | None = None,
    scans: Sequence[Scan] | None = None,
    evidence_rows: Sequence[Evidence] | None = None,
) -> str:
    if export_target == "findings":
        if export_format == "json":
            return json.dumps([serialize_finding(finding) for finding in findings or []], indent=2, default=_serialize_value) + "\n"
        rows = _finding_rows_for_csv(list(findings or []))
    elif export_target == "scans":
        if export_format == "json":
            return json.dumps([serialize_scan(scan) for scan in scans or []], indent=2, default=_serialize_value) + "\n"
        rows = _scan_rows_for_csv(list(scans or []))
    else:
        if export_format == "json":
            return json.dumps([serialize_evidence(item) for item in evidence_rows or []], indent=2, default=_serialize_value) + "\n"
        rows = _evidence_rows_for_csv(list(evidence_rows or []))

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


def export_evidence(
    session: Session,
    output: str | None,
    export_format: str,
    collector_name: str | None = None,
    record_type: str | None = None,
    scan_id: str | None = None,
    finding_id: str | None = None,
) -> int:
    evidence_rows = filtered_evidence(
        session,
        collector_name=collector_name,
        record_type=record_type,
        scan_id=scan_id,
        finding_id=finding_id,
    )
    if export_format == "json":
        _write_json([serialize_evidence(item) for item in evidence_rows], output)
    else:
        _write_csv(_evidence_rows_for_csv(evidence_rows), output)
    return len(evidence_rows)


def build_dashboard_snapshot(
    session: Session,
    page: str,
    name: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    status: str | None = None,
    os_family: str | None = None,
    collector_name: str | None = None,
    record_type: str | None = None,
    scan_id: str | None = None,
    finding_id: str | None = None,
) -> dict[str, Any]:
    from driftwatch.app.services.reporting import (
        count_findings,
        latest_host,
        latest_scan,
        latest_software_inventory,
        list_findings,
        list_scans_filtered,
        max_scan_total,
        recent_scan_activity,
        severity_distribution,
    )

    if page == "findings":
        findings = list_findings(session, severity=severity, category=category, status=status)
        return {
            "generated_at": utcnow_iso(),
            "page": page,
            "filters": {"severity": severity, "category": category, "status": status},
            "count": len(findings),
            "findings": [serialize_finding(finding) for finding in findings],
        }
    if page == "scans":
        activity = recent_scan_activity(session, limit=16)
        scans = list_scans_filtered(session, status=status, os_family=os_family)
        return {
            "generated_at": utcnow_iso(),
            "page": page,
            "filters": {"status": status, "os_family": os_family},
            "count": len(scans),
            "max_total_findings": max_scan_total(activity),
            "scan_activity": activity,
            "scans": [serialize_scan(scan) for scan in scans],
        }
    if page == "software":
        inventory = latest_software_inventory(session, name_filter=name)
        return {
            "generated_at": utcnow_iso(),
            "page": page,
            "filters": {"name": name},
            "count": len(inventory),
            "software": inventory,
        }
    if page == "evidence":
        evidence_rows = filtered_evidence(
            session,
            collector_name=collector_name,
            record_type=record_type,
            scan_id=scan_id,
            finding_id=finding_id,
        )
        return {
            "generated_at": utcnow_iso(),
            "page": page,
            "filters": {
                "collector_name": collector_name,
                "record_type": record_type,
                "scan_id": scan_id,
                "finding_id": finding_id,
            },
            "count": len(evidence_rows),
            "evidence": [serialize_evidence(item) for item in evidence_rows],
        }

    counts = count_findings(session)
    activity = recent_scan_activity(session)
    current_scan = latest_scan(session)
    return {
        "generated_at": utcnow_iso(),
        "page": "overview",
        "host": serialize_host(latest_host(session)),
        "latest_scan": serialize_scan(current_scan) if current_scan else None,
        "finding_counts": counts,
        "severity_chart": severity_distribution(counts),
        "scan_activity": activity,
        "max_total_findings": max_scan_total(activity),
    }
