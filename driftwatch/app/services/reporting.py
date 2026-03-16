from __future__ import annotations

from collections import Counter
from datetime import datetime

from sqlalchemy import Select, desc, func, select
from sqlalchemy.orm import Session, selectinload

from driftwatch.app.core.utils import stable_hash
from driftwatch.app.models.entities import Evidence, Finding, Host, Scan


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLORS = {
    "critical": "var(--critical)",
    "high": "var(--high)",
    "medium": "var(--medium)",
    "low": "var(--low)",
    "info": "var(--info)",
}


def latest_host(session: Session) -> Host | None:
    return session.execute(select(Host).order_by(desc(Host.last_seen_at)).limit(1)).scalar_one_or_none()


def latest_scan(session: Session) -> Scan | None:
    return session.execute(select(Scan).order_by(desc(Scan.started_at)).limit(1)).scalar_one_or_none()


def count_findings(session: Session) -> dict[str, int]:
    rows = session.execute(select(Finding.severity, func.count()).group_by(Finding.severity)).all()
    counts = Counter({severity: total for severity, total in rows})
    for severity in SEVERITY_ORDER:
        counts.setdefault(severity, 0)
    counts["total"] = sum(total for severity, total in rows)
    return dict(counts)


def finding_query(
    severity: str | None = None,
    category: str | None = None,
    status: str | None = None,
) -> Select[tuple[Finding]]:
    query = select(Finding).options(selectinload(Finding.notes)).order_by(desc(Finding.timestamp))
    if severity:
        query = query.where(Finding.severity == severity)
    if category:
        query = query.where(Finding.category == category)
    if status:
        query = query.where(Finding.status == status)
    return query


def list_findings(
    session: Session,
    severity: str | None = None,
    category: str | None = None,
    status: str | None = None,
) -> list[Finding]:
    findings = session.execute(finding_query(severity, category, status)).scalars().all()
    attach_finding_recurrence(session, findings)
    return findings


def list_scans(session: Session) -> list[Scan]:
    return session.execute(select(Scan).order_by(desc(Scan.started_at))).scalars().all()


def scan_query(status: str | None = None, os_family: str | None = None) -> Select[tuple[Scan]]:
    query = select(Scan).order_by(desc(Scan.started_at))
    if status:
        query = query.where(Scan.status == status)
    if os_family:
        query = query.where(Scan.os_family == os_family)
    return query


def list_scans_filtered(
    session: Session,
    status: str | None = None,
    os_family: str | None = None,
) -> list[Scan]:
    return session.execute(scan_query(status, os_family)).scalars().all()


def evidence_query(
    collector_name: str | None = None,
    record_type: str | None = None,
    scan_id: str | None = None,
    finding_id: str | None = None,
) -> Select[tuple[Evidence]]:
    query = select(Evidence).order_by(desc(Evidence.created_at))
    if collector_name:
        query = query.where(Evidence.collector_name == collector_name)
    if record_type:
        query = query.where(Evidence.record_type == record_type)
    if scan_id:
        query = query.where(Evidence.scan_id == scan_id)
    if finding_id:
        query = query.where(Evidence.finding_id == finding_id)
    return query


def list_evidence(
    session: Session,
    collector_name: str | None = None,
    record_type: str | None = None,
    scan_id: str | None = None,
    finding_id: str | None = None,
    limit: int = 250,
) -> list[Evidence]:
    return session.execute(evidence_query(collector_name, record_type, scan_id, finding_id).limit(limit)).scalars().all()


def evidence_collectors(session: Session) -> list[str]:
    rows = session.execute(select(Evidence.collector_name).distinct().order_by(Evidence.collector_name)).all()
    return [row[0] for row in rows if row[0]]


def evidence_record_types(session: Session) -> list[str]:
    rows = session.execute(select(Evidence.record_type).distinct().order_by(Evidence.record_type)).all()
    return [row[0] for row in rows if row[0]]


def latest_software_inventory(session: Session, name_filter: str | None = None) -> list[dict[str, object]]:
    entry = session.execute(
        select(Evidence)
        .where(Evidence.collector_name == "software", Evidence.record_type == "collector_result")
        .order_by(desc(Evidence.created_at))
        .limit(1)
    ).scalar_one_or_none()
    if entry is None:
        return []
    records = list((entry.payload_json or {}).get("records", []))
    if name_filter:
        normalized = name_filter.strip().lower()
        records = [record for record in records if normalized in str(record.get("name", "")).lower()]
    return sorted(
        records,
        key=lambda record: (
            str(record.get("name", "")).lower(),
            str(record.get("version", "")).lower(),
        ),
    )


def finding_categories(session: Session) -> list[str]:
    rows = session.execute(select(Finding.category).distinct().order_by(Finding.category)).all()
    return [row[0] for row in rows]


def scan_statuses(session: Session) -> list[str]:
    rows = session.execute(select(Scan.status).distinct().order_by(Scan.status)).all()
    return [row[0] for row in rows if row[0]]


def scan_os_families(session: Session) -> list[str]:
    rows = session.execute(select(Scan.os_family).distinct().order_by(Scan.os_family)).all()
    return [row[0] for row in rows if row[0]]


def severity_distribution(counts: dict[str, int]) -> list[dict[str, object]]:
    total = max(int(counts.get("total", 0)), 1)
    return [
        {
            "severity": severity,
            "count": int(counts.get(severity, 0)),
            "percent": round((int(counts.get(severity, 0)) / total) * 100, 1),
            "color": SEVERITY_COLORS[severity],
        }
        for severity in SEVERITY_ORDER
    ]


def recent_scan_activity(session: Session, limit: int = 10) -> list[dict[str, object]]:
    scans = session.execute(select(Scan).order_by(desc(Scan.started_at)).limit(limit)).scalars().all()
    series: list[dict[str, object]] = []
    for scan in reversed(scans):
        severity_counts = (scan.summary_json or {}).get("severity_counts", {})
        total_findings = int((scan.summary_json or {}).get("total_findings", 0))
        started_at: datetime | None = scan.started_at
        label = started_at.strftime("%m-%d %H:%M") if started_at else scan.id[:8]
        series.append(
            {
                "scan_id": scan.id,
                "label": label,
                "started_at": started_at,
                "total_findings": total_findings,
                "severity_counts": {severity: int(severity_counts.get(severity, 0)) for severity in SEVERITY_ORDER},
                "status": scan.status,
            }
        )
    return series


def line_chart_points(series: list[dict[str, object]], width: int = 560, height: int = 180, padding: int = 16) -> str:
    if not series:
        return ""
    values = [int(item["total_findings"]) for item in series]
    if len(values) == 1:
        x = width / 2
        y = height - padding
        return f"{x:.1f},{y:.1f}"
    max_value = max(max(values), 1)
    usable_width = width - (padding * 2)
    usable_height = height - (padding * 2)
    step = usable_width / (len(values) - 1)
    points: list[str] = []
    for index, value in enumerate(values):
        x = padding + (step * index)
        y = height - padding - ((value / max_value) * usable_height)
        points.append(f"{x:.1f},{y:.1f}")
    return " ".join(points)


def max_scan_total(series: list[dict[str, object]]) -> int:
    if not series:
        return 0
    return max(int(item["total_findings"]) for item in series)


def recurrence_signature_parts(
    host_id: str,
    rule_name: str,
    category: str,
    title: str,
    source_module: str,
    os_family: str,
    evidence_json: dict | None,
) -> list[object]:
    evidence_json = evidence_json or {}
    evidence_focus = {
        "path": evidence_json.get("path"),
        "name": evidence_json.get("name"),
        "command": evidence_json.get("command"),
        "collector_name": evidence_json.get("collector_name"),
        "baseline_type": evidence_json.get("baseline_type"),
        "item_key": evidence_json.get("item_key"),
        "raddr": evidence_json.get("raddr"),
        "laddr": evidence_json.get("laddr"),
    }
    return [host_id, rule_name, category, title, source_module, os_family, evidence_focus]


def recurrence_signature_for_finding(finding: Finding) -> str:
    return stable_hash(
        recurrence_signature_parts(
            finding.host_id,
            finding.rule_name,
            finding.category,
            finding.title,
            finding.source_module,
            finding.os_family,
            finding.evidence_json,
        )
    )


def attach_finding_recurrence(session: Session, findings: list[Finding]) -> None:
    if not findings:
        return
    host_ids = sorted({finding.host_id for finding in findings})
    rows = session.execute(
        select(
            Finding.id,
            Finding.host_id,
            Finding.rule_name,
            Finding.category,
            Finding.title,
            Finding.source_module,
            Finding.os_family,
            Finding.evidence_json,
            Finding.timestamp,
        ).where(Finding.host_id.in_(host_ids))
    ).all()
    grouped: dict[str, list[tuple[str, datetime | None]]] = {}
    for row in rows:
        signature = stable_hash(
            recurrence_signature_parts(
                row.host_id,
                row.rule_name,
                row.category,
                row.title,
                row.source_module,
                row.os_family,
                row.evidence_json,
            )
        )
        grouped.setdefault(signature, []).append((row.id, row.timestamp))
    index_maps: dict[str, dict[str, object]] = {}
    for signature, entries in grouped.items():
        ordered = sorted(entries, key=lambda item: (item[1] or datetime.min, item[0]))
        first_seen = ordered[0][1] if ordered else None
        for index, (finding_id, timestamp) in enumerate(ordered):
            index_maps[finding_id] = {
                "occurrence_count": len(ordered),
                "occurrence_index": index + 1,
                "first_seen_at": first_seen,
                "previous_seen_at": ordered[index - 1][1] if index > 0 else None,
                "seen_before": index > 0,
                "repeat_count": index,
                "is_recurring": len(ordered) > 1,
            }
    for finding in findings:
        recurrence = index_maps.get(finding.id, {})
        finding.recurrence_signature = recurrence_signature_for_finding(finding)
        finding.occurrence_count = int(recurrence.get("occurrence_count", 1))
        finding.occurrence_index = int(recurrence.get("occurrence_index", 1))
        finding.first_seen_at = recurrence.get("first_seen_at", finding.timestamp)
        finding.previous_seen_at = recurrence.get("previous_seen_at")
        finding.seen_before = bool(recurrence.get("seen_before", False))
        finding.repeat_count = int(recurrence.get("repeat_count", 0))
        finding.is_recurring = bool(recurrence.get("is_recurring", False))
