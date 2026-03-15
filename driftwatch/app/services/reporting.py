from __future__ import annotations

from collections import Counter
from datetime import datetime

from sqlalchemy import Select, desc, func, select
from sqlalchemy.orm import Session

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
    query = select(Finding).order_by(desc(Finding.timestamp))
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
    return session.execute(finding_query(severity, category, status)).scalars().all()


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


def list_evidence(session: Session) -> list[Evidence]:
    return session.execute(select(Evidence).order_by(desc(Evidence.created_at)).limit(250)).scalars().all()


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
