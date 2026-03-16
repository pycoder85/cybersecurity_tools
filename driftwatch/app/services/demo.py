from __future__ import annotations

from datetime import timedelta
from sqlalchemy import select

from driftwatch.app.core.config import AppConfig
from driftwatch.app.core.utils import utcnow
from driftwatch.app.models.entities import DemoMarker, Evidence, Finding, FindingNote, Host, Scan
from driftwatch.app.services.database import init_database, session_scope


def seed_demo_data(config: AppConfig) -> None:
    init_database(config.database_url)
    now = utcnow()
    with session_scope(config.database_url) as session:
        marker = session.execute(select(DemoMarker).where(DemoMarker.active.is_(True))).scalar_one_or_none()
        if marker is not None:
            return
        host = Host(
            hostname="lab-sample-01",
            os_family="linux",
            os_version="Demo Linux 6.x",
            architecture="x86_64",
            metadata_json={"demo": True, "hostname": "lab-sample-01", "os_family": "linux"},
            last_seen_at=now,
        )
        session.add(host)
        session.flush()
        demo_scans = [
            ("completed", now - timedelta(hours=4), {"high": 1, "medium": 2, "low": 1}),
            ("completed", now - timedelta(hours=2), {"critical": 1, "medium": 1}),
            ("completed", now - timedelta(minutes=20), {"high": 2, "low": 1}),
        ]
        for index, (_, started_at, counts) in enumerate(demo_scans, start=1):
            scan = Scan(
                host_id=host.id,
                os_family="linux",
                started_at=started_at,
                completed_at=started_at,
                status="completed",
                summary_json={"total_findings": sum(counts.values()), "severity_counts": counts},
            )
            session.add(scan)
            session.flush()
            title = [
                "Process executing from /tmp",
                "Recent authorized_keys change",
                "Process executing from /tmp",
            ][(index - 1) % 3]
            finding = Finding(
                host_id=host.id,
                scan_id=scan.id,
                timestamp=started_at,
                category=["Suspicious processes", "Unauthorized key or startup file changes", "Suspicious processes"][(index - 1) % 3],
                severity=list(counts.keys())[0],
                title=title,
                description="Demo finding for UI preview and local dashboard validation.",
                evidence_json={"demo": True, "scan_index": index, "path": "/tmp/demo.bin"},
                rule_name=["suspicious_temp_process", "recent_authorized_keys", "suspicious_temp_process"][(index - 1) % 3],
                source_module="demo.seed",
                os_family="linux",
                confidence="medium",
                suggested_action="Validate the file path and keep response actions disabled by default.",
                explanation="Demo explanation only. Deterministic rules remain the primary source of truth.",
            )
            session.add(finding)
            session.flush()
            session.add(
                Evidence(
                    host_id=host.id,
                    scan_id=scan.id,
                    finding_id=finding.id,
                    collector_name="demo.seed",
                    record_type="finding_evidence",
                    payload_json=finding.evidence_json,
                )
            )
            if index == 1:
                session.add(
                    FindingNote(
                        finding_id=finding.id,
                        author="demo-analyst",
                        note_text="Demo analyst note: validate whether this path belongs to an approved test artifact.",
                    )
                )
        session.add(DemoMarker(active=True))
