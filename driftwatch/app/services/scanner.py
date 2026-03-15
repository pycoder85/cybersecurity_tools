from __future__ import annotations

import time
from collections import Counter

from sqlalchemy import select

from driftwatch.app.collectors.factory import build_collectors
from driftwatch.app.core.config import AppConfig
from driftwatch.app.core.platform import detect_os_family
from driftwatch.app.models.entities import Evidence, Finding, Host, Scan
from driftwatch.app.rules.engine import evaluate_rules
from driftwatch.app.services.baseline import diff_baseline
from driftwatch.app.services.database import init_database, session_scope
from driftwatch.app.services.settings import get_settings


def _get_or_create_host(session, host_record: dict) -> Host:
    host = session.execute(
        select(Host).where(
            Host.hostname == host_record["hostname"],
            Host.os_family == host_record["os_family"],
        )
    ).scalar_one_or_none()
    if host is None:
        host = Host(
            hostname=host_record["hostname"],
            os_family=host_record["os_family"],
            os_version=host_record.get("os_version", ""),
            architecture=host_record.get("architecture", ""),
            metadata_json=host_record,
        )
        session.add(host)
        session.flush()
    else:
        host.os_version = host_record.get("os_version", "")
        host.architecture = host_record.get("architecture", "")
        host.metadata_json = host_record
    return host


def collect_snapshot(config: AppConfig) -> tuple[dict, dict]:
    os_family = detect_os_family()
    init_database(config.database_url)
    with session_scope(config.database_url) as session:
        settings = get_settings(session)
    snapshot = {"collectors": {}, "collected_at": time.time(), "os_family": os_family}
    for collector in build_collectors(os_family):
        result = collector.collect(config, settings)
        snapshot["collectors"][result.name] = {"records": result.records, "metadata": result.metadata}
    host_record = snapshot["collectors"]["host"]["records"][0]
    snapshot["host"] = host_record
    return snapshot, settings


def run_scan(config: AppConfig) -> dict:
    snapshot, settings = collect_snapshot(config)
    os_family = snapshot["os_family"]
    init_database(config.database_url)
    with session_scope(config.database_url) as session:
        host = _get_or_create_host(session, snapshot["host"])
        scan = Scan(host_id=host.id, os_family=os_family, status="running")
        session.add(scan)
        session.flush()
        snapshot["baseline_diff"] = diff_baseline(session, host.id, snapshot)
        findings = evaluate_rules(snapshot, os_family)
        severity_counts: Counter = Counter()
        for collector_name, payload in snapshot["collectors"].items():
            session.add(
                Evidence(
                    host_id=host.id,
                    scan_id=scan.id,
                    finding_id=None,
                    collector_name=collector_name,
                    record_type="collector_result",
                    payload_json=payload,
                )
            )
        for finding_draft in findings:
            finding = Finding(
                host_id=host.id,
                scan_id=scan.id,
                category=finding_draft.category,
                severity=finding_draft.severity,
                title=finding_draft.title,
                description=finding_draft.description,
                evidence_json=finding_draft.evidence,
                rule_name=finding_draft.rule_name,
                source_module=finding_draft.source_module,
                os_family=finding_draft.os_family,
                confidence=finding_draft.confidence,
                suggested_action=finding_draft.suggested_action,
            )
            session.add(finding)
            session.flush()
            session.add(
                Evidence(
                    host_id=host.id,
                    scan_id=scan.id,
                    finding_id=finding.id,
                    collector_name=finding_draft.source_module,
                    record_type="finding_evidence",
                    payload_json=finding_draft.evidence,
                )
            )
            severity_counts[finding.severity] += 1
        host.last_seen_at = scan.started_at
        scan.status = "completed"
        scan.completed_at = scan.started_at
        scan.summary_json = {
            "total_findings": sum(severity_counts.values()),
            "severity_counts": dict(severity_counts),
            "collector_counts": {
                name: len(payload["records"]) for name, payload in snapshot["collectors"].items()
            },
            "settings_used": settings,
        }
        return {
            "scan_id": scan.id,
            "host_id": host.id,
            "os_family": os_family,
            "summary": scan.summary_json,
        }
