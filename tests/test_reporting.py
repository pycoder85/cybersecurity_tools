from pathlib import Path
from datetime import datetime, timezone

from driftwatch.app.core.config import AppConfig
from driftwatch.app.models.entities import Evidence, Host, Scan
from driftwatch.app.services.database import init_database, session_scope
from driftwatch.app.services.demo import seed_demo_data
from driftwatch.app.services.reporting import (
    SEVERITY_ORDER,
    line_chart_points,
    latest_software_inventory,
    list_findings,
    max_scan_total,
    recent_scan_activity,
    severity_distribution,
)


def build_test_config(tmp_path: Path) -> AppConfig:
    return AppConfig(data_dir=tmp_path, database_url=f"sqlite:///{tmp_path / 'test.db'}")


def test_recurrence_metadata_marks_repeat_findings(tmp_path):
    config = build_test_config(tmp_path)
    seed_demo_data(config)

    with session_scope(config.database_url) as session:
        findings = list_findings(session)

    repeat_findings = [finding for finding in findings if getattr(finding, "seen_before", False)]
    first_sightings = [finding for finding in findings if getattr(finding, "is_recurring", False) and not getattr(finding, "seen_before", False)]

    assert repeat_findings
    assert first_sightings
    assert repeat_findings[0].repeat_count >= 1
    assert repeat_findings[0].previous_seen_at is not None
    assert first_sightings[0].occurrence_count >= 2


def test_severity_distribution_includes_all_levels_in_order():
    chart = severity_distribution({"critical": 1, "high": 2, "medium": 1, "total": 4})

    assert [item["severity"] for item in chart] == SEVERITY_ORDER
    assert chart[0]["percent"] == 25.0
    assert chart[1]["percent"] == 50.0
    assert chart[-1]["count"] == 0
    assert chart[-1]["percent"] == 0.0


def test_recent_scan_activity_returns_chronological_series_with_normalized_counts(tmp_path):
    config = build_test_config(tmp_path)
    seed_demo_data(config)

    with session_scope(config.database_url) as session:
        series = recent_scan_activity(session, limit=2)

    assert len(series) == 2
    assert series[0]["started_at"] < series[1]["started_at"]
    assert list(series[0]["severity_counts"].keys()) == SEVERITY_ORDER
    assert series[0]["severity_counts"]["critical"] == 1
    assert series[1]["severity_counts"]["high"] == 2
    assert series[1]["total_findings"] == 3


def test_line_chart_points_and_max_scan_total_handle_empty_and_non_empty_series():
    series = [
        {"total_findings": 0},
        {"total_findings": 5},
        {"total_findings": 10},
    ]

    assert line_chart_points([]) == ""
    assert max_scan_total([]) == 0
    assert line_chart_points(series, width=100, height=50, padding=10) == "10.0,40.0 50.0,25.0 90.0,10.0"
    assert max_scan_total(series) == 10


def test_latest_software_inventory_returns_latest_records_and_applies_name_filter(tmp_path):
    config = build_test_config(tmp_path)
    init_database(config.database_url)

    with session_scope(config.database_url) as session:
        host = Host(hostname="lab-host", os_family="linux", os_version="test", architecture="x86_64", metadata_json={})
        session.add(host)
        session.flush()
        old_scan = Scan(host_id=host.id, os_family="linux", status="completed")
        new_scan = Scan(host_id=host.id, os_family="linux", status="completed")
        session.add_all([old_scan, new_scan])
        session.flush()
        old_created_at = datetime(2026, 3, 15, 12, 0, tzinfo=timezone.utc)
        new_created_at = datetime(2026, 3, 16, 12, 0, tzinfo=timezone.utc)
        session.add(
            Evidence(
                host_id=host.id,
                scan_id=old_scan.id,
                finding_id=None,
                collector_name="software",
                record_type="collector_result",
                created_at=old_created_at,
                payload_json={"records": [{"name": "curl", "version": "8.4.0", "hash": "old"}]},
            )
        )
        session.add(
            Evidence(
                host_id=host.id,
                scan_id=new_scan.id,
                finding_id=None,
                collector_name="software",
                record_type="collector_result",
                created_at=new_created_at,
                payload_json={
                    "records": [
                        {"name": "openssl", "version": "3.0.2", "hash": "2"},
                        {"name": "curl", "version": "8.5.0", "hash": "1"},
                    ]
                },
            )
        )

    with session_scope(config.database_url) as session:
        inventory = latest_software_inventory(session)
        filtered = latest_software_inventory(session, name_filter="ssl")

    assert [item["name"] for item in inventory] == ["curl", "openssl"]
    assert inventory[0]["version"] == "8.5.0"
    assert len(filtered) == 1
    assert filtered[0]["name"] == "openssl"
