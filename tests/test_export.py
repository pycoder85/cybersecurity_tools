import json
from pathlib import Path

from driftwatch.app.cli import main
from driftwatch.app.core.config import AppConfig
from driftwatch.app.models.entities import Host, Scan
from driftwatch.app.services.database import session_scope
from driftwatch.app.services.demo import seed_demo_data


def test_export_findings_json_file(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    output_path = tmp_path / "findings.json"
    config = AppConfig(data_dir=data_dir, database_url=f"sqlite:///{data_dir / 'driftwatch.db'}")
    seed_demo_data(config)
    monkeypatch.setenv("DRIFTWATCH_HOME", str(data_dir))

    exit_code = main(["export", "findings", "--format", "json", "--output", str(output_path)])

    assert exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload
    assert payload[0]["rule_name"]
    assert payload[0]["title"]


def test_export_scans_csv_file(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    output_path = tmp_path / "scans.csv"
    config = AppConfig(data_dir=data_dir, database_url=f"sqlite:///{data_dir / 'driftwatch.db'}")
    seed_demo_data(config)
    monkeypatch.setenv("DRIFTWATCH_HOME", str(data_dir))

    exit_code = main(["export", "scans", "--format", "csv", "--output", str(output_path)])

    assert exit_code == 0
    content = output_path.read_text(encoding="utf-8")
    assert "started_at" in content
    assert "summary_json" in content


def test_export_findings_json_file_applies_filters(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    output_path = tmp_path / "critical-findings.json"
    config = AppConfig(data_dir=data_dir, database_url=f"sqlite:///{data_dir / 'driftwatch.db'}")
    seed_demo_data(config)
    monkeypatch.setenv("DRIFTWATCH_HOME", str(data_dir))

    exit_code = main(
        [
            "export",
            "findings",
            "--format",
            "json",
            "--severity",
            "critical",
            "--category",
            "Unauthorized key or startup file changes",
            "--status",
            "open",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(payload) == 1
    assert payload[0]["severity"] == "critical"
    assert payload[0]["category"] == "Unauthorized key or startup file changes"
    assert payload[0]["status"] == "open"


def test_export_scans_csv_file_applies_filters(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    output_path = tmp_path / "failed-windows-scans.csv"
    config = AppConfig(data_dir=data_dir, database_url=f"sqlite:///{data_dir / 'driftwatch.db'}")
    seed_demo_data(config)
    with session_scope(config.database_url) as session:
        host = session.query(Host).first()
        session.add(
            Scan(
                host_id=host.id,
                os_family="windows",
                status="failed",
                summary_json={"total_findings": 0, "severity_counts": {}},
            )
        )
    monkeypatch.setenv("DRIFTWATCH_HOME", str(data_dir))

    exit_code = main(
        [
            "export",
            "scans",
            "--format",
            "csv",
            "--status",
            "failed",
            "--os-family",
            "windows",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    rows = output_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(rows) == 2
    assert "windows" in rows[1]
    assert "failed" in rows[1]


def test_export_evidence_json_file_applies_filters(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    output_path = tmp_path / "evidence.json"
    config = AppConfig(data_dir=data_dir, database_url=f"sqlite:///{data_dir / 'driftwatch.db'}")
    seed_demo_data(config)
    monkeypatch.setenv("DRIFTWATCH_HOME", str(data_dir))

    exit_code = main(
        [
            "export",
            "evidence",
            "--format",
            "json",
            "--collector-name",
            "demo.seed",
            "--record-type",
            "finding_evidence",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload
    assert payload[0]["collector_name"] == "demo.seed"
    assert payload[0]["record_type"] == "finding_evidence"
