import json
from pathlib import Path

from driftwatch.app.cli import main
from driftwatch.app.core.config import AppConfig
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
