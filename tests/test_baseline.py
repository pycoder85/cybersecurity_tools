from pathlib import Path

from driftwatch.app.core.config import AppConfig
from driftwatch.app.models.entities import Host
from driftwatch.app.services.baseline import create_baseline, diff_baseline, extract_baseline_items
from driftwatch.app.services.database import init_database, session_scope


def build_test_config(tmp_path: Path) -> AppConfig:
    return AppConfig(data_dir=tmp_path, database_url=f"sqlite:///{tmp_path / 'test.db'}")


def test_extract_baseline_items_only_keeps_supported_records():
    snapshot = {
        "collectors": {
            "persistence": {
                "records": [
                    {"path": "/etc/systemd/system/demo.service", "command": "/usr/bin/demo"},
                    {"name": "Demo LaunchAgent", "command": "/Applications/Demo.app"},
                ]
            },
            "filesystem": {
                "records": [
                    {"category": "authorized_keys", "path": "/home/demo/.ssh/authorized_keys", "content": "ssh-ed25519 AAA"},
                    {"category": "startup_file", "path": "/etc/profile.d/demo.sh", "sha256": "abc123"},
                    {"category": "web_root", "path": "/var/www/html/index.php"},
                ]
            },
        }
    }

    items = extract_baseline_items(snapshot)

    assert len(items) == 4
    assert {item["baseline_type"] for item in items} == {"persistence_entry", "authorized_key", "startup_file"}
    assert {item["item_key"] for item in items} >= {
        "/etc/systemd/system/demo.service",
        "Demo LaunchAgent",
        "/home/demo/.ssh/authorized_keys",
        "/etc/profile.d/demo.sh",
    }


def test_create_and_diff_baseline_detects_new_modified_and_removed_items(tmp_path):
    config = build_test_config(tmp_path)
    init_database(config.database_url)

    baseline_snapshot = {
        "collectors": {
            "persistence": {
                "records": [
                    {"path": "/etc/systemd/system/demo.service", "command": "/usr/bin/demo"}
                ]
            },
            "filesystem": {
                "records": [
                    {"category": "authorized_keys", "path": "/home/demo/.ssh/authorized_keys", "content": "ssh-ed25519 AAA"},
                    {"category": "startup_file", "path": "/etc/profile.d/demo.sh", "sha256": "old-hash"},
                ]
            },
        }
    }
    changed_snapshot = {
        "collectors": {
            "persistence": {
                "records": [
                    {"path": "/etc/systemd/system/demo.service", "command": "/tmp/demo"}
                ]
            },
            "filesystem": {
                "records": [
                    {"category": "startup_file", "path": "/etc/profile.d/demo.sh", "sha256": "old-hash"},
                    {"category": "startup_file", "path": "/etc/cron.daily/demo", "sha256": "new-hash"},
                ]
            },
        }
    }

    with session_scope(config.database_url) as session:
        host = Host(hostname="baseline-host", os_family="linux")
        session.add(host)
        session.flush()
        host_id = host.id
        assert create_baseline(session, host_id, baseline_snapshot) == 3

    with session_scope(config.database_url) as session:
        drift = diff_baseline(session, host_id, changed_snapshot)

    assert {
        (item["change"], item["baseline_type"], item["item_key"])
        for item in drift
    } == {
        ("modified", "persistence_entry", "/etc/systemd/system/demo.service"),
        ("new", "startup_file", "/etc/cron.daily/demo"),
        ("removed", "authorized_key", "/home/demo/.ssh/authorized_keys"),
    }

    modified_item = next(item for item in drift if item["change"] == "modified")
    assert modified_item["baseline_hash"] != modified_item["current_hash"]
