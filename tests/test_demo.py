from pathlib import Path

from driftwatch.app.core.config import AppConfig
from driftwatch.app.models.entities import DemoMarker, Finding, Host, Scan
from driftwatch.app.services.database import session_scope
from driftwatch.app.services.demo import seed_demo_data


def build_test_config(tmp_path: Path) -> AppConfig:
    return AppConfig(data_dir=tmp_path, database_url=f"sqlite:///{tmp_path / 'test.db'}")


def test_seed_demo_data_is_idempotent(tmp_path):
    config = build_test_config(tmp_path)

    seed_demo_data(config)
    seed_demo_data(config)

    with session_scope(config.database_url) as session:
        assert session.query(Host).count() == 1
        assert session.query(Scan).count() == 3
        assert session.query(Finding).count() == 3
        assert session.query(DemoMarker).count() == 1
