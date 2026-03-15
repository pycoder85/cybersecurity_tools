from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from driftwatch.app.core.config import default_settings
from driftwatch.app.core.utils import parse_csv
from driftwatch.app.models.entities import Setting


def get_settings(session: Session) -> dict[str, object]:
    settings = default_settings()
    rows = session.execute(select(Setting)).scalars().all()
    for row in rows:
        settings[row.key] = row.value_json
    return settings


def upsert_setting(session: Session, key: str, value: object) -> None:
    row = session.get(Setting, key)
    if row is None:
        row = Setting(key=key, value_json=value)
        session.add(row)
        return
    row.value_json = value


def update_settings_from_form(session: Session, form_data: dict[str, str]) -> None:
    upsert_setting(session, "scan_directories", parse_csv(form_data.get("scan_directories")))
    upsert_setting(session, "scan_exclusions", parse_csv(form_data.get("scan_exclusions")))
    upsert_setting(session, "schedule_interval_minutes", int(form_data.get("schedule_interval_minutes") or 0))
    upsert_setting(session, "llm_provider", form_data.get("llm_provider") or "none")
    upsert_setting(session, "llm_model", form_data.get("llm_model") or "")
    upsert_setting(session, "response_actions_enabled", False)
