from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from driftwatch.app.core.utils import stable_hash
from driftwatch.app.models.entities import BaselineItem


def extract_baseline_items(snapshot: dict) -> list[dict]:
    items: list[dict] = []
    for record in snapshot.get("collectors", {}).get("persistence", {}).get("records", []):
        key = record.get("path") or record.get("name") or record.get("command") or ""
        items.append(
            {
                "baseline_type": "persistence_entry",
                "item_key": key,
                "item_hash": stable_hash(record),
                "data_json": record,
            }
        )
    for record in snapshot.get("collectors", {}).get("filesystem", {}).get("records", []):
        category = record.get("category")
        if category not in {"authorized_keys", "startup_file"}:
            continue
        baseline_type = "authorized_key" if category == "authorized_keys" else "startup_file"
        items.append(
            {
                "baseline_type": baseline_type,
                "item_key": record.get("path") or "",
                "item_hash": stable_hash(record),
                "data_json": record,
            }
        )
    return items


def create_baseline(session: Session, host_id: str, snapshot: dict) -> int:
    items = extract_baseline_items(snapshot)
    session.execute(delete(BaselineItem).where(BaselineItem.host_id == host_id))
    for item in items:
        session.add(BaselineItem(host_id=host_id, **item))
    return len(items)


def diff_baseline(session: Session, host_id: str, snapshot: dict) -> list[dict]:
    current_items = extract_baseline_items(snapshot)
    existing_rows = session.execute(select(BaselineItem).where(BaselineItem.host_id == host_id)).scalars().all()
    existing_map = {(row.baseline_type, row.item_key): row.item_hash for row in existing_rows}
    current_map = {(item["baseline_type"], item["item_key"]): item["item_hash"] for item in current_items}
    drift: list[dict] = []
    for key, item_hash in current_map.items():
        baseline_hash = existing_map.get(key)
        if baseline_hash is None:
            drift.append(
                {
                    "change": "new",
                    "baseline_type": key[0],
                    "item_key": key[1],
                    "current_hash": item_hash,
                }
            )
        elif baseline_hash != item_hash:
            drift.append(
                {
                    "change": "modified",
                    "baseline_type": key[0],
                    "item_key": key[1],
                    "current_hash": item_hash,
                    "baseline_hash": baseline_hash,
                }
            )
    for key, baseline_hash in existing_map.items():
        if key not in current_map:
            drift.append(
                {
                    "change": "removed",
                    "baseline_type": key[0],
                    "item_key": key[1],
                    "baseline_hash": baseline_hash,
                }
            )
    return drift
