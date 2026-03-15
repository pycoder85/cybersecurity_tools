from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utcnow_iso() -> str:
    return utcnow().isoformat()


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def stable_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def parse_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def safe_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, indent=2, default=str)


def chunked(items: Iterable[Any], size: int) -> list[list[Any]]:
    chunk: list[Any] = []
    rows: list[list[Any]] = []
    for item in items:
        chunk.append(item)
        if len(chunk) >= size:
            rows.append(chunk)
            chunk = []
    if chunk:
        rows.append(chunk)
    return rows
