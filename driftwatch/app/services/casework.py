from __future__ import annotations

from sqlalchemy.orm import Session

from driftwatch.app.models.entities import Finding, FindingNote


ALLOWED_FINDING_STATUSES = {"open", "investigating", "resolved"}


def update_finding_status(session: Session, finding_id: str, status: str) -> Finding | None:
    if status not in ALLOWED_FINDING_STATUSES:
        raise ValueError(f"Unsupported finding status: {status}")
    finding = session.get(Finding, finding_id)
    if finding is None:
        return None
    finding.status = status
    return finding


def add_finding_note(
    session: Session,
    finding_id: str,
    note_text: str,
    author: str = "local-analyst",
) -> FindingNote | None:
    finding = session.get(Finding, finding_id)
    if finding is None:
        return None
    cleaned = note_text.strip()
    if not cleaned:
        raise ValueError("Note text cannot be empty")
    note = FindingNote(finding_id=finding_id, author=author.strip() or "local-analyst", note_text=cleaned)
    session.add(note)
    session.flush()
    return note
