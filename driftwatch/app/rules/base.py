from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class FindingDraft:
    category: str
    severity: str
    title: str
    description: str
    evidence: dict
    rule_name: str
    os_family: str
    source_module: str
    confidence: str = "medium"
    suggested_action: str = (
        "Review the evidence, validate whether the item belongs on the host, and consider a manual quarantine step."
    )


@dataclass(slots=True)
class RuleDefinition:
    name: str
    description: str
    category: str
    supported_os: set[str]
    severity_hint: str

    def applies_to(self, os_family: str) -> bool:
        return os_family in self.supported_os
