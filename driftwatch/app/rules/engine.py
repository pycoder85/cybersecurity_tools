from __future__ import annotations

from collections import defaultdict

from driftwatch.app.rules.builtin import RULE_REGISTRY
from driftwatch.app.rules.base import FindingDraft


def evaluate_rules(snapshot: dict, os_family: str) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for definition, evaluator in RULE_REGISTRY:
        if not definition.applies_to(os_family):
            continue
        findings.extend(evaluator(snapshot, os_family))
    return findings


def rule_coverage() -> dict[str, list[dict]]:
    coverage: dict[str, list[dict]] = defaultdict(list)
    for definition, _ in RULE_REGISTRY:
        for os_family in definition.supported_os:
            coverage[os_family].append(
                {
                    "name": definition.name,
                    "category": definition.category,
                    "severity_hint": definition.severity_hint,
                    "description": definition.description,
                }
            )
    return dict(coverage)
