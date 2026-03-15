from __future__ import annotations

from driftwatch.app.models.entities import Finding


class NoOpExplainer:
    provider = "none"

    def explain(self, finding: Finding) -> str:
        return (
            "Deterministic rule match only. Review the evidence, validate whether the activity maps to an expected "
            "admin task, then decide whether to update the baseline or investigate further."
        )


def get_explainer(provider: str):
    return NoOpExplainer()
