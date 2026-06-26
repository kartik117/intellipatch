from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib

from intellipatch.config import settings
from intellipatch.models.schemas import Finding, RankedFinding
from intellipatch.ranking.features import feature_vector


class Ranker:
    """Wraps the trained model. Injected so tests can pass a stub
    instead of loading the real joblib artifact from disk.
    """

    def __init__(self, model: Any) -> None:
        self._model = model

    @classmethod
    def load(cls, model_path: Path | None = None) -> Ranker:
        return cls(joblib.load(model_path or Path(settings.model_path)))

    def rank(self, findings: list[Finding]) -> list[RankedFinding]:
        if not findings:
            return []

        scores = self._model.predict([feature_vector(f) for f in findings])
        ordered = sorted(zip(findings, scores), key=lambda pair: pair[1], reverse=True)
        return [
            RankedFinding(finding=finding, priority_score=round(float(score), 2), rank=i + 1)
            for i, (finding, score) in enumerate(ordered)
        ]
