"""Trains the exploitability-ranking model on real Trivy scan data.

Run with: python -m intellipatch.ranking.train (from the repo root)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error, r2_score
from sklearn.model_selection import train_test_split

from intellipatch.config import settings
from intellipatch.ranking.dataset import build_dataset
from intellipatch.ranking.features import FEATURE_NAMES

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MODEL_PATH = Path(settings.model_path)
METRICS_PATH = Path(settings.metrics_path)


def main() -> None:
    X, y = build_dataset()
    logger.info("loaded %d real findings from data/raw_trivy_scans", len(X))

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestRegressor(n_estimators=200, max_depth=8, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    metrics = {
        "r2": round(r2_score(y_test, y_pred), 4),
        "mae": round(mean_absolute_error(y_test, y_pred), 4),
        "n_train": len(X_train),
        "n_test": len(X_test),
        "feature_importances": dict(
            zip(FEATURE_NAMES, [round(v, 4) for v in model.feature_importances_])
        ),
    }

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2) + "\n")

    logger.info("wrote %s", MODEL_PATH)
    logger.info("metrics: %s", json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
