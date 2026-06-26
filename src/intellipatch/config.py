from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="INTELLIPATCH_", env_file=".env")

    database_url: str = "postgresql+psycopg://intellipatch:intellipatch@localhost:5432/intellipatch"

    model_path: str = "models/ranking_model.joblib"
    metrics_path: str = "models/metrics.json"
    # Only read at training time, never at inference. Resolved relative
    # to cwd, not __file__ -- a sibling project (PNWater) learned the
    # hard way that Path(__file__).resolve().parents[N] finds the repo
    # root from a source checkout but resolves to somewhere under
    # site-packages once the package is pip install-ed. Run training
    # from the repo root.
    raw_scans_dir: str = "data/raw_trivy_scans"

    trivy_binary: str = "trivy"
    trivy_timeout_seconds: int = 300

    # A finding is "gate-blocking" if its predicted priority score is at
    # or above this threshold AND no fixed version is available --
    # see gate.py. 0-100 scale, see ranking/label.py for how priority is
    # defined.
    gate_priority_threshold: float = 70.0

    # Empty by default: remediation reports fall back to a deterministic
    # templated message when no key is configured (see
    # remediation/llm.py). Never required for the app to start.
    google_api_key: str = ""


settings = Settings()
