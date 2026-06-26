"""Builds the training dataset from real Trivy scans of real public
images (data/raw_trivy_scans/) -- every CVE ID, package, version, and
CVSS vector in the training set is real output from a real `trivy
image` scan of python:3.9-slim, node:14-slim, nginx:1.18, redis:6.0,
and ubuntu:20.04. Only the label (see label.py) is a documented
heuristic, not the underlying CVE data.
"""

from __future__ import annotations

import json
from pathlib import Path

from intellipatch.config import settings
from intellipatch.models.schemas import Finding
from intellipatch.ranking.features import feature_vector
from intellipatch.ranking.label import priority_label
from intellipatch.scanning.trivy import parse_trivy_report

RAW_SCANS_DIR = Path(settings.raw_scans_dir)


def load_real_findings(raw_scans_dir: Path = RAW_SCANS_DIR) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(raw_scans_dir.glob("*.json")):
        image = path.stem.replace("_", ":", 1)
        report = json.loads(path.read_text())
        findings.extend(parse_trivy_report(report, image))
    return findings


def build_dataset(raw_scans_dir: Path = RAW_SCANS_DIR) -> tuple[list[list[float]], list[float]]:
    findings = load_real_findings(raw_scans_dir)
    X = [feature_vector(f) for f in findings]
    y = [priority_label(f) for f in findings]
    return X, y
