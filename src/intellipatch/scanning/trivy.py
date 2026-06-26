"""Runs Trivy and parses its JSON report into Finding objects.

parse_trivy_report is split out from run_scan so the same parser works
on a live `trivy image` invocation and on the raw JSON files in
data/raw_trivy_scans/ used to build the training dataset -- one code
path, not two slightly-different ones to keep in sync.
"""

from __future__ import annotations

import json
import logging
import subprocess

from intellipatch.config import settings
from intellipatch.models.schemas import Finding

logger = logging.getLogger(__name__)


class ScanError(Exception):
    pass


def parse_trivy_report(report: dict, image: str) -> list[Finding]:
    findings: list[Finding] = []
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cvss = vuln.get("CVSS", {})
            # Prefer NVD's vector when available; it's the most
            # consistently populated source across the scans this
            # project's model was trained on.
            source = cvss.get("nvd") or next(iter(cvss.values()), {})
            findings.append(
                Finding(
                    cve_id=vuln["VulnerabilityID"],
                    image=image,
                    pkg_name=vuln.get("PkgName", "unknown"),
                    installed_version=vuln.get("InstalledVersion", "unknown"),
                    fixed_version=vuln.get("FixedVersion") or None,
                    severity=vuln.get("Severity", "UNKNOWN"),
                    cvss_score=source.get("V3Score"),
                    cvss_vector=source.get("V3Vector"),
                    title=vuln.get("Title", ""),
                )
            )
    return findings


def run_scan(image: str) -> list[Finding]:
    cmd = [
        settings.trivy_binary,
        "image",
        "--format",
        "json",
        "--severity",
        "LOW,MEDIUM,HIGH,CRITICAL",
        "--scanners",
        "vuln",
        image,
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=settings.trivy_timeout_seconds, check=True
        )
    except subprocess.CalledProcessError as exc:
        raise ScanError(f"trivy exited {exc.returncode}: {exc.stderr}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"trivy scan of {image} timed out") from exc

    report = json.loads(result.stdout)
    return parse_trivy_report(report, image)
