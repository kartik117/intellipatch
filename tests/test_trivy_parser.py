import json
from pathlib import Path

from intellipatch.scanning.trivy import parse_trivy_report

RAW_SCANS_DIR = Path(__file__).resolve().parents[1] / "data" / "raw_trivy_scans"


def test_parses_real_ubuntu_scan():
    report = json.loads((RAW_SCANS_DIR / "ubuntu_20.04.json").read_text())
    findings = parse_trivy_report(report, "ubuntu:20.04")

    assert len(findings) >= 1
    assert all(f.cve_id.startswith("CVE-") for f in findings)
    assert all(f.image == "ubuntu:20.04" for f in findings)


def test_parses_real_python_scan_and_finds_known_cve_fields():
    report = json.loads((RAW_SCANS_DIR / "python_3.9-slim.json").read_text())
    findings = parse_trivy_report(report, "python:3.9-slim")

    assert len(findings) > 50
    with_cvss = [f for f in findings if f.cvss_score is not None]
    assert len(with_cvss) > 0
    assert all(0.0 <= f.cvss_score <= 10.0 for f in with_cvss)


def test_finding_with_no_fixed_version_has_fix_is_false():
    report = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-9999",
                        "PkgName": "libfoo",
                        "InstalledVersion": "1.0",
                        "Severity": "HIGH",
                    }
                ]
            }
        ]
    }
    findings = parse_trivy_report(report, "test:latest")
    assert len(findings) == 1
    assert findings[0].has_fix is False
    assert findings[0].cvss_score is None


def test_report_with_no_results_returns_empty_list():
    assert parse_trivy_report({}, "test:latest") == []
