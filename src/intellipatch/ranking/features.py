from __future__ import annotations

from intellipatch.models.schemas import CvssVector, Finding

FEATURE_NAMES = (
    "cvss_score",
    "is_network_exploitable",
    "is_low_complexity",
    "requires_no_privileges",
    "requires_no_user_interaction",
    "severity_rank",
    "has_fix",
)

_SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def feature_vector(finding: Finding) -> list[float]:
    cvss = CvssVector(finding.cvss_vector) if finding.cvss_vector else None
    return [
        finding.cvss_score or 0.0,
        float(cvss.is_network_exploitable) if cvss else 0.0,
        float(cvss.is_low_complexity) if cvss else 0.0,
        float(cvss.requires_no_privileges) if cvss else 0.0,
        float(cvss.requires_no_user_interaction) if cvss else 0.0,
        float(_SEVERITY_RANK.get(finding.severity, 0)),
        float(finding.has_fix),
    ]
