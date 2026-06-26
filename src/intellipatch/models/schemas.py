from __future__ import annotations

from pydantic import BaseModel


class CvssVector:
    """Parsed CVSS v3.x base vector. Real sub-metrics extracted from the
    vector string Trivy reports (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/
    C:H/I:H/A:H"), not invented -- this is what lets the ranking model
    tell "exploitable over the network with no auth" apart from "same
    CVSS score but needs local shell access" instead of treating every
    7.0 the same way.
    """

    def __init__(self, vector: str) -> None:
        self.raw = vector
        parts = dict(p.split(":") for p in vector.split("/") if ":" in p)
        self.attack_vector = parts.get("AV", "U")
        self.attack_complexity = parts.get("AC", "U")
        self.privileges_required = parts.get("PR", "U")
        self.user_interaction = parts.get("UI", "U")
        self.scope = parts.get("S", "U")
        self.confidentiality = parts.get("C", "N")
        self.integrity = parts.get("I", "N")
        self.availability = parts.get("A", "N")

    @property
    def is_network_exploitable(self) -> bool:
        return self.attack_vector == "N"

    @property
    def is_low_complexity(self) -> bool:
        return self.attack_complexity == "L"

    @property
    def requires_no_privileges(self) -> bool:
        return self.privileges_required == "N"

    @property
    def requires_no_user_interaction(self) -> bool:
        return self.user_interaction == "N"


class Finding(BaseModel):
    cve_id: str
    image: str
    pkg_name: str
    installed_version: str
    fixed_version: str | None = None
    severity: str
    cvss_score: float | None = None
    cvss_vector: str | None = None
    title: str = ""

    @property
    def has_fix(self) -> bool:
        return bool(self.fixed_version)


class RankedFinding(BaseModel):
    finding: Finding
    priority_score: float
    rank: int


class RemediationReport(BaseModel):
    cve_id: str
    pkg_name: str
    message: str
    llm_enhanced: bool
