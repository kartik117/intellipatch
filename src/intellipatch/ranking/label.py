"""Defines the training target: a documented heuristic, not ground
truth. No dataset of "this CVE was actually exploited against this
image in production" exists for me to train against, so the model's
target is a transparent formula instead of a black-box label -- anyone
reading this can verify exactly what the model is learning to predict,
and swap in real incident data later without touching anything else in
this package.

priority_score (0-100) = 60% from raw CVSS severity, 40% from how easy
the CVE is to actually trigger (network-reachable, low complexity, no
privileges, no user interaction needed). Two CVEs with the same CVSS
score don't pose the same real-world risk -- one exploitable over the
network with no auth is a very different problem from the same score
requiring local shell access -- and raw CVSS alone can't tell them
apart, which is the entire reason this project ranks by more than CVSS.
"""

from __future__ import annotations

from intellipatch.models.schemas import CvssVector, Finding

CVSS_WEIGHT = 0.6
EXPLOITABILITY_WEIGHT = 0.4


def priority_label(finding: Finding) -> float:
    # cvss_score is 0-10; scale to 0-100 before weighting.
    cvss_component = (finding.cvss_score or 0.0) * 10 * CVSS_WEIGHT

    if finding.cvss_vector:
        vector = CvssVector(finding.cvss_vector)
        factors = [
            vector.is_network_exploitable,
            vector.is_low_complexity,
            vector.requires_no_privileges,
            vector.requires_no_user_interaction,
        ]
        exploitability_fraction = sum(factors) / len(factors)
    else:
        exploitability_fraction = 0.0

    exploitability_component = exploitability_fraction * 100 * EXPLOITABILITY_WEIGHT

    return round(min(100.0, cvss_component + exploitability_component), 2)
