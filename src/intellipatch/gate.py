"""CI/CD gate: scan an image, rank findings by exploitability, and
block the build if any finding with no fix available is at or above
the priority threshold -- a finding with a fix is "upgrade the
package," not a deploy blocker; one with no fix and a high priority
score is the one that actually needs a human decision before shipping.

Usage: python -m intellipatch.gate <image> [--threshold 70]
"""

from __future__ import annotations

import argparse
import sys

from intellipatch.config import settings
from intellipatch.models.schemas import RankedFinding
from intellipatch.ranking.ranker import Ranker
from intellipatch.scanning.trivy import run_scan


def blocking_findings(ranked: list[RankedFinding], threshold: float) -> list[RankedFinding]:
    return [r for r in ranked if not r.finding.has_fix and r.priority_score >= threshold]


def evaluate(image: str, threshold: float, ranker: Ranker | None = None) -> tuple[list[RankedFinding], list[RankedFinding]]:
    findings = run_scan(image)
    ranked = (ranker or Ranker.load()).rank(findings)
    return ranked, blocking_findings(ranked, threshold)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--threshold", type=float, default=settings.gate_priority_threshold)
    args = parser.parse_args()

    ranked, blocking = evaluate(args.image, args.threshold)

    print(f"scanned {args.image}: {len(ranked)} findings, top 10 by priority:")
    for item in ranked[:10]:
        fix_note = f"fix: {item.finding.fixed_version}" if item.finding.has_fix else "NO FIX AVAILABLE"
        print(f"  [{item.priority_score:5.1f}] {item.finding.cve_id} {item.finding.pkg_name} ({fix_note})")

    if blocking:
        print(f"\nGATE FAILED: {len(blocking)} finding(s) at/above priority {args.threshold} with no fix available:")
        for item in blocking:
            print(f"  - {item.finding.cve_id} {item.finding.pkg_name} (priority {item.priority_score})")
        sys.exit(1)

    print(f"\nGATE PASSED: no unresolved finding at/above priority {args.threshold}")
    sys.exit(0)


if __name__ == "__main__":
    main()
