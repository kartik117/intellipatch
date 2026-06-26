from __future__ import annotations

import logging

from intellipatch.models.schemas import Finding, RemediationReport
from intellipatch.remediation.llm import get_llm_client

logger = logging.getLogger(__name__)


def _deterministic_message(finding: Finding) -> str:
    if finding.has_fix:
        return (
            f"Upgrade {finding.pkg_name} from {finding.installed_version} to "
            f"{finding.fixed_version} to resolve {finding.cve_id} ({finding.severity})."
        )
    return (
        f"No fixed version is published yet for {finding.cve_id} in {finding.pkg_name} "
        f"{finding.installed_version} ({finding.severity}). Track upstream for a patch; "
        "consider a compensating control (network policy, WAF rule, or removing the "
        "package if unused) in the meantime."
    )


def build_report(finding: Finding) -> RemediationReport:
    message = _deterministic_message(finding)
    llm_enhanced = False

    client = get_llm_client()
    if client is not None:
        try:
            response = client.invoke(
                "In one or two sentences for a developer fixing this, expand on this "
                f"remediation note without restating it verbatim: {message}\n\n"
                f"Context: {finding.title}"
            )
            explanation = (response.content or "").strip()
            if explanation:
                message = f"{message} {explanation}"
                llm_enhanced = True
        except Exception:
            logger.exception("LLM remediation enhancement failed; keeping the deterministic message")

    return RemediationReport(
        cve_id=finding.cve_id, pkg_name=finding.pkg_name, message=message, llm_enhanced=llm_enhanced
    )
