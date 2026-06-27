from intellipatch.gate import blocking_findings
from intellipatch.models.schemas import Finding, RankedFinding


def _ranked(cve_id, priority, has_fix, rank=1):
    finding = Finding(
        cve_id=cve_id,
        image="test:latest",
        pkg_name="libfoo",
        installed_version="1.0",
        fixed_version="1.1" if has_fix else None,
        severity="CRITICAL",
        cvss_score=9.0,
    )
    return RankedFinding(finding=finding, priority_score=priority, rank=rank)


def test_high_priority_with_no_fix_blocks():
    ranked = [_ranked("CVE-1", priority=85.0, has_fix=False)]
    assert len(blocking_findings(ranked, threshold=70.0)) == 1


def test_high_priority_with_fix_available_does_not_block():
    ranked = [_ranked("CVE-1", priority=85.0, has_fix=True)]
    assert blocking_findings(ranked, threshold=70.0) == []


def test_low_priority_with_no_fix_does_not_block():
    ranked = [_ranked("CVE-1", priority=40.0, has_fix=False)]
    assert blocking_findings(ranked, threshold=70.0) == []


def test_priority_exactly_at_threshold_blocks():
    ranked = [_ranked("CVE-1", priority=70.0, has_fix=False)]
    assert len(blocking_findings(ranked, threshold=70.0)) == 1


def test_mixed_list_only_blocks_the_qualifying_ones():
    ranked = [
        _ranked("CVE-1", priority=90.0, has_fix=False),
        _ranked("CVE-2", priority=90.0, has_fix=True),
        _ranked("CVE-3", priority=30.0, has_fix=False),
    ]
    blocked = blocking_findings(ranked, threshold=70.0)
    assert [r.finding.cve_id for r in blocked] == ["CVE-1"]
