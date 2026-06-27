from intellipatch.models.schemas import Finding, RankedFinding
from intellipatch.storage.repository import ScanRepository


def _ranked(cve_id, rank):
    finding = Finding(
        cve_id=cve_id,
        image="test:latest",
        pkg_name="libfoo",
        installed_version="1.0",
        fixed_version="1.1",
        severity="HIGH",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    return RankedFinding(finding=finding, priority_score=80.0 - rank, rank=rank)


def test_create_persists_scan_and_findings(session_factory):
    ranked = [_ranked("CVE-1", 1), _ranked("CVE-2", 2)]

    with session_factory() as session:
        scan = ScanRepository(session).create(image="test:latest", ranked=ranked)
        scan_id = scan.id
        assert scan.finding_count == 2

    with session_factory() as session:
        repo = ScanRepository(session)
        fetched = repo.get(scan_id)
        assert fetched is not None
        assert fetched.image == "test:latest"

        findings = repo.findings(scan_id)
        assert [f.cve_id for f in findings] == ["CVE-1", "CVE-2"]


def test_get_unknown_scan_returns_none(session_factory):
    import uuid

    with session_factory() as session:
        assert ScanRepository(session).get(uuid.uuid4()) is None
