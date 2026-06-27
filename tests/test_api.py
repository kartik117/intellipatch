import intellipatch.services.api.main as api_main
from fastapi.testclient import TestClient

from intellipatch.models.schemas import Finding
from intellipatch.ranking.ranker import Ranker


class _StubModel:
    def predict(self, X):
        return [row[0] for row in X]


def _fake_findings(image):
    return [
        Finding(
            cve_id="CVE-2024-0001",
            image=image,
            pkg_name="libfoo",
            installed_version="1.0",
            fixed_version="1.1",
            severity="HIGH",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
        Finding(
            cve_id="CVE-2024-0002",
            image=image,
            pkg_name="libbar",
            installed_version="2.0",
            fixed_version=None,
            severity="CRITICAL",
            cvss_score=9.5,
        ),
    ]


def test_health():
    client = TestClient(api_main.app)
    assert client.get("/health").json() == {"status": "ok"}


def test_create_scan_persists_and_returns_summary(monkeypatch, session_factory):
    monkeypatch.setattr(api_main, "SessionLocal", session_factory)
    monkeypatch.setattr(api_main, "run_scan", _fake_findings)
    monkeypatch.setattr(api_main, "_ranker", Ranker(_StubModel()))

    client = TestClient(api_main.app)
    response = client.post("/scans", json={"image": "test:latest"})

    assert response.status_code == 201
    body = response.json()
    assert body["image"] == "test:latest"
    assert body["finding_count"] == 2


def test_get_scan_findings_are_ranked(monkeypatch, session_factory):
    monkeypatch.setattr(api_main, "SessionLocal", session_factory)
    monkeypatch.setattr(api_main, "run_scan", _fake_findings)
    monkeypatch.setattr(api_main, "_ranker", Ranker(_StubModel()))

    client = TestClient(api_main.app)
    scan_id = client.post("/scans", json={"image": "test:latest"}).json()["scan_id"]

    findings = client.get(f"/scans/{scan_id}/findings").json()
    assert len(findings) == 2
    # _StubModel predicts cvss_score back out, so the 9.5-score finding ranks first.
    assert findings[0]["cve_id"] == "CVE-2024-0002"
    assert findings[0]["rank"] == 1


def test_get_unknown_scan_is_404(monkeypatch, session_factory):
    monkeypatch.setattr(api_main, "SessionLocal", session_factory)
    client = TestClient(api_main.app)
    response = client.get("/scans/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404


def test_remediation_endpoint_returns_a_report(monkeypatch, session_factory):
    monkeypatch.setattr(api_main, "SessionLocal", session_factory)
    monkeypatch.setattr(api_main, "run_scan", _fake_findings)
    monkeypatch.setattr(api_main, "_ranker", Ranker(_StubModel()))

    client = TestClient(api_main.app)
    findings = client.post("/scans", json={"image": "test:latest"})
    scan_id = findings.json()["scan_id"]
    finding_id = client.get(f"/scans/{scan_id}/findings").json()[0]["finding_id"]

    response = client.get(f"/findings/{finding_id}/remediation")
    assert response.status_code == 200
    assert "libbar" in response.json()["message"] or "libfoo" in response.json()["message"]
