import pytest

from intellipatch.models.schemas import Finding
from intellipatch.remediation import llm as llm_module
from intellipatch.remediation.report import build_report


@pytest.fixture(autouse=True)
def _reset_llm_client():
    llm_module.reset_for_test()
    yield
    llm_module.reset_for_test()


def _finding(**overrides):
    base = dict(
        cve_id="CVE-2024-0001",
        image="test:latest",
        pkg_name="libfoo",
        installed_version="1.0",
        fixed_version="1.1",
        severity="HIGH",
        cvss_score=7.5,
    )
    base.update(overrides)
    return Finding(**base)


def test_report_with_fix_recommends_upgrade(monkeypatch):
    monkeypatch.setattr(llm_module.settings, "google_api_key", "")
    report = build_report(_finding())

    assert "Upgrade libfoo from 1.0 to 1.1" in report.message
    assert report.llm_enhanced is False


def test_report_without_fix_recommends_compensating_control(monkeypatch):
    monkeypatch.setattr(llm_module.settings, "google_api_key", "")
    report = build_report(_finding(fixed_version=None))

    assert "No fixed version is published yet" in report.message
    assert "compensating control" in report.message
    assert report.llm_enhanced is False


def test_report_works_without_an_api_key_configured(monkeypatch):
    monkeypatch.setattr(llm_module.settings, "google_api_key", "")
    report = build_report(_finding())
    assert report.cve_id == "CVE-2024-0001"
    assert report.pkg_name == "libfoo"
