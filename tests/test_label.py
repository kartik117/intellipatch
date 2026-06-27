from intellipatch.models.schemas import Finding
from intellipatch.ranking.label import priority_label


def _finding(**overrides):
    base = dict(
        cve_id="CVE-2024-0001",
        image="test:latest",
        pkg_name="libfoo",
        installed_version="1.0",
        fixed_version="1.1",
        severity="HIGH",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    base.update(overrides)
    return Finding(**base)


def test_max_cvss_and_full_exploitability_gives_max_label():
    finding = _finding(cvss_score=10.0, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert priority_label(finding) == 100.0


def test_zero_cvss_and_no_exploitability_gives_zero_label():
    finding = _finding(
        cvss_score=0.0, cvss_vector="CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"
    )
    assert priority_label(finding) == 0.0


def test_missing_cvss_data_does_not_crash():
    finding = _finding(cvss_score=None, cvss_vector=None)
    assert priority_label(finding) == 0.0


def test_label_is_bounded_between_zero_and_hundred():
    finding = _finding(cvss_score=10.0)
    assert 0.0 <= priority_label(finding) <= 100.0


def test_higher_cvss_never_produces_a_lower_label_at_equal_exploitability():
    low = _finding(cvss_score=3.0)
    high = _finding(cvss_score=9.0)
    assert priority_label(high) > priority_label(low)
