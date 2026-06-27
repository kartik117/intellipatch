from intellipatch.models.schemas import Finding
from intellipatch.ranking.features import FEATURE_NAMES, feature_vector


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


def test_feature_vector_length_matches_names():
    vec = feature_vector(_finding())
    assert len(vec) == len(FEATURE_NAMES)


def test_network_exploitable_finding_has_expected_features():
    vec = feature_vector(_finding())
    as_dict = dict(zip(FEATURE_NAMES, vec))
    assert as_dict["cvss_score"] == 7.5
    assert as_dict["is_network_exploitable"] == 1.0
    assert as_dict["has_fix"] == 1.0


def test_finding_with_no_cvss_vector_defaults_to_zero_exploitability():
    vec = feature_vector(_finding(cvss_vector=None))
    as_dict = dict(zip(FEATURE_NAMES, vec))
    assert as_dict["is_network_exploitable"] == 0.0
    assert as_dict["requires_no_privileges"] == 0.0


def test_finding_with_no_fix_has_zero_has_fix_feature():
    vec = feature_vector(_finding(fixed_version=None))
    as_dict = dict(zip(FEATURE_NAMES, vec))
    assert as_dict["has_fix"] == 0.0
