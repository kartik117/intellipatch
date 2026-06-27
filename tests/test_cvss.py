from intellipatch.models.schemas import CvssVector


def test_network_exploitable_no_privileges_no_interaction():
    v = CvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert v.is_network_exploitable
    assert v.is_low_complexity
    assert v.requires_no_privileges
    assert v.requires_no_user_interaction


def test_local_high_complexity_vector():
    v = CvssVector("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H")
    assert not v.is_network_exploitable
    assert not v.is_low_complexity
    assert not v.requires_no_privileges
    assert not v.requires_no_user_interaction


def test_missing_components_default_safe():
    v = CvssVector("CVSS:3.1/S:U/C:H/I:H/A:H")
    assert not v.is_network_exploitable
    assert not v.is_low_complexity
