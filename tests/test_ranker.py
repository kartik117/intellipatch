from intellipatch.models.schemas import Finding
from intellipatch.ranking.ranker import Ranker


def _finding(cve_id, **overrides):
    base = dict(
        cve_id=cve_id,
        image="test:latest",
        pkg_name="libfoo",
        installed_version="1.0",
        fixed_version=None,
        severity="HIGH",
        cvss_score=5.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    base.update(overrides)
    return Finding(**base)


class _StubModel:
    """Predicts the cvss_score back out (feature index 0) -- isolates
    the ranker's sort/rank wiring from whatever the real model predicts.
    """

    def predict(self, X):
        return [row[0] for row in X]


def test_empty_input_returns_empty_list():
    ranker = Ranker(_StubModel())
    assert ranker.rank([]) == []


def test_higher_score_ranks_first():
    ranker = Ranker(_StubModel())
    low = _finding("CVE-1", cvss_score=2.0)
    high = _finding("CVE-2", cvss_score=9.0)

    ranked = ranker.rank([low, high])

    assert ranked[0].finding.cve_id == "CVE-2"
    assert ranked[0].rank == 1
    assert ranked[1].finding.cve_id == "CVE-1"
    assert ranked[1].rank == 2


def test_real_trained_model_ranks_network_exploitable_above_local_at_same_cvss():
    ranker = Ranker.load()
    network = _finding(
        "CVE-NET", cvss_score=7.0, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    local = _finding(
        "CVE-LOCAL", cvss_score=7.0, cvss_vector="CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H"
    )

    ranked = ranker.rank([local, network])

    assert ranked[0].finding.cve_id == "CVE-NET"
