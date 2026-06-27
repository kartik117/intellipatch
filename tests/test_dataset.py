from intellipatch.ranking.dataset import build_dataset, load_real_findings


def test_loads_real_findings_from_all_five_scans():
    findings = load_real_findings()
    images = {f.image for f in findings}
    assert len(findings) > 1000
    assert images == {
        "nginx:1.18",
        "node:14-slim",
        "python:3.9-slim",
        "redis:6.0",
        "ubuntu:20.04",
    }


def test_build_dataset_shapes_match():
    X, y = build_dataset()
    assert len(X) == len(y)
    assert all(len(row) == 7 for row in X)
    assert all(0.0 <= label <= 100.0 for label in y)
