from __future__ import annotations

import uuid

from fastapi import FastAPI, HTTPException
from prometheus_client import Counter, make_asgi_app
from pydantic import BaseModel

from intellipatch.models.schemas import Finding
from intellipatch.ranking.ranker import Ranker
from intellipatch.remediation.report import build_report
from intellipatch.scanning.trivy import ScanError, run_scan
from intellipatch.storage.db import SessionLocal
from intellipatch.storage.repository import ScanRepository

app = FastAPI(title="intellipatch-api")
app.mount("/metrics", make_asgi_app())

scans_completed_total = Counter("intellipatch_scans_completed_total", "Image scans completed")
findings_by_severity_total = Counter(
    "intellipatch_findings_by_severity_total", "Findings recorded by severity", ["severity"]
)

_ranker: Ranker | None = None


def _get_ranker() -> Ranker:
    global _ranker
    if _ranker is None:
        _ranker = Ranker.load()
    return _ranker


class ScanRequest(BaseModel):
    image: str


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/scans", status_code=201)
async def create_scan(request: ScanRequest) -> dict:
    try:
        findings = run_scan(request.image)
    except ScanError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    ranked = _get_ranker().rank(findings)

    with SessionLocal() as session:
        scan = ScanRepository(session).create(image=request.image, ranked=ranked)

    scans_completed_total.inc()
    for item in ranked:
        findings_by_severity_total.labels(severity=item.finding.severity).inc()

    return {"scan_id": str(scan.id), "image": scan.image, "finding_count": scan.finding_count}


@app.get("/scans/{scan_id}")
async def get_scan(scan_id: uuid.UUID) -> dict:
    with SessionLocal() as session:
        scan = ScanRepository(session).get(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return {
            "scan_id": str(scan.id),
            "image": scan.image,
            "finding_count": scan.finding_count,
            "created_at": scan.created_at.isoformat(),
        }


@app.get("/scans/{scan_id}/findings")
async def get_findings(scan_id: uuid.UUID) -> list[dict]:
    with SessionLocal() as session:
        rows = ScanRepository(session).findings(scan_id)
        return [
            {
                "finding_id": str(row.id),
                "cve_id": row.cve_id,
                "pkg_name": row.pkg_name,
                "installed_version": row.installed_version,
                "fixed_version": row.fixed_version,
                "severity": row.severity,
                "cvss_score": row.cvss_score,
                "priority_score": row.priority_score,
                "rank": row.rank,
            }
            for row in rows
        ]


@app.get("/findings/{finding_id}/remediation")
async def get_remediation(finding_id: uuid.UUID) -> dict:
    from intellipatch.storage.orm import FindingRow

    with SessionLocal() as session:
        row = session.get(FindingRow, finding_id)
        if row is None:
            raise HTTPException(status_code=404, detail="finding not found")

        finding = Finding(
            cve_id=row.cve_id,
            image="",
            pkg_name=row.pkg_name,
            installed_version=row.installed_version,
            fixed_version=row.fixed_version,
            severity=row.severity,
            cvss_score=row.cvss_score,
            cvss_vector=row.cvss_vector,
            title=row.title,
        )

    report = build_report(finding)
    return report.model_dump()
