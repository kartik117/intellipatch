import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from intellipatch.models.schemas import RankedFinding
from intellipatch.storage.orm import FindingRow, ScanRow


class ScanRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, *, image: str, ranked: list[RankedFinding]) -> ScanRow:
        scan = ScanRow(image=image, finding_count=len(ranked))
        self.session.add(scan)
        self.session.flush()

        for item in ranked:
            f = item.finding
            self.session.add(
                FindingRow(
                    scan_id=scan.id,
                    cve_id=f.cve_id,
                    pkg_name=f.pkg_name,
                    installed_version=f.installed_version,
                    fixed_version=f.fixed_version,
                    severity=f.severity,
                    cvss_score=f.cvss_score,
                    cvss_vector=f.cvss_vector,
                    title=f.title,
                    priority_score=item.priority_score,
                    rank=item.rank,
                )
            )
        self.session.commit()
        self.session.refresh(scan)
        return scan

    def get(self, scan_id: uuid.UUID) -> ScanRow | None:
        return self.session.get(ScanRow, scan_id)

    def findings(self, scan_id: uuid.UUID) -> list[FindingRow]:
        stmt = select(FindingRow).where(FindingRow.scan_id == scan_id).order_by(FindingRow.rank)
        return list(self.session.execute(stmt).scalars().all())
