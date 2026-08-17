from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.vulnerability import Vulnerability
from app.models.scan import Host
from app.models.user import User
from app.auth.dependencies import get_current_user, require_analyst, allowed_scan_ids

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


def _vuln_dict(v: Vulnerability) -> dict:
    return {
        "id": v.id,
        "host_id": v.host_id,
        "host_ip": v.host.ip if v.host else "—",
        "severity": v.severity.value,
        "title": v.title,
        "description": v.description,
        "recommendation": v.recommendation,
        "impact": v.impact,
        "comment": v.comment,
        "cvss_score": v.cvss_score,
        "port_number": v.port_number,
    }


@router.get("/")
def list_vulnerabilities(
    scan_id: int | None = None,
    severity: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = db.query(Vulnerability).join(Host)
    allowed = allowed_scan_ids(db, current_user)
    if allowed is not None:
        q = q.filter(Host.scan_id.in_(allowed))
    if scan_id:
        q = q.filter(Host.scan_id == scan_id)
    if severity:
        q = q.filter(Vulnerability.severity == severity)
    return [_vuln_dict(v) for v in q.all()]


@router.get("/stats")
def vuln_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from sqlalchemy import func
    q = db.query(Vulnerability.severity, func.count()).join(Host)
    allowed = allowed_scan_ids(db, current_user)
    if allowed is not None:
        q = q.filter(Host.scan_id.in_(allowed))
    rows = q.group_by(Vulnerability.severity).all()
    return {r[0].value: r[1] for r in rows}


class CommentPayload(BaseModel):
    comment: str


@router.patch("/{vuln_id}/comment")
def add_comment(
    vuln_id: int,
    payload: CommentPayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Analysts and admins can add/update a technical comment on a vulnerability
    that belongs to one of their own scans (admins are unrestricted)."""
    vuln = db.get(Vulnerability, vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    allowed = allowed_scan_ids(db, current_user)
    if allowed is not None and (not vuln.host or vuln.host.scan_id not in allowed):
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    vuln.comment = payload.comment
    db.commit()
    return _vuln_dict(vuln)
