from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database.session import get_db
from app.models.scan import Scan, Host
from app.models.vulnerability import Vulnerability
from app.models.report import Report
from app.models.user import User
from app.auth.dependencies import get_current_user, allowed_scan_ids

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


def _scan_summary(scan: Scan) -> dict:
    vulns = [v for h in scan.hosts for v in h.vulnerabilities]
    from app.services.pdf import _risk_score
    return {
        "scan_id":   scan.id,
        "target":    scan.target,
        "date":      scan.started_at.isoformat(),
        "hosts":     len(scan.hosts),
        "ports":     sum(len(h.ports) for h in scan.hosts),
        "critical":  sum(1 for v in vulns if v.severity.value == "critical"),
        "high":      sum(1 for v in vulns if v.severity.value == "high"),
        "medium":    sum(1 for v in vulns if v.severity.value == "medium"),
        "low":       sum(1 for v in vulns if v.severity.value == "low"),
        "total_vulns": len(vulns),
        "risk_score":  _risk_score(vulns),
    }


@router.get("/compare")
def compare_scans(scan_before: int, scan_after: int,
                  db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from fastapi import HTTPException
    allowed = allowed_scan_ids(db, current_user)
    if allowed is not None and (scan_before not in allowed or scan_after not in allowed):
        raise HTTPException(status_code=404, detail="Scan not found")
    before = db.get(Scan, scan_before)
    after  = db.get(Scan, scan_after)
    if not before or not after:
        raise HTTPException(status_code=404, detail="Scan not found")
    b, a = _scan_summary(before), _scan_summary(after)
    return {
        "before": b,
        "after":  a,
        "diff": {
            "risk_score":   round(a["risk_score"]   - b["risk_score"],   1),
            "total_vulns":  a["total_vulns"]  - b["total_vulns"],
            "critical":     a["critical"]     - b["critical"],
            "high":         a["high"]         - b["high"],
        }
    }


@router.get("/alerts")
def get_alerts(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    """Retourne les alertes actives : vulnérabilités critiques récentes, scans échoués, nouveaux rapports."""
    from datetime import datetime, timedelta
    from app.models.report import Report
    cutoff = datetime.utcnow() - timedelta(hours=24)

    is_client  = current_user.role.value == "client"
    is_analyst = current_user.role.value == "analyst"
    scan_ids = (
        [s.id for s in db.query(Scan.id).filter(Scan.client_id == current_user.id).all()]
        if is_client else
        [s.id for s in db.query(Scan.id).filter(Scan.user_id == current_user.id).all()]
        if is_analyst else None
    )

    def scan_q_filter(q):
        return q.filter(Scan.id.in_(scan_ids)) if scan_ids is not None else q

    alerts = []

    # Scans échoués récents
    failed_q = scan_q_filter(db.query(Scan).filter(Scan.status == "failed", Scan.finished_at >= cutoff))
    for s in failed_q.all():
        alerts.append({"type": "scan_failed", "level": "danger",
                       "message": f"Scan #{s.id} ({s.target}) a échoué",
                       "date": s.finished_at.isoformat()})

    # Vulnérabilités critiques récentes (via hôtes de scans récents)
    recent_scan_ids_q = scan_q_filter(db.query(Scan.id).filter(Scan.started_at >= cutoff))
    recent_ids = [r[0] for r in recent_scan_ids_q.all()]
    if recent_ids:
        crit_count = (db.query(func.count(Vulnerability.id))
                      .join(Host).filter(Host.scan_id.in_(recent_ids),
                                         Vulnerability.severity == "critical").scalar())
        if crit_count:
            alerts.append({"type": "critical_vuln", "level": "danger",
                           "message": f"{crit_count} vulnérabilité(s) critique(s) détectée(s) (24h)",
                           "date": datetime.utcnow().isoformat()})

    # Nouveaux rapports (24h)
    report_q = db.query(Report).filter(Report.created_at >= cutoff)
    if scan_ids is not None:
        report_q = report_q.filter(Report.scan_id.in_(scan_ids))
    new_reports = report_q.count()
    if new_reports:
        alerts.append({"type": "new_report", "level": "success",
                       "message": f"{new_reports} nouveau(x) rapport(s) disponible(s)",
                       "date": datetime.utcnow().isoformat()})

    return alerts


@router.get("/stats")
def dashboard_stats(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    is_client  = current_user.role.value == "client"
    is_analyst = current_user.role.value == "analyst"
    client_scan_ids = (
        [s.id for s in db.query(Scan.id).filter(Scan.client_id == current_user.id).all()]
        if is_client else
        [s.id for s in db.query(Scan.id).filter(Scan.user_id == current_user.id).all()]
        if is_analyst else None
    )
    restricted = is_client or is_analyst

    def scan_q():
        q = db.query(func.count(Scan.id))
        return q.filter(Scan.id.in_(client_scan_ids)) if restricted else q

    def host_q():
        q = db.query(func.count(Host.id))
        return q.filter(Host.scan_id.in_(client_scan_ids)) if restricted else q

    def vuln_q():
        q = db.query(func.count(Vulnerability.id)).join(Host)
        return q.filter(Host.scan_id.in_(client_scan_ids)) if restricted else q

    total_scans = scan_q().scalar()
    total_hosts = host_q().scalar()
    total_vulns = vuln_q().scalar()
    critical = vuln_q().filter(Vulnerability.severity == "critical").scalar()
    high     = vuln_q().filter(Vulnerability.severity == "high").scalar()

    report_q = db.query(Report)
    if restricted:
        report_q = report_q.filter(Report.scan_id.in_(client_scan_ids))
    latest_report = report_q.order_by(Report.created_at.desc()).first()
    latest_score  = round(latest_report.risk_score, 1) if latest_report else 0.0

    avg_score = db.query(func.avg(Report.risk_score))
    if restricted:
        avg_score = avg_score.filter(Report.scan_id.in_(client_scan_ids))
    avg_score = round(float(avg_score.scalar()), 1) if avg_score.scalar() else 0.0

    recent_q = db.query(Scan).order_by(Scan.started_at.desc()).limit(5)
    if restricted:
        recent_q = db.query(Scan).filter(Scan.id.in_(client_scan_ids)).order_by(Scan.started_at.desc()).limit(5)

    return {
        "total_scans": total_scans,
        "total_hosts": total_hosts,
        "total_vulnerabilities": total_vulns,
        "critical": critical,
        "high": high,
        "avg_risk_score": avg_score,
        "latest_risk_score": latest_score,
        "recent_scans": [
            {"id": s.id, "target": s.target, "status": s.status, "started_at": s.started_at}
            for s in recent_q.all()
        ],
    }



@router.get("/admin-stats")
def admin_stats(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    from app.auth.dependencies import require_roles
    from app.models.user import UserRole, User as UserModel
    if current_user.role != UserRole.admin:
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Admin only")

    total_clients = db.query(func.count(UserModel.id)).filter(UserModel.role == UserRole.client).scalar()
    total_analysts = db.query(func.count(UserModel.id)).filter(UserModel.role == UserRole.analyst).scalar()
    total_scans = db.query(func.count(Scan.id)).scalar()
    total_vulns = db.query(func.count(Vulnerability.id)).join(Host).scalar()
    critical = db.query(func.count(Vulnerability.id)).join(Host).filter(Vulnerability.severity == "critical").scalar()

    # Per-client summary
    clients = db.query(UserModel).filter(UserModel.role == UserRole.client).all()
    client_rows = []
    for c in clients:
        scan_ids = [s.id for s in db.query(Scan.id).filter(Scan.client_id == c.id).all()]
        n_scans = len(scan_ids)
        n_vulns = 0
        n_crit = 0
        latest_score = None
        if scan_ids:
            n_vulns = db.query(func.count(Vulnerability.id)).join(Host).filter(Host.scan_id.in_(scan_ids)).scalar()
            n_crit = db.query(func.count(Vulnerability.id)).join(Host).filter(
                Host.scan_id.in_(scan_ids), Vulnerability.severity == "critical").scalar()
            rpt = db.query(Report).filter(Report.scan_id.in_(scan_ids)).order_by(Report.created_at.desc()).first()
            if rpt:
                latest_score = round(rpt.risk_score, 1)
        client_rows.append({
            "id": c.id, "username": c.username, "email": c.email,
            "scans": n_scans, "vulnerabilities": n_vulns,
            "critical": n_crit, "risk_score": latest_score,
        })

    return {
        "total_clients": total_clients,
        "total_analysts": total_analysts,
        "total_scans": total_scans,
        "total_vulnerabilities": total_vulns,
        "critical": critical,
        "clients": client_rows,
    }
