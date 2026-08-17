from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.report import Report
from app.models.scan import Scan
from app.schemas.report import ReportOut
from app.auth.dependencies import get_current_user, require_analyst
from app.services.pdf import generate_pdf
from app.models.user import User
from fastapi import HTTPException
from fastapi.responses import FileResponse

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/new-count")
def new_reports_count(db: Session = Depends(get_db), current_user: User = Depends(get_current_user),
                      since: str = None):
    from datetime import datetime, timedelta
    if since:
        try:
            cutoff = datetime.fromisoformat(since.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            cutoff = datetime.utcnow() - timedelta(hours=24)
    else:
        cutoff = datetime.utcnow() - timedelta(hours=24)
    q = db.query(Report).filter(Report.created_at >= cutoff)
    if current_user.role.value == "client":
        client_scan_ids = [s.id for s in db.query(Scan.id).filter(Scan.client_id == current_user.id).all()]
        q = q.filter(Report.scan_id.in_(client_scan_ids))
    return {"count": q.count()}


@router.get("/", response_model=list[ReportOut])
def list_reports(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    q = db.query(Report).order_by(Report.created_at.desc())
    if current_user.role.value == "client":
        client_scan_ids = [s.id for s in db.query(Scan.id).filter(Scan.client_id == current_user.id).all()]
        q = q.filter(Report.scan_id.in_(client_scan_ids))
    return q.all()


@router.post("/{scan_id}", response_model=ReportOut, status_code=201)
def create_report(scan_id: int, db: Session = Depends(get_db), _=Depends(require_analyst)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    existing = db.query(Report).filter(Report.scan_id == scan_id).first()
    if existing:
        return existing
    report = generate_pdf(scan, db)

    # Auto-send email to assigned client
    if scan.client_id:
        from app.models.user import User
        from app.services.email import send_report_email
        client = db.get(User, scan.client_id)
        if client and report.pdf_path:
            send_report_email(
                to=client.email,
                username=client.username,
                scan_target=scan.target,
                risk_score=report.risk_score,
                pdf_path=report.pdf_path,
            )
    return report


@router.get("/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db),
                    current_user: User = Depends(get_current_user)):
    report = db.get(Report, report_id)
    if not report or not report.pdf_path:
        raise HTTPException(status_code=404, detail="Report not found")
    if current_user.role.value == "client":
        scan = db.get(Scan, report.scan_id)
        if not scan or scan.client_id != current_user.id:
            raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(report.pdf_path, media_type="application/pdf",
                        filename=f"nexussecure_report_{report_id}.pdf")


@router.post("/{report_id}/send-email")
def send_email_report(report_id: int, db: Session = Depends(get_db),
                      current_user: User = Depends(get_current_user)):
    """Simulated email — logs the email instead of sending (no SMTP required)."""
    from app.utils.logger import logger
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    recipient = current_user.email
    logger.info(
        "[EMAIL SIMULÉ] À: %s | Sujet: Rapport NexusSecure #%d | Score: %.1f/10 | Scan: #%d",
        recipient, report_id, report.risk_score, report.scan_id
    )
    return {"simulated": True, "to": recipient, "report_id": report_id}
