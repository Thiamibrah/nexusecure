from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.user import User
from app.models.scan import Scan
from app.schemas.scan import ScanCreate, ScanOut
from app.auth.dependencies import get_current_user, require_analyst, allowed_scan_ids
from app.core.limiter import limiter
from app.services.scanner import run_scan

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.get("/", response_model=list[ScanOut])
def list_scans(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    q = db.query(Scan)
    if current_user.role.value == "client":
        q = q.filter(Scan.client_id == current_user.id)
    elif current_user.role.value == "analyst":
        q = q.filter(Scan.user_id == current_user.id)
    return q.order_by(Scan.started_at.desc()).all()


@router.post("/", response_model=ScanOut, status_code=201)
@limiter.limit("20/minute")
def create_scan(
    request: Request,
    payload: ScanCreate,
    bg: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    scan = Scan(target=payload.target, user_id=current_user.id, client_id=payload.client_id)
    db.add(scan); db.commit(); db.refresh(scan)
    bg.add_task(run_scan, scan.id)
    return scan


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    allowed = allowed_scan_ids(db, current_user)
    if allowed is not None and scan_id not in allowed:
        raise HTTPException(status_code=403, detail="Forbidden")
    return scan


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: int, db: Session = Depends(get_db), _=Depends(require_analyst)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan); db.commit()
