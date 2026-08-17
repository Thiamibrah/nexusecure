from fastapi import APIRouter, Depends
from app.auth.dependencies import require_admin
from app.config import settings
import os

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.get("/")
def get_logs(lines: int = 100, _=Depends(require_admin)):
    log_path = settings.LOG_FILE
    if not os.path.exists(log_path):
        # try relative to backend dir
        log_path = os.path.join("app", "logs", "nexussecure.log")
    if not os.path.exists(log_path):
        return {"lines": []}
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        all_lines = f.readlines()
    return {"lines": [l.rstrip() for l in all_lines[-lines:]]}
