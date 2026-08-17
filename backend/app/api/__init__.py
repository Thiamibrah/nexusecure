from fastapi import APIRouter
from .auth import router as auth_router
from .users import router as users_router
from .scans import router as scans_router
from .vulnerabilities import router as vulns_router
from .reports import router as reports_router
from .dashboard import router as dashboard_router
from .logs import router as logs_router

api_router = APIRouter()
for r in (auth_router, users_router, scans_router, vulns_router, reports_router, dashboard_router, logs_router):
    api_router.include_router(r)
