from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.config import settings
from app.database.base import Base
from app.database.session import engine
from app.api import api_router
from app.core.limiter import limiter
from app.utils.logger import logger
import app.models  # noqa: F401 — register all models before create_all


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables + seed admin on startup
    Base.metadata.create_all(bind=engine)
    _migrate_users_table()
    _flag_known_default_passwords()
    _seed_admin()
    _purge_expired_revoked_tokens()
    logger.info("NexusSecure started")
    yield
    logger.info("NexusSecure shutdown")


def _migrate_users_table():
    # No Alembic migration history exists yet; patch pre-existing dev DBs
    # created before the must_change_password column was added.
    from sqlalchemy import inspect, text
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return
    columns = [c["name"] for c in inspector.get_columns("users")]
    if "must_change_password" in columns:
        return
    default_literal = "0" if engine.dialect.name == "sqlite" else "false"
    with engine.begin() as conn:
        conn.execute(text(
            f"ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT {default_literal}"
        ))
    logger.info("Migrated users table: added must_change_password column")


def _flag_known_default_passwords():
    # One-time remediation for instances provisioned before this fix: any
    # account still using the password previously published in README.md
    # ("Admin@1234!") is forced to change it on next login, regardless of role.
    from app.database.session import SessionLocal
    from app.models.user import User
    from app.auth.security import verify_password
    db = SessionLocal()
    try:
        changed = False
        for user in db.query(User).filter(User.must_change_password.is_(False)).all():
            if verify_password("Admin@1234!", user.password_hash):
                user.must_change_password = True
                changed = True
                logger.warning(
                    "User %s uses the previously-documented default password — flagged for forced change",
                    user.username,
                )
        if changed:
            db.commit()
    finally:
        db.close()


def _purge_expired_revoked_tokens():
    from datetime import datetime
    from app.database.session import SessionLocal
    from app.models.revoked_token import RevokedToken
    db = SessionLocal()
    try:
        deleted = db.query(RevokedToken).filter(RevokedToken.expires_at < datetime.utcnow()).delete()
        if deleted:
            db.commit()
    finally:
        db.close()


def _seed_admin():
    import secrets
    from app.database.session import SessionLocal
    from app.models.user import User, UserRole
    from app.auth.security import hash_password
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.role == UserRole.admin).first():
            generated = not settings.FIRST_ADMIN_PASSWORD
            password = settings.FIRST_ADMIN_PASSWORD or secrets.token_urlsafe(12)
            admin = User(
                username="admin",
                email=settings.FIRST_ADMIN_EMAIL,
                password_hash=hash_password(password),
                role=UserRole.admin,
                must_change_password=True,
            )
            db.add(admin); db.commit()
            if generated:
                logger.warning(
                    "Default admin created: %s | mot de passe généré (affiché une seule fois, à noter): %s",
                    settings.FIRST_ADMIN_EMAIL, password,
                )
            else:
                logger.info("Default admin created: %s (password change required on first login)",
                            settings.FIRST_ADMIN_EMAIL)
    finally:
        db.close()


app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="Plateforme de cybersécurité — audit et sécurisation des réseaux",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# CSP allows 'unsafe-inline' for script/style because the Jinja2 templates rely on
# inline <script> blocks and style="" attributes throughout — removing that needs a
# template-wide nonce migration, tracked as follow-up (see SECURITY_FIXES.md). Still
# meaningfully reduces XSS blast radius: blocks loading script/frames from arbitrary
# third-party origins, clickjacking (frame-ancestors), and MIME sniffing.
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "font-src 'self' https://cdn.jsdelivr.net data:; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'"
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = _CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# API routes
app.include_router(api_router)

# Static files & templates
app.mount("/static", StaticFiles(directory="../frontend/static"), name="static")
templates = Jinja2Templates(directory="../frontend/templates")

# ----- Frontend page routes -----
from fastapi.responses import HTMLResponse


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "app_name": settings.APP_NAME})


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/scans", response_class=HTMLResponse, include_in_schema=False)
async def scans_page(request: Request):
    return templates.TemplateResponse("scans.html", {"request": request})


@app.get("/vulnerabilities", response_class=HTMLResponse, include_in_schema=False)
async def vulns_page(request: Request):
    return templates.TemplateResponse("vulnerabilities.html", {"request": request})


@app.get("/reports", response_class=HTMLResponse, include_in_schema=False)
async def reports_page(request: Request):
    return templates.TemplateResponse("reports.html", {"request": request})


@app.get("/compare", response_class=HTMLResponse, include_in_schema=False)
async def compare_page(request: Request):
    return templates.TemplateResponse("compare.html", {"request": request})


@app.get("/users", response_class=HTMLResponse, include_in_schema=False)
async def users_page(request: Request):
    return templates.TemplateResponse("users.html", {"request": request})


@app.get("/logs", response_class=HTMLResponse, include_in_schema=False)
async def logs_page(request: Request):
    return templates.TemplateResponse("logs.html", {"request": request})


@app.get("/profile", response_class=HTMLResponse, include_in_schema=False)
async def profile_page(request: Request):
    return templates.TemplateResponse("profile.html", {"request": request})
