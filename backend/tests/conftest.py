import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.base import Base
from app.database.session import get_db
from app.models.user import User, UserRole
from app.models.scan import Scan, Host
from app.models.vulnerability import Vulnerability, Severity
from app.models.report import Report
from app.auth.security import hash_password
from app.core.limiter import limiter
from main import app

TEST_DB = "sqlite:///./test_nexussecure.db"
engine = create_engine(TEST_DB, connect_args={"check_same_thread": False})
TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    # Rate limiting is a production concern (see app/core/limiter.py); the fixtures
    # below log in far more often than a real client would within a minute.
    limiter.enabled = False
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db():
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db):
    def override_db():
        yield db
    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def admin_token(db, client):
    if not db.query(User).filter(User.username == "testadmin").first():
        db.add(User(username="testadmin", email="testadmin@test.local",
                    password_hash=hash_password("Admin@1234!"), role=UserRole.admin))
        db.commit()
    res = client.post("/api/auth/token", data={"username": "testadmin", "password": "Admin@1234!"})
    return res.json()["access_token"]


@pytest.fixture()
def analyst_token(db, client):
    if not db.query(User).filter(User.username == "testanalyst").first():
        db.add(User(username="testanalyst", email="analyst@test.local",
                    password_hash=hash_password("Analyst@123!"), role=UserRole.analyst))
        db.commit()
    res = client.post("/api/auth/token", data={"username": "testanalyst", "password": "Analyst@123!"})
    return res.json()["access_token"]


def _login_as(db, client, username, email, password, role):
    if not db.query(User).filter(User.username == username).first():
        db.add(User(username=username, email=email, password_hash=hash_password(password), role=role))
        db.commit()
    res = client.post("/api/auth/token", data={"username": username, "password": password})
    return res.json()["access_token"]


@pytest.fixture()
def client_token(db, client):
    return _login_as(db, client, "testclient", "client@test.local", "Client@123!", UserRole.client)


@pytest.fixture()
def other_client_token(db, client):
    return _login_as(db, client, "testclient2", "client2@test.local", "Client2@123!", UserRole.client)


@pytest.fixture()
def other_analyst_token(db, client):
    return _login_as(db, client, "testanalyst2", "analyst2@test.local", "Analyst2@123!", UserRole.analyst)


def user_id(db, username: str) -> int:
    return db.query(User).filter(User.username == username).first().id


def make_scan(db, user_id: int, client_id: int | None = None, target: str = "10.0.0.1") -> Scan:
    scan = Scan(target=target, user_id=user_id, client_id=client_id)
    db.add(scan); db.commit(); db.refresh(scan)
    return scan


def make_host(db, scan_id: int, ip: str = "10.0.0.1") -> Host:
    host = Host(scan_id=scan_id, ip=ip)
    db.add(host); db.commit(); db.refresh(host)
    return host


def make_vulnerability(db, host_id: int, severity: Severity = Severity.high, title: str = "Test vuln") -> Vulnerability:
    vuln = Vulnerability(host_id=host_id, severity=severity, title=title)
    db.add(vuln); db.commit(); db.refresh(vuln)
    return vuln


def make_report(db, scan_id: int, pdf_path: str | None = None, risk_score: float = 5.0) -> Report:
    report = Report(scan_id=scan_id, pdf_path=pdf_path, risk_score=risk_score)
    db.add(report); db.commit(); db.refresh(report)
    return report
