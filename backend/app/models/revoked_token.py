from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime
from app.database.base import Base


class RevokedToken(Base):
    """Logged-out access tokens, by JWT id (jti). Checked on every request via
    get_current_user. expires_at mirrors the token's own exp so expired rows can
    be purged instead of growing the table forever (see main.py startup purge)."""
    __tablename__ = "revoked_tokens"

    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(36), unique=True, nullable=False, index=True)
    revoked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
