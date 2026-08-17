from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.user import User, UserRole
from app.models.scan import Scan
from app.models.revoked_token import RevokedToken
from app.auth.security import decode_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

# Endpoints a user must still reach while must_change_password is set,
# so they can see their own state and actually change the password.
PASSWORD_CHANGE_EXEMPT_PATHS = {
    "/api/users/me",
    "/api/users/me/password",
    "/api/auth/logout",
}


def get_current_user(request: Request, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    payload = decode_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    jti = payload.get("jti")
    if jti and db.query(RevokedToken).filter(RevokedToken.jti == jti).first():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")
    user = db.get(User, int(user_id))
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    if user.must_change_password and request.url.path not in PASSWORD_CHANGE_EXEMPT_PATHS:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Password change required")
    return user


def require_roles(*roles: UserRole):
    def checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return current_user
    return checker


require_admin = require_roles(UserRole.admin)
require_analyst = require_roles(UserRole.admin, UserRole.analyst)


def allowed_scan_ids(db: Session, user: User) -> list[int] | None:
    """Scan IDs the user is scoped to. None means unrestricted (admin)."""
    if user.role.value == "client":
        return [s.id for s in db.query(Scan.id).filter(Scan.client_id == user.id).all()]
    if user.role.value == "analyst":
        return [s.id for s in db.query(Scan.id).filter(Scan.user_id == user.id).all()]
    return None
