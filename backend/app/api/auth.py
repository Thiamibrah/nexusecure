from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.user import User
from app.models.log import Log
from app.models.revoked_token import RevokedToken
from app.auth.security import verify_password, create_access_token, decode_token
from app.auth.dependencies import get_current_user, oauth2_scheme
from app.core.limiter import limiter
from app.schemas.auth import Token

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/token", response_model=Token)
@limiter.limit("5/minute")
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.password_hash):
        db.add(Log(action="login_failed", detail=f"username={form.username}",
                   ip_address=request.client.host if request.client else None))
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")
    remember = "remember" in (form.scopes or [])
    db.add(Log(action="login_success", user_id=user.id,
               ip_address=request.client.host if request.client else None))
    db.commit()
    return Token(access_token=create_access_token(user.id, user.role.value, remember=remember))


@router.post("/logout", status_code=204)
def logout(request: Request, db: Session = Depends(get_db),
           current_user: User = Depends(get_current_user),
           token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    jti, exp = payload.get("jti"), payload.get("exp")
    if jti and exp:
        db.add(RevokedToken(jti=jti, expires_at=datetime.utcfromtimestamp(exp)))
    db.add(Log(action="logout", user_id=current_user.id,
               ip_address=request.client.host if request.client else None))
    db.commit()
