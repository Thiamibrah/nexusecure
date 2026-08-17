import re
from datetime import datetime
from pydantic import BaseModel, field_validator
from app.models.user import UserRole
from app.auth.password_policy import password_policy_errors


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: UserRole = UserRole.client

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            raise ValueError("Invalid email address")
        return v.lower()

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        errors = password_policy_errors(v)
        if errors:
            raise ValueError("; ".join(errors))
        return v


class UserUpdate(BaseModel):
    username: str | None = None
    email: str | None = None
    role: UserRole | None = None
    is_active: bool | None = None


class UserOut(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    username: str
    email: str
    role: UserRole
    is_active: bool
    must_change_password: bool
    created_at: datetime
