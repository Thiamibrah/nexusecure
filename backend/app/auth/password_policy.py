import re

MIN_LENGTH = 8


def password_policy_errors(password: str) -> list[str]:
    errors = []
    if len(password) < MIN_LENGTH:
        errors.append(f"Password must be at least {MIN_LENGTH} characters")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain a lowercase letter")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain an uppercase letter")
    if not re.search(r"\d", password):
        errors.append("Password must contain a digit")
    if not re.search(r"[^\w\s]", password):
        errors.append("Password must contain a special character")
    return errors
