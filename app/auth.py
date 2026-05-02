# app/auth.py  - core auth helpers (no routes)
import os, secrets, hashlib
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt, JWTError

SECRET_KEY   = os.getenv("SECRET_KEY", secrets.token_hex(32))
ALGORITHM    = "HS256"
TOKEN_EXPIRE_HOURS = int(os.getenv("SESSION_HOURS", "8"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


# - Password ---------------------------------

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def check_password_strength(password: str) -> dict:
    """
    Returns { score: 0-4, label: str, issues: [str] }
    score 0-1 = weak, 2 = medium, 3 = strong, 4 = very strong
    """
    issues = []
    score  = 0

    if len(password) < 12:
        issues.append("At least 12 characters required")
    else:
        score += 1
        if len(password) >= 16:
            score += 1

    if not any(c.isupper() for c in password):
        issues.append("Add an uppercase letter")
    else:
        score += 0.5

    if not any(c.islower() for c in password):
        issues.append("Add a lowercase letter")
    else:
        score += 0.5

    if not any(c.isdigit() for c in password):
        issues.append("Add a number")
    else:
        score += 0.5

    specials = set("!@#$%^&*()_+-=[]{}|;':\",./<>?")
    if not any(c in specials for c in password):
        issues.append("Add a special character (!@#$%^&* etc.)")
    else:
        score += 0.5

    score = min(4, int(score))
    labels = {0: "Very Weak", 1: "Weak", 2: "Medium", 3: "Strong", 4: "Very Strong"}
    return {"score": score, "label": labels[score], "issues": issues, "ok": score >= 3}


# - Short codes (6-digit, for email verify + MFA) ---------------

def generate_code() -> str:
    """6-digit numeric code."""
    return str(secrets.randbelow(900000) + 100000)

def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()

def verify_code(plain: str, hashed: str) -> bool:
    return hashlib.sha256(plain.encode()).hexdigest() == hashed


# - Password reset token (URL-safe 32-byte random) --------------

def generate_reset_token() -> str:
    return secrets.token_urlsafe(32)

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def verify_token(plain: str, hashed: str) -> bool:
    return hashlib.sha256(plain.encode()).hexdigest() == hashed


# - JWT session tokens ----------------------------

def create_session_token(user_id: int, email: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    return jwt.encode(
        {"sub": str(user_id), "email": email, "exp": expire},
        SECRET_KEY, algorithm=ALGORITHM,
    )

def decode_session_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None