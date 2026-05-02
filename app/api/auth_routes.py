# app/api/auth_routes.py
import logging
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.auth import (
    hash_password, verify_password, check_password_strength,
    generate_code, hash_code, verify_code,
    generate_reset_token, hash_token, verify_token,
    create_session_token, decode_session_token,
)
from app.services.email_service import (
    send_verification_email, send_mfa_email, send_password_reset_email,
)
import os

logger  = logging.getLogger(__name__)
router  = APIRouter(prefix="/auth", tags=["Auth"])
bearer  = HTTPBearer(auto_error=False)
APP_URL = os.getenv("APP_URL", "http://localhost:5173")

CODE_EXPIRY_MINUTES  = 10
RESET_EXPIRY_MINUTES = 60
MAX_FAILED_ATTEMPTS  = 5
LOCKOUT_MINUTES      = 15


# - Schemas ----------------------------------

class RegisterRequest(BaseModel):
    email:    EmailStr
    password: str

class VerifyEmailRequest(BaseModel):
    email: EmailStr
    code:  str

class LoginRequest(BaseModel):
    email:    EmailStr
    password: str

class MFARequest(BaseModel):
    email: EmailStr
    code:  str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token:        str
    new_password: str


# - Dependency: get current user from JWT -------------------

def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    db:    Session = Depends(get_db),
) -> User:
    if not creds:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_session_token(creds.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    user = db.query(User).filter(User.id == int(payload["sub"])).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


# - Register ---------------------------------

@router.post("/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    # Password strength check
    strength = check_password_strength(req.password)
    if not strength["ok"]:
        raise HTTPException(
            status_code=400,
            detail={"message": "Password too weak", "issues": strength["issues"], "score": strength["score"]}
        )

    # Check duplicate
    if db.query(User).filter(User.email == req.email.lower()).first():
        raise HTTPException(status_code=409, detail="An account with this email already exists")

    # Generate verification code
    code     = generate_code()
    code_exp = datetime.utcnow() + timedelta(minutes=CODE_EXPIRY_MINUTES)

    user = User(
        email           = req.email.lower(),
        hashed_password = hash_password(req.password),
        verify_code_hash= hash_code(code),
        verify_code_exp = code_exp,
    )
    db.add(user)
    db.commit()

    send_verification_email(user.email, code)
    logger.info(f"Registered: {user.email}")
    return {"message": "Account created. Check your email for a 6-digit verification code."}


# - Verify Email -------------------------------

@router.post("/verify-email")
def verify_email(req: VerifyEmailRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email.lower()).first()
    if not user:
        raise HTTPException(status_code=404, detail="Account not found")
    if user.is_verified:
        return {"message": "Email already verified — you can log in"}
    if not user.verify_code_hash or not user.verify_code_exp:
        raise HTTPException(status_code=400, detail="No verification code found — try registering again")
    if datetime.utcnow() > user.verify_code_exp:
        raise HTTPException(status_code=400, detail="Verification code expired — please request a new one")
    if not verify_code(req.code.strip(), user.verify_code_hash):
        raise HTTPException(status_code=400, detail="Incorrect verification code")

    user.is_verified      = True
    user.verify_code_hash = None
    user.verify_code_exp  = None
    db.commit()
    logger.info(f"Email verified: {user.email}")
    return {"message": "Email verified! You can now log in."}


# - Resend verification code -------------------------

@router.post("/resend-verification")
def resend_verification(req: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email.lower()).first()
    if not user or user.is_verified:
        # Don't reveal whether account exists
        return {"message": "If that account exists and isn't verified, a new code has been sent."}
    code     = generate_code()
    code_exp = datetime.utcnow() + timedelta(minutes=CODE_EXPIRY_MINUTES)
    user.verify_code_hash = hash_code(code)
    user.verify_code_exp  = code_exp
    db.commit()
    send_verification_email(user.email, code)
    return {"message": "New verification code sent."}


# - Login (step 1: password check → send MFA code) --------------

@router.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email.lower()).first()

    # Generic error — don't reveal if email exists
    def bad_creds():
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user:
        bad_creds()

    # Lockout check
    if user.locked_until and datetime.utcnow() < user.locked_until:
        remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60) + 1
        raise HTTPException(status_code=429, detail=f"Account locked. Try again in {remaining} minute(s).")

    if not verify_password(req.password, user.hashed_password):
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until    = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_attempts = 0
            db.commit()
            raise HTTPException(status_code=429, detail=f"Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes.")
        db.commit()
        bad_creds()

    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Please verify your email before logging in.")

    # Reset failed attempts on success
    user.failed_attempts = 0
    user.locked_until    = None

    # Generate MFA code
    code     = generate_code()
    code_exp = datetime.utcnow() + timedelta(minutes=CODE_EXPIRY_MINUTES)
    user.mfa_code_hash = hash_code(code)
    user.mfa_code_exp  = code_exp
    db.commit()

    send_mfa_email(user.email, code)
    logger.info(f"Login step 1 OK, MFA sent: {user.email}")
    return {"message": "Password correct. A 6-digit code has been sent to your email."}


# - MFA verify (step 2 → issue session token) ----------------

@router.post("/verify-mfa")
def verify_mfa(req: MFARequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email.lower()).first()
    if not user or not user.mfa_code_hash:
        raise HTTPException(status_code=400, detail="No MFA code pending for this account")
    if datetime.utcnow() > user.mfa_code_exp:
        raise HTTPException(status_code=400, detail="MFA code expired — please log in again")
    if not verify_code(req.code.strip(), user.mfa_code_hash):
        raise HTTPException(status_code=400, detail="Incorrect MFA code")

    # Consume the code (single-use)
    user.mfa_code_hash = None
    user.mfa_code_exp  = None
    db.commit()

    token = create_session_token(user.id, user.email)
    logger.info(f"MFA verified, session created: {user.email}")
    return {"access_token": token, "token_type": "bearer", "email": user.email}


# - Forgot Password ------------------------------

@router.post("/forgot-password")
def forgot_password(req: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email.lower()).first()
    # Always return same message — don't reveal if account exists
    msg = {"message": "If that email is registered, a password reset link has been sent."}
    if not user or not user.is_verified:
        return msg

    token      = generate_reset_token()
    token_exp  = datetime.utcnow() + timedelta(minutes=RESET_EXPIRY_MINUTES)
    user.reset_token_hash = hash_token(token)
    user.reset_token_exp  = token_exp
    db.commit()

    reset_url = f"{APP_URL}/reset-password?token={token}"
    send_password_reset_email(user.email, reset_url)
    logger.info(f"Password reset sent: {user.email}")
    return msg


# - Reset Password ------------------------------

@router.post("/reset-password")
def reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    # Find user by matching the token hash
    candidates = db.query(User).filter(User.reset_token_hash.isnot(None)).all()
    user = next((u for u in candidates if verify_token(req.token, u.reset_token_hash)), None)

    if not user:
        raise HTTPException(status_code=400, detail="Invalid or already-used reset link")
    if datetime.utcnow() > user.reset_token_exp:
        raise HTTPException(status_code=400, detail="Reset link has expired — please request a new one")

    # Validate new password strength
    strength = check_password_strength(req.new_password)
    if not strength["ok"]:
        raise HTTPException(
            status_code=400,
            detail={"message": "Password too weak", "issues": strength["issues"], "score": strength["score"]}
        )

    user.hashed_password  = hash_password(req.new_password)
    user.reset_token_hash = None
    user.reset_token_exp  = None
    # Invalidate any active MFA codes too
    user.mfa_code_hash    = None
    user.mfa_code_exp     = None
    db.commit()

    logger.info(f"Password reset complete: {user.email}")
    return {"message": "Password updated successfully. You can now log in."}


# - Me (verify token + return user info) -------------------

@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "email": current_user.email, "created_at": current_user.created_at}