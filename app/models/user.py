# app/models/user.py
from sqlalchemy import Column, String, Boolean, DateTime, Integer
from datetime import datetime
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id                = Column(Integer, primary_key=True, index=True)
    email             = Column(String, unique=True, index=True, nullable=False)
    hashed_password   = Column(String, nullable=False)
    is_verified       = Column(Boolean, default=False)       # email verified
    is_active         = Column(Boolean, default=True)
    failed_attempts   = Column(Integer, default=0)           # login lockout
    locked_until      = Column(DateTime, nullable=True)      # lockout expiry
    created_at        = Column(DateTime, default=datetime.utcnow)

    # Email verification code (hashed)
    verify_code_hash  = Column(String, nullable=True)
    verify_code_exp   = Column(DateTime, nullable=True)

    # MFA code (hashed) - sent on each login
    mfa_code_hash     = Column(String, nullable=True)
    mfa_code_exp      = Column(DateTime, nullable=True)

    # Password reset token (hashed)
    reset_token_hash  = Column(String, nullable=True)
    reset_token_exp   = Column(DateTime, nullable=True)