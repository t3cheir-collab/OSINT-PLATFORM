# app/models/api_key.py
import hashlib
import secrets
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Integer, ForeignKey
from app.database import Base


class APIKey(Base):
    __tablename__ = "api_keys"

    id             = Column(Integer, primary_key=True, index=True)
    user_id        = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name           = Column(String, nullable=False)           # e.g. "Splunk Production"
    key_hash       = Column(String, nullable=False, unique=True)  # SHA-256 of raw key
    key_prefix     = Column(String, nullable=False)           # first 8 chars for display
    is_active      = Column(Boolean, default=True)
    created_at     = Column(DateTime, default=datetime.utcnow)
    last_used_at   = Column(DateTime, nullable=True)
    requests_total = Column(Integer, default=0)

    @staticmethod
    def generate() -> tuple[str, str, str]:
        """
        Generate a new API key.
        Returns (raw_key, key_hash, key_prefix).
        raw_key is shown once to the user and never stored.
        key_hash (SHA-256) is stored in the database.
        key_prefix (first 8 chars) is used for display/identification.
        """
        raw_key    = "osint_" + secrets.token_urlsafe(32)
        key_hash   = hashlib.sha256(raw_key.encode()).hexdigest()
        key_prefix = raw_key[:14]  # "osint_" + 8 chars
        return raw_key, key_hash, key_prefix

    @staticmethod
    def hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode()).hexdigest()