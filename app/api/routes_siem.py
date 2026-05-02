# app/api/routes_siem.py
"""
SIEM Integration API - REST pull endpoint for automated enrichment.

Authentication: API key via X-API-Key header (long-lived, no MFA required).
This is designed for machine-to-machine use by SIEM platforms, SOAR tools,
and automated scripts.

Compatible with: Splunk, Elastic SIEM, IBM QRadar, Microsoft Sentinel,
                 Cortex XSOAR, TheHive, and any REST-capable platform.

Endpoints:
  POST /siem/enrich          - bulk IOC enrichment (up to 10 IOCs per request)
  GET  /siem/keys            - list  API keys
  POST /siem/keys            - create a new API key
  DELETE /siem/keys/{key_id} - revoke an API key
  GET  /siem/health          - unauthenticated health check for SIEM monitoring
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.api_key import APIKey
from app.models.user import User
from app.api.auth_routes import get_current_user
from app.api.routes_ioc import detect_ioc_type
from app.services.enrichment_service import (
    enrich_ip_async, enrich_domain_async, enrich_url_async,
    enrich_hash_async, enrich_email_async,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/siem", tags=["SIEM Integration"])

# -- API key security scheme ---------------------------------------------------
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# -- Rate limiting (simple in-memory, per key) ---------------------------------
# In production replace with Redis-backed sliding window
_rate_store: dict[str, list[float]] = {}
RATE_LIMIT_REQUESTS = 60   # per minute per key
RATE_LIMIT_WINDOW   = 60   # seconds


def _check_rate_limit(key_prefix: str) -> bool:
    """Returns True if within limit, False if exceeded."""
    import time
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    history = _rate_store.get(key_prefix, [])
    # prune old entries
    history = [t for t in history if t > window_start]
    if len(history) >= RATE_LIMIT_REQUESTS:
        _rate_store[key_prefix] = history
        return False
    history.append(now)
    _rate_store[key_prefix] = history
    return True


# -- API key dependency --------------------------------------------------------

def get_api_key_user(
    x_api_key: Optional[str] = Security(api_key_header),
    db: Session = Depends(get_db),
) -> tuple[APIKey, User]:
    """Validate X-API-Key header and return (api_key_record, user)."""
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required. Include X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    key_hash = APIKey.hash_key(x_api_key)
    key_record = db.query(APIKey).filter(
        APIKey.key_hash == key_hash,
        APIKey.is_active == True,
    ).first()

    if not key_record:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key.")

    user = db.query(User).filter(User.id == key_record.user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="Associated user account is inactive.")

    # Rate limit check
    if not _check_rate_limit(key_record.key_prefix):
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: {RATE_LIMIT_REQUESTS} requests per minute.",
            headers={"Retry-After": str(RATE_LIMIT_WINDOW)},
        )

    # Update usage stats
    key_record.last_used_at = datetime.utcnow()
    key_record.requests_total += 1
    db.commit()

    return key_record, user


# -- Schemas -------------------------------------------------------------------

class EnrichRequest(BaseModel):
    iocs: list[str] = Field(
        ...,
        min_length=1,
        max_length=10,
        description="List of IOC values to enrich (max 10 per request).",
        examples=[["185.220.101.35", "44d88612fea8a8f36de82e1278abb02f", "evil.example.com"]],
    )
    include_ai: bool = Field(
        default=False,
        description="Include AI-generated threat analysis. Increases latency by 3-8 seconds.",
    )


class IOCResult(BaseModel):
    ioc:        str
    ioc_type:   str
    verdict:    str          # malicious / suspicious / benign
    score:      int          # 0-100
    confidence: int          # 0-100 percent
    mitre_techniques: list[str]   # e.g. ["T1566", "T1090"]
    sources:    dict         # raw source scores
    ai_summary: Optional[str] = None
    error:      Optional[str] = None
    enriched_at: str


class EnrichResponse(BaseModel):
    results:    list[IOCResult]
    total:      int
    enriched:   int
    errors:     int
    request_id: str
    platform:   str = "OSINT IOC Intelligence Platform v1.0"


class CreateKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100,
                      description="Descriptive name, e.g. 'Splunk Production' or 'QRadar Dev'")


class APIKeyResponse(BaseModel):
    id:          int
    name:        str
    key_prefix:  str
    is_active:   bool
    created_at:  str
    last_used_at: Optional[str]
    requests_total: int


class CreateKeyResponse(BaseModel):
    id:         int
    name:       str
    key_prefix: str
    raw_key:    str   # shown ONCE - user must copy this
    created_at: str
    message:    str = "Store this key securely - it will not be shown again."


# -- Helper: run enrichment for a single IOC -----------------------------------

async def _enrich_one(ioc: str, include_ai: bool) -> dict:
    ioc = ioc.strip()
    ioc_type = detect_ioc_type(ioc)
    dispatch = {
        "ip":     enrich_ip_async,
        "domain": enrich_domain_async,
        "url":    enrich_url_async,
        "hash":   enrich_hash_async,
        "email":  enrich_email_async,
    }
    fn = dispatch.get(ioc_type)
    if not fn:
        return {"error": f"Unrecognised IOC type for value: {ioc}"}

    result = await fn(ioc)

    # Extract MITRE technique IDs only (compact for SIEM consumption)
    mitre_ids = [t.get("id", "") for t in result.get("mitre_techniques", []) if t.get("id")]

    # Build the SIEM-friendly result
    out = {
        "ioc":              ioc,
        "ioc_type":         ioc_type,
        "verdict":          result.get("verdict", "unknown"),
        "score":            result.get("raw_score", result.get("score", 0)),
        "confidence":       result.get("confidence", 0),
        "mitre_techniques": mitre_ids,
        "sources":          {
            k: v.get("score", 0) if isinstance(v, dict) else 0
            for k, v in result.get("sources", {}).items()
        },
        "enriched_at": datetime.utcnow().isoformat() + "Z",
    }

    if include_ai:
        out["ai_summary"] = result.get("ai_analysis", "")

    return out


# ══════════════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/health")
async def siem_health():
    """Unauthenticated health check - use this in SIEM monitoring dashboards."""
    return {
        "status":   "operational",
        "service":  "OSINT IOC Intelligence Platform - SIEM API",
        "version":  "1.0",
        "endpoints": {
            "enrich":     "POST /siem/enrich",
            "keys_list":  "GET  /siem/keys",
            "keys_create":"POST /siem/keys",
            "keys_revoke":"DELETE /siem/keys/{id}",
        },
        "rate_limit":  f"{RATE_LIMIT_REQUESTS} requests/minute per key",
        "max_iocs_per_request": 10,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/enrich", response_model=EnrichResponse)
async def bulk_enrich(
    req: EnrichRequest,
    auth: tuple = Depends(get_api_key_user),
):
    """
    Bulk IOC enrichment endpoint for SIEM integration.

    Submit up to 10 IOCs per request. Each IOC is automatically typed
    and enriched across all relevant intelligence sources. Results include
    verdict (malicious/suspicious/benign), risk score (0-100), confidence
    percentage, MITRE ATT&CK technique IDs, and per-source scores.

    **SIEM Integration Examples:**

    Splunk: Use the REST API Input or Adaptive Response Action to POST
    indicators from notable events to this endpoint and write results
    back to a lookup table or index.

    Elastic SIEM: Use the Elastic Watcher or Custom Connector to call
    this endpoint when rules trigger, enriching alerts with verdict and
    MITRE mapping before analyst review.

    Microsoft Sentinel: Use a Logic App with HTTP action to call this
    endpoint from an Automation Rule, writing enrichment results back
    to the incident as comments or custom fields.

    QRadar: Use a Custom Action script or the SOAR integration to call
    this endpoint and update offense custom properties.
    """
    import uuid
    request_id = str(uuid.uuid4())[:8].upper()
    key_record, user = auth

    logger.info(f"SIEM enrich request [{request_id}] - key={key_record.key_prefix} "
                f"iocs={len(req.iocs)} ai={req.include_ai} user={user.email}")

    # Deduplicate whilst preserving order
    seen = set()
    unique_iocs = []
    for ioc in req.iocs:
        if ioc.strip() not in seen:
            seen.add(ioc.strip())
            unique_iocs.append(ioc.strip())

    # Enrich all IOCs concurrently (max 5 at a time to respect rate limits)
    sem = asyncio.Semaphore(5)

    async def bounded_enrich(ioc: str) -> dict:
        async with sem:
            try:
                return await _enrich_one(ioc, req.include_ai)
            except Exception as e:
                logger.error(f"SIEM enrich error for {ioc}: {e}")
                return {
                    "ioc":       ioc,
                    "ioc_type":  "unknown",
                    "verdict":   "error",
                    "score":     0,
                    "confidence": 0,
                    "mitre_techniques": [],
                    "sources":   {},
                    "enriched_at": datetime.utcnow().isoformat() + "Z",
                    "error":     str(e),
                }

    raw_results = await asyncio.gather(*[bounded_enrich(ioc) for ioc in unique_iocs])

    results = []
    errors  = 0
    for r in raw_results:
        if r.get("error") and r.get("verdict") == "error":
            errors += 1
        results.append(IOCResult(**r))

    logger.info(f"SIEM enrich [{request_id}] complete - "
                f"{len(results)-errors} enriched, {errors} errors")

    return EnrichResponse(
        results    = results,
        total      = len(results),
        enriched   = len(results) - errors,
        errors     = errors,
        request_id = request_id,
    )


# -- API Key Management (JWT-authenticated - browser users manage their keys) --

@router.get("/keys", response_model=list[APIKeyResponse])
def list_keys(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all API keys for the authenticated user."""
    keys = db.query(APIKey).filter(
        APIKey.user_id == current_user.id,
        APIKey.is_active == True,
    ).all()
    return [
        APIKeyResponse(
            id             = k.id,
            name           = k.name,
            key_prefix     = k.key_prefix,
            is_active      = k.is_active,
            created_at     = k.created_at.isoformat(),
            last_used_at   = k.last_used_at.isoformat() if k.last_used_at else None,
            requests_total = k.requests_total,
        )
        for k in keys
    ]


@router.post("/keys", response_model=CreateKeyResponse, status_code=201)
def create_key(
    req: CreateKeyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Create a new API key for SIEM integration.
    The raw key is shown ONCE - copy it immediately and store securely.
    """
    # Limit: max 10 active keys per user
    count = db.query(APIKey).filter(
        APIKey.user_id == current_user.id,
        APIKey.is_active == True,
    ).count()
    if count >= 10:
        raise HTTPException(
            status_code=400,
            detail="Maximum of 10 active API keys per user. Revoke unused keys first."
        )

    raw_key, key_hash, key_prefix = APIKey.generate()
    key = APIKey(
        user_id    = current_user.id,
        name       = req.name.strip(),
        key_hash   = key_hash,
        key_prefix = key_prefix,
    )
    db.add(key)
    db.commit()
    db.refresh(key)

    logger.info(f"API key created: user={current_user.email} name='{key.name}' prefix={key_prefix}")

    return CreateKeyResponse(
        id         = key.id,
        name       = key.name,
        key_prefix = key_prefix,
        raw_key    = raw_key,
        created_at = key.created_at.isoformat(),
    )


@router.delete("/keys/{key_id}", status_code=204)
def revoke_key(
    key_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke (deactivate) an API key. This cannot be undone."""
    key = db.query(APIKey).filter(
        APIKey.id      == key_id,
        APIKey.user_id == current_user.id,
    ).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found.")
    key.is_active = False
    db.commit()
    logger.info(f"API key revoked: user={current_user.email} key_id={key_id} prefix={key.key_prefix}")