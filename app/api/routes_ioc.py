# app/api/routes_ioc.py

import re
import logging
from fastapi import APIRouter, Query, HTTPException
from datetime import datetime

from app.services.enrichment_service import (
    enrich_ip_async   as enrich_ip,
    enrich_domain_async as enrich_domain,
    enrich_url_async  as enrich_url,
    enrich_hash_async as enrich_hash,
    enrich_email_async as enrich_email,
)
from app.services.investigation_store import (
    save_investigation,
    get_investigation,
    list_investigations,
)
from app.services.pivot_service import extract_pivots_from_text
from app.models.investigation import (
    InvestigationRecord,
    generate_investigation_id,
)

router = APIRouter(prefix="/ioc", tags=["IOC"])
logger = logging.getLogger(__name__)


# ============================================================
# IOC TYPE DETECTION
# ============================================================

def detect_ioc_type(value: str) -> str:
    """Detect the IOC type from the value."""
    v = value.strip()

    # IPv4
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', v):
        return "ip"

    # Email — check before domain (contains @)
    if re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]{2,}$', v):
        return "email"

    # URL — starts with http/https
    if re.match(r'^https?://', v):
        return "url"

    # MD5 / SHA1 / SHA256 hash
    if re.match(r'^[a-fA-F0-9]{32}$', v):   # MD5
        return "hash"
    if re.match(r'^[a-fA-F0-9]{40}$', v):   # SHA1
        return "hash"
    if re.match(r'^[a-fA-F0-9]{64}$', v):   # SHA256
        return "hash"

    # Domain (anything with a dot that isn't an IP or URL)
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,253}\.[a-zA-Z]{2,}$', v):
        return "domain"

    # Default fallback
    return "ip"


# ============================================================
# ANALYZE IOC — dispatches to correct enrichment pipeline
# ============================================================

@router.get("/analyze")
async def analyze_ioc(value: str = Query(..., description="IOC value to analyse")):
    """
    Analyse an IOC (IP, domain, URL, hash, or email).
    Automatically detects the IOC type and routes to the correct enrichment pipeline.
    """
    v = value.strip()
    if not v:
        raise HTTPException(status_code=400, detail="IOC value cannot be empty")

    ioc_type = detect_ioc_type(v)
    logger.info(f"Analysing [{ioc_type}]: {v}")

    # - Dispatch to correct enrichment function -------
    try:
        if ioc_type == "ip":
            result = await enrich_ip(v)
        elif ioc_type == "domain":
            result = await enrich_domain(v)
        elif ioc_type == "url":
            result = await enrich_url(v)
        elif ioc_type == "hash":
            result = await enrich_hash(v)
        elif ioc_type == "email":
            result = await enrich_email(v)
        else:
            result = await enrich_ip(v)
    except Exception as e:
        logger.error(f"Enrichment failed for [{ioc_type}] {v}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Enrichment failed: {str(e)}")

    # - Save investigation record --------------
    pivot_text_blob = str(result.get("sources", ""))
    pivots = extract_pivots_from_text(pivot_text_blob)
    investigation_id = generate_investigation_id()

    record = InvestigationRecord(
        investigation_id=investigation_id,
        ioc=v,
        ioc_type=result.get("type", ioc_type),
        timestamp=datetime.utcnow(),
        verdict=result.get("verdict", "benign"),
        score=result.get("score", 0),
        confidence=result.get("confidence", 0),
        sources=result.get("sources", {}),
        pivots=pivots,
    )

    save_investigation(record)

    # - Return full enrichment result + record metadata ---
    return {
        "investigation_id": investigation_id,
        **result,
        # Ensure these are always present for the frontend
        "ioc":        v,
        "type":       result.get("type", ioc_type),
        "verdict":    result.get("verdict", "benign"),
        "score":      result.get("score", 0),
        "raw_score":  result.get("raw_score", 0),
        "confidence": result.get("confidence", 0),
        "sources":    result.get("sources", {}),
        "geo":        result.get("geo", {}),
        "mitre_tactics": result.get("mitre_tactics", []),
        "owasp":      result.get("owasp", []),
        "tags":       result.get("tags", []),
        "summary":    result.get("summary", ""),
        "narrative":  result.get("narrative", ""),
        "ai_analysis": result.get("ai_analysis", ""),
        "links":      result.get("links", {}),
    }


# ============================================================
# GET SINGLE INVESTIGATION
# ============================================================

@router.get("/investigation/{investigation_id}")
def fetch_investigation(investigation_id: str):
    record = get_investigation(investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return record


# ============================================================
# LIST INVESTIGATIONS
# ============================================================

@router.get("/investigations")
def fetch_all_investigations():
    return list_investigations()


# ============================================================
# DEBUG — check which keys are loaded (dev only)
# ============================================================

@router.get("/debug/keys")
async def debug_keys():
    """Shows which API keys are loaded. Remove in production."""
    from app.config import settings
    return {
        "VT_API_KEY":           bool(settings.vt_api_key),
        "ABUSEIPDB_API_KEY":    bool(settings.abuseipdb_api_key),
        "OTX_API_KEY":          bool(settings.otx_api_key),
        "URLSCAN_API_KEY":      bool(settings.urlscan_api_key),
        "GOOGLE_SAFE_API_KEY":  bool(settings.google_safe_api_key),
        "HUNTER_API_KEY":       bool(settings.hunter_api_key),
        "HIBP_API_KEY":         bool(settings.hibp_api_key),
        "ANTHROPIC_API_KEY":    bool(settings.anthropic_api_key),
        "SHODAN_API_KEY":       bool(settings.shodan_api_key),
    }


# ============================================================
# DEBUG — test a specific IOC type detection
# ============================================================

@router.get("/debug/detect")
async def debug_detect(value: str = Query(...)):
    """Returns what IOC type would be detected for a given value."""
    return {
        "value":    value,
        "detected": detect_ioc_type(value),
    }