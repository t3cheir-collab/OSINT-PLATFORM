# app/api/web.py

import json
import re
import asyncio
import logging
import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime
from typing import Dict, Any, List, Optional

router = APIRouter(prefix="/web", tags=["Web"])
logger = logging.getLogger(__name__)

ANTHROPIC_URL     = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL      = "claude-sonnet-4-5"
TIMEOUT           = httpx.Timeout(90.0)   # longer — one big call
CACHE_TTL_SECONDS = 1800                  # 30 min cache


def _anthropic_headers() -> dict:
    from app.config import settings
    key = settings.anthropic_api_key
    if not key:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY not configured on server")
    return {
        "x-api-key":         key,
        "anthropic-version": "2023-06-01",
        "content-type":      "application/json",
    }


# - Feed cache --------------------------------
_feed_cache: dict = {"items": [], "fetched_at": None}

# Per-category cache so individual buttons can refresh one at a time
_cat_cache:  dict = {}   # { category_id: item_dict }


# - Status ----------------------------------

@router.get("/status")
async def platform_status() -> Dict[str, Any]:
    return {
        "platform":  "OSINT IOC Intelligence Platform",
        "status":    "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "features": {
            "ioc_analysis":            True,
            "multi_source_enrichment": True,
            "ai_analysis":             True,
            "threat_feed":             True,
            "ioc_chat":                True,
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# THREAT FEED
# Strategy: ONE batched Claude call for all 6 items.
#   Output tokens: ~2000 total (well under 8K/min limit)
#   Web search uses: 1 call (limit is 30/sec — no issue)
#   Input tokens: ~1500 (well under 30K/min)
#
# Per-category endpoint reuses the batch cache — only calls Claude if
# that specific category isn't cached yet.
# ═══════════════════════════════════════════════════════════════════════════════

_CATEGORIES = [
    ("malware_1", "Malware or Ransomware",    "the most active malware or ransomware campaign right now"),
    ("cve_1",     "CVE or Zero-Day",          "the most critical CVE or zero-day from the past 7 days"),
    ("apt_1",     "Threat Actor or Campaign", "the most notable APT or threat actor campaign active now"),
    ("malware_2", "Malware or Ransomware",    "the second most active malware or ransomware campaign this week"),
    ("vuln_1",    "Vulnerability or CVE",     "a vulnerability being actively exploited in the wild right now"),
    ("apt_2",     "Threat Actor or Campaign", "a notable data breach or supply chain attack in the past 7 days"),
]

_BATCH_SYSTEM = (
    "You are a threat intelligence analyst with web search access. "
    "Search the web for current cybersecurity threats. "
    "Return ONLY a valid JSON array of objects. "
    "No markdown, no code fences, no explanation. "
    "CRITICAL: never use double-quote characters inside string values — rephrase instead."
)

_SINGLE_SYSTEM = (
    "You are a threat intelligence analyst with web search access. "
    "Return ONLY a single valid JSON object. "
    "No markdown, no code fences, no explanation. "
    "CRITICAL: never use double-quote characters inside string values."
)


def _batch_prompt() -> str:
    items_desc = "\n".join(
        f'{i+1}. id="{cat[0]}", category="{cat[1]}", topic="{cat[2]}"'
        for i, cat in enumerate(_CATEGORIES)
    )
    return (
        "Search the web for the latest cybersecurity threats. "
        "Return a JSON array containing exactly 6 objects, one per topic below:\n\n"
        + items_desc + "\n\n"
        "Each object must have these exact fields:\n"
        '  id (use the id value given above), '
        'category (use the category value given), '
        'severity (CRITICAL/HIGH/MEDIUM), '
        'title (short), '
        'summary (max 2 sentences — no double-quote chars), '
        'ioc_examples (array of IPs/domains/hashes only, max 2, empty array if none), '
        'tags (array of strings), '
        'source (publication name), '
        'source_url (full article URL).\n\n'
        "Return the raw JSON array only. Start with [ and end with ]."
    )


def _single_prompt(category_hint: str, what: str) -> str:
    return (
        "Search the web for " + what + ". "
        "Return ONE JSON object with: "
        "id (string), category (" + category_hint + "), "
        "severity (CRITICAL/HIGH/MEDIUM), title (short), "
        "summary (max 2 sentences, no double-quote chars), "
        "ioc_examples (array max 2, empty if none), "
        "tags (array), source, source_url. "
        "Raw JSON object only."
    )


def _clean_text(text: str) -> str:
    text = (text
        .replace("\u2018", "'").replace("\u2019", "'")
        .replace("\u201c", "'").replace("\u201d", "'")
        .replace("\u2013", "-").replace("\u2014", "-")
        .replace("\u2026", "...")
    )
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)


def _clean_ioc(v: str) -> Optional[str]:
    v = v.strip().strip("'\"").strip()
    if not v or v in ("N/A", "n/a", "None", "none", "-", "TBD", "Unknown"): return None
    if " " in v and not v.startswith("http"): return None
    if len(v) < 4: return None
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d+$", v): v = v.split(":")[0]
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d+$",  v): v = v.split("/")[0]
    if v.startswith("*."): v = v[2:]
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):                           return v
    if re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$", v):                     return v
    if re.match(r"^https?://", v):                                          return v
    if re.match(r"^[a-fA-F0-9]{32,64}$", v):                               return v
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,253}\.[a-zA-Z]{2,}$", v): return v
    return None


def _postprocess(obj: dict, fallback_id: str) -> dict:
    obj.setdefault("id", fallback_id)
    obj["ioc_examples"] = [c for r in (obj.get("ioc_examples") or []) if (c := _clean_ioc(str(r)))]
    return obj


def _parse_array(text: str) -> list:
    """Parse Claude response into a list of item dicts."""
    text = re.sub(r"```\w*", "", _clean_text(text.strip())).strip()
    # Extract JSON array
    if not text.startswith("["):
        m = re.search(r"\[.*\]", text, re.DOTALL)
        text = m.group(0) if m else None
    if not text:
        return []
    try:
        items = json.loads(text)
        return [_postprocess(i, f"item_{n}") for n, i in enumerate(items, 1) if isinstance(i, dict)]
    except json.JSONDecodeError as e:
        logger.warning(f"Batch parse failed: {e} — trying object extraction")
        # Fall back: extract individual objects
        items = []
        depth, start = 0, None
        for idx, ch in enumerate(text):
            if ch == "{":
                if depth == 0: start = idx
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0 and start is not None:
                    try:
                        items.append(_postprocess(json.loads(text[start:idx+1]), f"item_{len(items)+1}"))
                    except Exception:
                        pass
                    start = None
        return items


def _parse_object(text: str, fallback_id: str) -> Optional[dict]:
    """Parse Claude response into a single item dict."""
    text = re.sub(r"```\w*", "", _clean_text(text.strip())).strip()
    if not text.startswith("{"):
        m = re.search(r"\{.*\}", text, re.DOTALL)
        text = m.group(0) if m else None
    if not text:
        return None
    try:
        return _postprocess(json.loads(text), fallback_id)
    except json.JSONDecodeError as e:
        logger.warning(f"Single item parse failed ({fallback_id}): {e}")
        return None


# - Bulk endpoint: one batched call for all 6 -----------------

@router.get("/threat-feed")
async def threat_feed(force: bool = False) -> Dict[str, Any]:
    """
    ONE Claude call returns all 6 threat items as a JSON array.
    ~2000 output tokens total — well within 8K/min Tier 1 limit.
    Cached 30 minutes. ?force=true bypasses cache.
    """
    now = datetime.utcnow()

    if not force and _feed_cache["fetched_at"] and _feed_cache["items"]:
        age = (now - _feed_cache["fetched_at"]).total_seconds()
        if age < CACHE_TTL_SECONDS:
            logger.info(f"Threat feed from cache (age={int(age)}s)")
            return {
                "items":             _feed_cache["items"],
                "fetched_at":        _feed_cache["fetched_at"].isoformat(),
                "cached":            True,
                "cache_age_seconds": int(age),
            }

    logger.info("Fetching threat feed — single batched Claude call")
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.post(
                ANTHROPIC_URL,
                json={
                    "model":      CLAUDE_MODEL,
                    "max_tokens": 2500,   # 6 items × ~350 tokens + buffer
                    "system":     _BATCH_SYSTEM,
                    "tools":      [{"type": "web_search_20250305", "name": "web_search"}],
                    "messages":   [{"role": "user", "content": _batch_prompt()}],
                },
                headers=_anthropic_headers(),
            )
        if r.status_code == 429:
            logger.warning("Threat feed rate limited (429)")
            raise HTTPException(status_code=429, detail="Rate limited — please wait a minute then try again")
        if r.status_code != 200:
            logger.error(f"Threat feed Claude error {r.status_code}: {r.text[:200]}")
            raise HTTPException(status_code=502, detail=f"Claude API error {r.status_code}")

        blocks = r.json().get("content", [])
        text   = " ".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        items  = _parse_array(text)

        if not items:
            raise HTTPException(status_code=502, detail="Could not parse threat feed response")

        # Update caches
        _feed_cache["items"]      = items
        _feed_cache["fetched_at"] = now
        for item in items:
            _cat_cache[item.get("id", "")] = item

        return {"items": items, "fetched_at": now.isoformat(), "cached": False}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Threat feed error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# - Single-category endpoint: reuse cache, or fetch just that one -------

@router.get("/threat-feed/category/{category_id}")
async def threat_feed_category(category_id: str) -> Dict[str, Any]:
    """
    Fetch or refresh a single threat category.
    If already cached from a bulk fetch, returns immediately (no API call).
    Otherwise makes ONE small Claude call (~400 output tokens).
    """
    cat = next((c for c in _CATEGORIES if c[0] == category_id), None)
    if not cat:
        raise HTTPException(status_code=404, detail=f"Unknown category: {category_id}")

    # Serve from category cache if available
    if category_id in _cat_cache:
        logger.info(f"Category [{category_id}] served from cache")
        return {"item": _cat_cache[category_id], "fetched_at": datetime.utcnow().isoformat(), "cached": True}

    logger.info(f"Fetching single category: {category_id}")
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.post(
                ANTHROPIC_URL,
                json={
                    "model":      CLAUDE_MODEL,
                    "max_tokens": 500,   # single item — very small
                    "system":     _SINGLE_SYSTEM,
                    "tools":      [{"type": "web_search_20250305", "name": "web_search"}],
                    "messages":   [{"role": "user", "content": _single_prompt(cat[1], cat[2])}],
                },
                headers=_anthropic_headers(),
            )
        if r.status_code == 429:
            logger.warning(f"Category [{category_id}] rate limited")
            raise HTTPException(status_code=429, detail="Rate limited — wait 30 seconds then retry")
        if r.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Claude API error {r.status_code}")

        blocks = r.json().get("content", [])
        text   = " ".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        item   = _parse_object(text, category_id)

        if not item:
            raise HTTPException(status_code=502, detail=f"Could not parse response for {category_id}")

        _cat_cache[category_id] = item
        return {"item": item, "fetched_at": datetime.utcnow().isoformat(), "cached": False}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Category [{category_id}] error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# - IOC Chat ---------------------------------

class ChatMessage(BaseModel):
    role:    str
    content: str

class ChatRequest(BaseModel):
    messages: List[ChatMessage]


@router.post("/chat")
async def ioc_chat(req: ChatRequest) -> Dict[str, Any]:
    """SOC analyst chat powered by Claude + web search."""
    if not req.messages:
        raise HTTPException(status_code=400, detail="No messages provided")

    system = (
        "You are a senior SOC analyst and threat intelligence expert with web search access.\n\n"
        "When asked about an IOC: search the web, describe malware associations, "
        "give a risk assessment and recommended SOC actions.\n\n"
        "Format with bold headers, bullet points, monospace for IOC values. "
        "Under 400 words unless essential."
    )

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.post(
                ANTHROPIC_URL,
                json={
                    "model":      CLAUDE_MODEL,
                    "max_tokens": 1024,
                    "system":     system,
                    "tools":      [{"type": "web_search_20250305", "name": "web_search"}],
                    "messages":   [{"role": m.role, "content": m.content} for m in req.messages],
                },
                headers=_anthropic_headers(),
            )
        if r.status_code != 200:
            logger.error(f"Chat error {r.status_code}: {r.text[:200]}")
            raise HTTPException(status_code=502, detail=f"Claude API error {r.status_code}")

        blocks = r.json().get("content", [])
        text   = " ".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()
        return {"reply": text or "No response — try rephrasing."}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Chat error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# - Dashboard summary -----------------------------

@router.get("/summary")
async def dashboard_summary() -> Dict[str, Any]:
    return {
        "total_queries":      0,
        "malicious_detected": 0,
        "suspicious_detected": 0,
        "benign_detected":    0,
        "note":               "Metrics storage not yet enabled",
    }