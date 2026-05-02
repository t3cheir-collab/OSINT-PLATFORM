import httpx
from app.config import settings

BASE = "https://www.virustotal.com/api/v3"

# NOTE: Do NOT set HEADERS at module level — settings.vt_api_key is "" at import time.
# Always read the key fresh at call time.

def _headers():
    return {"x-apikey": settings.vt_api_key}


async def _safe_get(url: str):
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(url, headers=_headers())
            if r.status_code != 200:
                return {}
            return r.json()
    except Exception:
        return {}


async def vt_lookup_ip(ip: str):
    data = await _safe_get(f"{BASE}/ip_addresses/{ip}")
    return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})


async def vt_lookup_domain(domain: str):
    data = await _safe_get(f"{BASE}/domains/{domain}")
    return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})


async def vt_lookup_hash(file_hash: str):
    data = await _safe_get(f"{BASE}/files/{file_hash}")
    return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})