import httpx
from app.config import settings


async def abuseipdb_lookup(ip: str):
    url = "https://api.abuseipdb.com/api/v2/check"
    # Read key fresh - NOT at module import time
    headers = {
        "Key": settings.abuseipdb_api_key,
        "Accept": "application/json",
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(url, headers=headers, params=params)
            if r.status_code != 200:
                return {}
            return r.json().get("data", {})
    except Exception:
        return {}