import httpx
from app.config import settings


async def otx_lookup_ip(ip: str):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": settings.otx_api_key}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(url, headers=headers)
            if r.status_code != 200:
                return {}
            return r.json()
    except Exception:
        return {}