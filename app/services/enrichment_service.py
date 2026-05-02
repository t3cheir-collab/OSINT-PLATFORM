import asyncio
import hashlib
import base64
import httpx
import os
from typing import Dict, Any

# Keys come from app/config.py which calls load_dotenv() at startup

from app.services.scoring_service import generate_risk_score
from app.services.mitre_service import map_to_mitre, map_to_mitre_from_sources, map_to_owasp
from app.services.report_service import generate_full_report, generate_summary, generate_ai_narrative
from app.services.ai_service import generate_ai_analysis_async

# ================= API KEYS =================
# Read from config.py (which calls load_dotenv()) - NOT module-level os.getenv()
# so keys are always available regardless of import order
from app.config import settings as _cfg

def _vt_key():          return _cfg.vt_api_key          or os.getenv("VT_API_KEY", "")
def _abuse_key():       return _cfg.abuseipdb_api_key   or os.getenv("ABUSEIPDB_API_KEY", "")
def _otx_key():         return _cfg.otx_api_key         or os.getenv("OTX_API_KEY", "")
def _urlscan_key():     return getattr(_cfg, "urlscan_api_key", None)   or os.getenv("URLSCAN_API_KEY", "")
def _gsb_key():         return getattr(_cfg, "google_safe_api_key", None) or os.getenv("GOOGLE_SAFE_API_KEY", "")
def _hunter_key():      return getattr(_cfg, "hunter_api_key", None)   or os.getenv("HUNTER_API_KEY", "")
def _hibp_key():        return getattr(_cfg, "hibp_api_key", None)      or os.getenv("HIBP_API_KEY", "")
def _anthropic_key():   return getattr(_cfg, "anthropic_api_key", None) or os.getenv("ANTHROPIC_API_KEY", "")

# Keys read fresh via helper functions above

TIMEOUT = httpx.Timeout(15.0)

# ============================================================
# HELPERS
# ============================================================

def _vt_url_id(url: str) -> str:
    """VirusTotal URL identifier: base64url(url) with no padding."""
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


async def scrape(client: httpx.AsyncClient, q: str):
    try:
        r = await client.get(
            f"https://duckduckgo.com/html/?q={q}",
            headers={"User-Agent": "Mozilla/5.0"},
            follow_redirects=True,
        )
        return r.text[:1500]
    except Exception:
        return None

# ============================================================
# VirusTotal
# ============================================================

async def vt_ip(client: httpx.AsyncClient, ip: str) -> Dict:
    link = f"https://www.virustotal.com/gui/ip-address/{ip}"
    if not _vt_key():
        return {"score": 0, "detections": 0, "engines": 0, "link": link}
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": _vt_key()},
        )
        if r.status_code != 200:
            return {"score": 0, "detections": 0, "engines": 0, "link": link}
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = (stats.get("malicious",0) + stats.get("suspicious",0) +
                       stats.get("undetected",0) + stats.get("timeout",0)) or 94
        org        = attrs.get("as_owner", "") or attrs.get("network", "")
        country    = attrs.get("country", "")
        return {
            "score":      (0 if malicious == 0 else round(min(100, 60 + (malicious / max(total,1)) * 40))),
            "detections": malicious,
            "engines":    total,
            "org":        org,
            "country":    country,
            "link":       link,
        }
    except Exception:
        return {"score": 0, "detections": 0, "engines": 0, "link": link}


async def vt_domain(client: httpx.AsyncClient, domain: str) -> Dict:
    link = f"https://www.virustotal.com/gui/domain/{domain}"
    if not _vt_key():
        return {"score": 0, "detections": 0, "engines": 0, "link": link}
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": _vt_key()},
        )
        if r.status_code != 200:
            return {"score": 0, "detections": 0, "engines": 0, "link": link}
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = (stats.get("malicious",0) + stats.get("suspicious",0) +
                       stats.get("undetected",0) + stats.get("timeout",0)) or 94
        cats       = attrs.get("categories", {})
        cat_str    = ", ".join(list(cats.values())[:2]) if cats else ""
        return {
            "score":      (0 if malicious == 0 else round(min(100, 60 + (malicious / max(total,1)) * 40))),
            "detections": malicious,
            "engines":    total,
            "categories": cat_str,
            "link":       link,
        }
    except Exception:
        return {"score": 0, "detections": 0, "engines": 0, "link": link}


async def vt_url(client: httpx.AsyncClient, url: str) -> Dict:
    url_id = _vt_url_id(url)
    link   = f"https://www.virustotal.com/gui/url/{url_id}"
    key    = _vt_key()
    if not key:
        return {"score": 0, "detections": 0, "engines": 0, "link": link}
    try:
        headers = {"x-apikey": key}
        # Try fetching existing analysis first
        r = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)

        if r.status_code in (404, 400):
            # URL not in VT yet - submit it for scanning
            sub = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
            )
            if sub.status_code != 200:
                return {"score": 0, "detections": 0, "engines": 0, "link": link}
            # Get analysis ID from submission
            analysis_id = sub.json().get("data", {}).get("id", "")
            if not analysis_id:
                return {"score": 0, "detections": 0, "engines": 0, "link": link}
            # Poll for results (up to 3 attempts, 3s apart)
            stats = {}
            for _ in range(3):
                await asyncio.sleep(3)
                poll = await client.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers,
                )
                if poll.status_code == 200:
                    poll_attrs = poll.json().get("data", {}).get("attributes", {})
                    if poll_attrs.get("status") == "completed":
                        stats = poll_attrs.get("stats", {})
                        break
        else:
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = (stats.get("malicious",0) + stats.get("suspicious",0) +
                       stats.get("undetected",0) + stats.get("timeout",0)) or 94
        return {
            "score":      (0 if malicious == 0 else round(min(100, 60 + (malicious / max(total,1)) * 40))),
            "detections": malicious,
            "engines":    total,
            "link":       link,
        }
    except Exception as e:
        import logging; logging.getLogger(__name__).error(f"vt_url error: {e}")
        return {"score": 0, "detections": 0, "engines": 0, "link": link}


async def vt_hash(client: httpx.AsyncClient, file_hash: str) -> Dict:
    link = f"https://www.virustotal.com/gui/file/{file_hash}"
    if not _vt_key():
        return {"score": 0, "detections": 0, "engines": 0, "link": link}
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": _vt_key()},
        )
        if r.status_code != 200:
            return {"score": 0, "detections": 0, "engines": 0, "link": link}
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = (stats.get("malicious",0) + stats.get("suspicious",0) +
                       stats.get("undetected",0) + stats.get("timeout",0)) or 70
        name       = attrs.get("meaningful_name", "")
        return {
            "score":      (0 if malicious == 0 else round(min(100, 60 + (malicious / max(total,1)) * 40))),
            "detections": malicious,
            "engines":    total,
            "name":       name,
            "link":       link,
        }
    except Exception:
        return {"score": 0, "detections": 0, "engines": 0, "link": link}

# ============================================================
# AbuseIPDB  (IP only)
# ============================================================

async def abuse(client: httpx.AsyncClient, ip: str) -> Dict:
    link = f"https://www.abuseipdb.com/check/{ip}"
    if not _abuse_key():
        return {"score": 0, "confidence": 0, "link": link}
    try:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": _abuse_key(), "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
        )
        if r.status_code != 200:
            return {"score": 0, "confidence": 0, "link": link}
        data = r.json().get("data", {})
        conf = data.get("abuseConfidenceScore", 0)
        return {
            "score":      conf,          # 0–100, already on right scale
            "confidence": conf,
            "isp":        data.get("isp", ""),
            "domain":     data.get("domain", ""),
            "usageType":  data.get("usageType", ""),
            "isProxy":    data.get("isPublic", False),
            "isTor":      data.get("isTor", False),
            "country":    data.get("countryCode", ""),
            "link":       link,
        }
    except Exception:
        return {"score": 0, "confidence": 0, "link": link}

# ============================================================
# OTX  (IP + domain)
# ============================================================

async def otx_ip(client: httpx.AsyncClient, ip: str) -> Dict:
    link = f"https://otx.alienvault.com/indicator/ip/{ip}"
    if not _otx_key():
        return {"score": 0, "pulses": 0, "link": link}
    try:
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": _otx_key()},
        )
        if r.status_code != 200:
            return {"score": 0, "pulses": 0, "link": link}
        data   = r.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        # grab a note from the first pulse if available
        pulse_list = data.get("pulse_info", {}).get("pulses", [])
        note = pulse_list[0].get("name", "") if pulse_list else (
            "Known False Positive" if pulses == 0 else ""
        )
        country_name = data.get("country_name", "")
        city         = data.get("city", "")
        org          = data.get("asn", "")
        # Score: pulses are reference-based - popular IPs (8.8.8.8 etc.) appear in
        # many pulses simply because they're in traffic logs, not because they're threats.
        # Cap at 60 so OTX alone can't drive the verdict; scale conservatively.
        score = 0 if pulses == 0 else min(60, pulses * 6)
        return {
            "score":        score,
            "pulses":       pulses,
            "note":         note,
            "country_name": country_name,
            "city":         city,
            "org":          org,
            "link":         link,
        }
    except Exception:
        return {"score": 0, "pulses": 0, "link": link}


async def otx_domain(client: httpx.AsyncClient, domain: str) -> Dict:
    link = f"https://otx.alienvault.com/indicator/domain/{domain}"
    if not _otx_key():
        return {"score": 0, "pulses": 0, "link": link}
    try:
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers={"X-OTX-API-KEY": _otx_key()},
        )
        if r.status_code != 200:
            return {"score": 0, "pulses": 0, "link": link}
        data   = r.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        pulse_list = data.get("pulse_info", {}).get("pulses", [])
        note = pulse_list[0].get("name", "") if pulse_list else (
            "No threat intel" if pulses == 0 else ""
        )
        return {
            "score":  min(100, pulses * 10),
            "pulses": pulses,
            "note":   note,
            "link":   link,
        }
    except Exception:
        return {"score": 0, "pulses": 0, "link": link}

# ============================================================
# URLScan  (domain + url)
# ============================================================

async def urlscan_lookup(client: httpx.AsyncClient, query: str, is_url: bool = False) -> Dict:
    """
    URLScan.io search.
    For domains: searches page.domain field.
    For full URLs: submits URL for scanning, then fetches result.
    """
    import logging
    log = logging.getLogger(__name__)

    if is_url:
        # For full URLs, submit for a fresh scan
        import urllib.parse as _up0
        _h0 = _up0.urlparse(query).netloc or _up0.urlparse(query).path or query
        link = f"https://urlscan.io/search/#page.domain:{_h0}"
        try:
            scan_headers = {"Content-Type": "application/json"}
            if _urlscan_key():
                scan_headers["API-Key"] = _urlscan_key()
            else:
                # Without a key we can only search existing scans
                link_search = f"https://urlscan.io/search/#page.domain:{_h0}"
                headers = {}
                import urllib.parse as _up
                _parsed = _up.urlparse(query)
                _host   = _parsed.netloc or _parsed.path
                r = await client.get(
                    "https://urlscan.io/api/v1/search/",
                    headers=headers,
                    params={"q": f"page.domain:{_host}", "size": 3},
                    timeout=10.0,
                )
                if r.status_code == 200:
                    results = r.json().get("results", [])
                    if results:
                        latest = results[0]
                        v = latest.get("verdicts", {}).get("overall", {})
                        mal = v.get("malicious", False)
                        sv  = v.get("score", 0) or 0
                        vs  = "malicious" if mal else ("suspicious" if sv > 30 else "clean")
                        return {"score": max(1, sv) if vs == "clean" else sv, "verdict": vs, "link": link_search}
                return {"score": 1, "verdict": "clean", "link": link_search}

            # Submit URL for scanning
            sub = await client.post(
                "https://urlscan.io/api/v1/scan/",
                headers=scan_headers,
                json={"url": query, "visibility": "public"},
                timeout=10.0,
            )
            if sub.status_code not in (200, 400):  # 400 = already queued
                return {"score": 1, "verdict": "clean", "link": link}

            uuid = sub.json().get("uuid", "")
            if not uuid and sub.status_code == 400:
                # Already in queue or scanned - search for it
                import urllib.parse as _up3
                _parsed3 = _up3.urlparse(query)
                _host3   = _parsed3.netloc or _parsed3.path
                sr = await client.get(
                    "https://urlscan.io/api/v1/search/",
                    headers={"API-Key": _urlscan_key()} if _urlscan_key() else {},
                    params={"q": f"page.domain:{_host3}", "size": 3},
                    timeout=10.0,
                )
                if sr.status_code == 200 and sr.json().get("results"):
                    res = sr.json()["results"][0]
                    v   = res.get("verdicts", {}).get("overall", {})
                    mal = v.get("malicious", False)
                    sv  = v.get("score", 0) or 0
                    vs  = "malicious" if mal else ("suspicious" if sv > 30 else "clean")
                    return {"score": max(1, sv) if vs == "clean" else sv, "verdict": vs, "link": link}
                return {"score": 1, "verdict": "clean", "link": link}

            # Poll for result
            result_url = f"https://urlscan.io/api/v1/result/{uuid}/"
            for attempt in range(4):
                await asyncio.sleep(5)
                pr = await client.get(result_url, timeout=10.0)
                if pr.status_code == 200:
                    pd = pr.json()
                    v  = pd.get("verdicts", {}).get("overall", {})
                    mal = v.get("malicious", False)
                    sv  = v.get("score", 0) or 0
                    vs  = "malicious" if mal else ("suspicious" if sv > 30 else "clean")
                    return {"score": max(1, sv) if vs == "clean" else sv, "verdict": vs, "link": link}
                elif pr.status_code == 404:
                    continue  # not ready yet
            return {"score": 1, "verdict": "clean", "link": link}
        except Exception as e:
            log.error(f"URLScan URL error: {e}")
            return {"score": 0, "verdict": "unknown", "link": link}
    else:
        # Domain search
        link = f"https://urlscan.io/search/#page.domain:{query}"
        try:
            headers = {}
            if _urlscan_key():
                headers["API-Key"] = _urlscan_key()
            r = await client.get(
                "https://urlscan.io/api/v1/search/",
                headers=headers,
                params={"q": f"page.domain:{query}", "size": 5},
                timeout=10.0,
            )
            if r.status_code != 200:
                return {"score": 1, "verdict": "unknown", "link": link}
            results = r.json().get("results", [])
            if not results:
                return {"score": 1, "verdict": "clean", "link": link}
            latest    = results[0]
            verdicts  = latest.get("verdicts", {}).get("overall", {})
            malicious = verdicts.get("malicious", False)
            score_val = verdicts.get("score", 0) or 0
            verdict_str = "malicious" if malicious else ("suspicious" if score_val > 30 else "clean")
            display_score = max(1, min(100, score_val)) if verdict_str == "clean" else min(100, score_val)
            return {"score": display_score, "verdict": verdict_str, "link": link}
        except Exception as e:
            log.error(f"URLScan domain error: {e}")
            return {"score": 0, "verdict": "unknown", "link": link}

# ============================================================
# Google Safe Browsing  (domain + url)
# ============================================================

async def gsb_lookup(client: httpx.AsyncClient, ioc: str) -> Dict:
    """
    Google Safe Browsing v4 API.
    FIX IF YOU GET 403:
      1. Go to console.cloud.google.com/apis/credentials
      2. Click your API key → Application restrictions → select "None"
      3. API restrictions → restrict to "Safe Browsing API" only
      The key must have NO HTTP referrer restrictions (those are browser-only).
    """
    import logging
    log = logging.getLogger(__name__)
    link = f"https://transparencyreport.google.com/safe-browsing/search?url={ioc}"

    if not _gsb_key():
        return {"score": 0, "safe": True, "checked": False, "link": link}
    try:
        payload = {
            "client": {"clientId": "osint-platform", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING",
                                     "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": ioc}],
            },
        }
        r = await client.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={_gsb_key()}",
            json=payload,
            timeout=10.0,
        )
        if r.status_code == 403:
            err = ""
            try:
                err = r.json().get("error", {}).get("message", r.text[:150])
            except Exception:
                err = r.text[:150]
            log.error(
                f"GSB 403: {err} | "
                "FIX: In Google Cloud Console > APIs & Services > Credentials > "
                "click your key > Application restrictions > set to 'None' (not 'HTTP referrers'). "
                "HTTP referrer restrictions block server-side calls."
            )
            return {"score": 0, "safe": True, "checked": False,
                    "error": f"403: {err}", "link": link}

        if r.status_code != 200:
            log.warning(f"GSB HTTP {r.status_code}: {r.text[:100]}")
            return {"score": 0, "safe": True, "checked": False, "link": link}

        matches     = r.json().get("matches", [])
        flagged     = len(matches) > 0
        threat_type = matches[0].get("threatType", "") if flagged else ""
        return {
            "score":       100 if flagged else 1,
            "safe":        not flagged,
            "flagged":     flagged,
            "threat_type": threat_type,
            "checked":     True,
            "link":        link,
        }
    except Exception as e:
        log.error(f"GSB exception: {e}")
        return {"score": 0, "safe": True, "checked": False, "link": link}


async def urlhaus_lookup(client: httpx.AsyncClient, url_or_host: str, is_url: bool = False) -> Dict:
    """
    URLhaus by abuse.ch - free, no API key required.
    Huge database of malware distribution URLs.
    Supports: full URL lookup or host lookup.
    """
    import logging
    log = logging.getLogger(__name__)
    link = f"https://urlhaus.abuse.ch/browse.php?search={url_or_host}"
    try:
        if is_url:
            payload = {"url": url_or_host}
            endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        else:
            payload = {"host": url_or_host}
            endpoint = "https://urlhaus-api.abuse.ch/v1/host/"

        import urllib.parse
        r = await client.post(
            endpoint,
            content=urllib.parse.urlencode(payload).encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "osint-platform/1.0",
            },
            timeout=10.0,
        )
        if r.status_code != 200:
            return {"score": 0, "link": link}

        data   = r.json()
        status = data.get("query_status", "")

        if status in ("no_results", "invalid_url", "invalid_host"):
            return {"score": 0, "status": "clean", "link": link}

        # URL found in URLhaus database
        url_status  = data.get("url_status", "")    # "online", "offline", "unknown"
        threat      = data.get("threat", "")         # e.g. "malware_download"
        tags        = data.get("tags", []) or []
        url_count   = len(data.get("urls", [])) if not is_url else 1

        if url_status == "online" or threat:
            score = min(100, 70 + url_count * 5)
        elif url_status == "offline":
            score = 40  # Was malicious, now offline
        else:
            score = 30

        return {
            "score":      score,
            "url_status": url_status,
            "threat":     threat,
            "tags":       tags,
            "link":       link,
        }
    except Exception as e:
        log.error(f"URLhaus error: {e}")
        return {"score": 0, "link": link}


async def whois_lookup(client: httpx.AsyncClient, domain: str) -> Dict:
    """
    WHOIS lookup via whoisjson.com (free, no key needed).
    Returns registrar, creation date, country and a risk hint.
    """
    import logging
    log = logging.getLogger(__name__)
    link = f"https://whois.domaintools.com/{domain}"
    try:
        r = await client.get(
            f"https://whoisjson.com/api/v1/whois",
            params={"domain": domain},
            headers={"Accept": "application/json"},
            timeout=8.0,
        )
        if r.status_code != 200:
            return {"score": 0, "link": link}
        data = r.json()
        registrar = data.get("registrar", "") or ""
        created   = data.get("creation_date", "") or data.get("created", "") or ""
        country   = data.get("registrant_country", "") or data.get("country", "") or ""
        expires   = data.get("expiry_date", "") or data.get("expires", "") or ""

        # Very new domain = higher risk
        score = 0
        if created:
            try:
                from datetime import datetime as _dt
                # Handle list or string
                created_str = created[0] if isinstance(created, list) else str(created)
                created_dt  = _dt.fromisoformat(created_str[:10])
                age_days    = (_dt.utcnow() - created_dt).days
                if age_days < 30:
                    score = 60  # brand new domain
                elif age_days < 90:
                    score = 30
                elif age_days < 365:
                    score = 10
            except Exception:
                pass

        return {
            "score":     score,
            "registrar": registrar[:60] if registrar else "",
            "created":   str(created)[:10] if created else "",
            "expires":   str(expires)[:10] if expires else "",
            "country":   country,
            "link":      link,
        }
    except Exception as e:
        log.error(f"WHOIS error for {domain}: {e}")
        return {"score": 0, "link": link}

# ============================================================
# ThreatFox  (IP + domain + hash - NOT url)
# ============================================================

async def threatfox(client: httpx.AsyncClient, ioc: str, ioc_type: str = "ip") -> Dict:
    """
    ThreatFox API - free, no key required.
    Supported IOC types: ip_port (ip), domain, md5_hash, sha256_hash.
    Emails and URLs are not supported - returns empty for those.
    """
    link = f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc}"

    # ThreatFox does not support URL or raw email lookups
    if ioc_type in ("url", "email"):
        return {"score": 0, "hits": 0, "link": link}

    import logging
    log = logging.getLogger(__name__)

    try:
        # Build correct search term per type
        # For IPs: ThreatFox stores as "1.2.3.4:port" - search by tag instead for plain IPs
        if ioc_type == "ip":
            payload = {"query": "search_ioc", "search_term": ioc}
        elif ioc_type == "hash":
            # Use hash-specific query for better results
            payload = {"query": "search_hash", "hash": ioc}
        else:
            payload = {"query": "search_ioc", "search_term": ioc}

        r = await client.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "osint-platform/1.0",
            },
            timeout=12.0,
        )
        if r.status_code != 200:
            log.warning(f"ThreatFox HTTP {r.status_code} for {ioc}")
            return {"score": 0, "hits": 0, "link": link}

        data = r.json()
        status = data.get("query_status", "")

        # Handle hash-specific response
        if ioc_type == "hash":
            if status == "hash_not_found" or not data.get("data"):
                return {"score": 0, "hits": 0, "link": link}
            items = data.get("data") if isinstance(data.get("data"), list) else [data.get("data", {})]
            hits = len(items)
            malware = items[0].get("malware_printable", "") if hits else ""
            return {
                "score":   min(100, hits * 20),
                "hits":    hits,
                "malware": malware,
                "link":    link,
            }

        # Generic search_ioc response
        if status in ("no_result", "illegal_search_term") or not data.get("data"):
            return {"score": 0, "hits": 0, "link": link}

        hits = len(data["data"])
        malware = data["data"][0].get("malware_printable", "") if hits else ""
        return {
            "score":   min(100, hits * 15),
            "hits":    hits,
            "malware": malware,
            "link":    link,
        }
    except Exception as e:
        import logging; logging.getLogger(__name__).error(f"ThreatFox error for {ioc}: {e}")
        return {"score": 0, "hits": 0, "link": link}

# ============================================================
# EmailRep
# ============================================================

async def emailrep(client: httpx.AsyncClient, email: str) -> Dict:
    """
    EmailRep.io has disabled unauthenticated API access.
    Return a direct link to their web interface for manual review.
    """
    return {"score": 0, "reputation": "unknown", "suspicious": False, "link": f"https://hunter.io/email-finder#{email}"}

# ============================================================
# Hunter.io
# ============================================================

async def disposable_check(client: httpx.AsyncClient, email: str) -> Dict:
    """
    Returns a direct link to EmailRep for disposable/reputation check.
    EmailRep already covers disposable detection - no separate call needed.
    """
    link = f"https://emailrep.io/{email}"
    return {"score": 0, "link": link}


async def hibp(client: httpx.AsyncClient, email: str) -> Dict:
    """
    HaveIBeenPwned - checks if email appears in known data breaches.
    Requires HIBP_API_KEY in .env (free key at haveibeenpwned.com/API/Key).
    Without a key the source shows score=0 with a link to check manually.
    """
    link = f"https://haveibeenpwned.com/account/{email}"
    if not _hibp_key():
        import logging
        logging.getLogger(__name__).info(f"HIBP: no API key set - skipping API call, link only")
        return {"score": 0, "breaches": 0, "no_key": True, "link": link}
    try:
        r = await client.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={
                "hibp-api-key": _hibp_key(),
                "User-Agent":   "osint-platform/1.0",
            },
            params={"truncateResponse": "false"},
            timeout=10.0,
        )
        if r.status_code == 404:
            return {"score": 0, "breaches": 0, "breach_names": [], "link": link}
        if r.status_code == 401:
            return {"score": 0, "breaches": 0, "error": "invalid_key", "link": link}
        if r.status_code != 200:
            return {"score": 0, "breaches": 0, "link": link}
        data  = r.json()
        count = len(data)
        names = [b.get("Name", "") for b in data[:5]]
        # Score: each breach adds risk - 5+ = suspicious, 8+ = malicious threshold
        score = min(100, count * 10)
        import logging
        logging.getLogger(__name__).info(f"HIBP [{email}]: {count} breaches → score={score}")
        return {
            "score":        score,
            "breaches":     count,
            "breach_names": names,
            "link":         link,
        }
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"HIBP error: {e}")
        return {"score": 0, "breaches": 0, "link": link}


# ============================================================
# Shodan  (IP only - host info, open ports)
# ============================================================

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

async def shodan_ip(client: httpx.AsyncClient, ip: str) -> Dict:
    link = f"https://www.shodan.io/host/{ip}"
    if not SHODAN_API_KEY:
        return {"score": 0, "ports": [], "link": link}
    try:
        r = await client.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_API_KEY},
        )
        if r.status_code != 200:
            return {"score": 0, "ports": [], "link": link}
        data  = r.json()
        ports = data.get("ports", [])
        vulns = list(data.get("vulns", {}).keys())
        org   = data.get("org", "") or data.get("isp", "")
        # score based on open ports and known vulns
        port_risk = min(30, len(ports) * 3)
        vuln_risk = min(70, len(vulns) * 20)
        score     = min(100, port_risk + vuln_risk)
        return {
            "score":  score,
            "ports":  ports[:10],
            "vulns":  vulns[:5],
            "org":    org,
            "link":   link,
        }
    except Exception:
        return {"score": 0, "ports": [], "link": link}

# ============================================================
# GEO enrichment from OTX / VT response data
# ============================================================

def build_geo(vt_data: Dict, abuse_data: Dict, otx_data: Dict) -> Dict:
    geo: Dict[str, Any] = {}
    # OTX is most complete for geo
    for key in ("country_name", "city", "org"):
        val = otx_data.get(key, "")
        if val:
            geo[key] = val
    # Supplement from AbuseIPDB
    if not geo.get("country_name") and abuse_data.get("country"):
        geo["country_name"] = abuse_data["country"]
    if abuse_data.get("isp"):
        geo["isp"] = abuse_data["isp"]
    if abuse_data.get("domain"):
        geo["domain"] = abuse_data["domain"]
    if abuse_data.get("usageType"):
        geo["usageType"] = abuse_data["usageType"]
    # VT can give org / country
    if vt_data.get("org") and not geo.get("org"):
        geo["org"] = vt_data["org"]
    if vt_data.get("country") and not geo.get("country_name"):
        geo["country_name"] = vt_data["country"]
    return geo

# ============================================================
# PIPELINES
# ============================================================

async def enrich_ip_async(ip: str) -> Dict:
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        vt_r, ab_r, otx_r, tf_r, sh_r = await asyncio.gather(
            vt_ip(c, ip),
            abuse(c, ip),
            otx_ip(c, ip),
            threatfox(c, ip, "ip"),
            shodan_ip(c, ip),
        )
        scrape_data = await scrape(c, ip)

        sources = {
            "VirusTotal": vt_r,
            "AbuseIPDB":  ab_r,
            "OTX":        otx_r,
            "ThreatFox":  tf_r,
            "Shodan":     sh_r,
        }

        geo    = build_geo(vt_r, ab_r, otx_r)
        # Supplement geo with Shodan org
        if sh_r.get("org") and not geo.get("org"):
            geo["org"] = sh_r["org"]

        risk   = generate_risk_score(sources, scrape_data)
        mitre  = map_to_mitre_from_sources(sources, scrape_data, "ip")
        owasp  = map_to_owasp(sources, scrape_data, "ip")
        report = generate_full_report(ip, "ip", risk, mitre, sources, scrape_data, owasp=owasp)
        summary = generate_summary(report)

        narrative   = generate_ai_narrative(ip, "ip", risk.get("cvss_score", 0), sources, mitre, geo)
        ai_analysis = await generate_ai_analysis_async(
            ip, "ip", risk.get("cvss_score", 0), risk.get("verdict", "benign"),
            risk.get("confidence", 0), sources, mitre, geo,
        )
        return {**report, "summary": summary, "narrative": narrative, "ai_analysis": ai_analysis, "geo": geo}


async def enrich_domain_async(domain: str) -> Dict:
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        vt_r, us_r, gsb_r, otx_r, whois_r = await asyncio.gather(
            vt_domain(c, domain),
            urlscan_lookup(c, domain),
            gsb_lookup(c, domain),
            otx_domain(c, domain),
            whois_lookup(c, domain),
        )
        scrape_data = await scrape(c, domain)

        sources = {
            "VirusTotal": vt_r,
            "URLScan":    us_r,
            "GSB":        gsb_r,
            "OTX":        otx_r,
            "WHOIS":      whois_r,
        }

        risk    = generate_risk_score(sources, scrape_data)
        mitre   = map_to_mitre_from_sources(sources, scrape_data, "domain")
        owasp   = map_to_owasp(sources, scrape_data, "domain")
        report  = generate_full_report(domain, "domain", risk, mitre, sources, scrape_data, owasp=owasp)
        summary = generate_summary(report)

        narrative   = generate_ai_narrative(domain, "domain", risk.get("cvss_score", 0), sources, mitre, {})
        ai_analysis = await generate_ai_analysis_async(
            domain, "domain", risk.get("cvss_score", 0), risk.get("verdict", "benign"),
            risk.get("confidence", 0), sources, mitre, {},
        )
        return {**report, "summary": summary, "narrative": narrative, "ai_analysis": ai_analysis, "geo": {}}





async def enrich_url_async(url: str) -> Dict:
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        vt_r, us_r, gsb_r = await asyncio.gather(
            vt_url(c, url),
            urlscan_lookup(c, url, is_url=True),
            gsb_lookup(c, url),
        )
        scrape_data = await scrape(c, url)

        sources = {
            "VirusTotal": vt_r,
            "URLScan":    us_r,
            "GSB":        gsb_r,
        }

        risk    = generate_risk_score(sources, scrape_data)
        mitre   = map_to_mitre_from_sources(sources, scrape_data, "url")
        owasp   = map_to_owasp(sources, scrape_data, "url")
        report  = generate_full_report(url, "url", risk, mitre, sources, scrape_data, owasp=owasp)
        summary = generate_summary(report)

        narrative   = generate_ai_narrative(url, "url", risk.get("cvss_score", 0), sources, mitre, {})
        ai_analysis = await generate_ai_analysis_async(
            url, "url", risk.get("cvss_score", 0), risk.get("verdict", "benign"),
            risk.get("confidence", 0), sources, mitre, {},
        )
        return {**report, "summary": summary, "narrative": narrative, "ai_analysis": ai_analysis, "geo": {}}



async def otx_hash(client: httpx.AsyncClient, file_hash: str) -> Dict:
    link = f"https://otx.alienvault.com/indicator/file/{file_hash}"
    if not _otx_key():
        return {"score": 0, "pulses": 0, "link": link}
    try:
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general",
            headers={"X-OTX-API-KEY": _otx_key()},
        )
        if r.status_code != 200:
            return {"score": 0, "pulses": 0, "link": link}
        data   = r.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        pulse_list = data.get("pulse_info", {}).get("pulses", [])
        note = pulse_list[0].get("name", "") if pulse_list else ""
        return {
            "score":  min(100, pulses * 10),
            "pulses": pulses,
            "note":   note,
            "link":   link,
        }
    except Exception:
        return {"score": 0, "pulses": 0, "link": link}

async def enrich_hash_async(file_hash: str) -> Dict:
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        vt_r, tf_r = await asyncio.gather(
            vt_hash(c, file_hash),
            threatfox(c, file_hash, "hash"),
        )
        scrape_data = await scrape(c, file_hash)

        # MalwareBazaar (abuse.ch) - free, no API key needed
        # MalwareBazaar uses keyword search syntax: md5:HASH or sha256:HASH
        if len(file_hash) == 32:
            mb_search = f"md5:{file_hash}"
        elif len(file_hash) == 64:
            mb_search = f"sha256:{file_hash}"
        else:
            mb_search = file_hash
        mb_link = f"https://bazaar.abuse.ch/browse.php?search={mb_search}"
        ha_r = {"score": 0, "link": mb_link}
        try:
            mb_resp = await c.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": file_hash},
                headers={
                    "User-Agent":   "osint-platform/1.0",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept":       "application/json",
                },
                timeout=12.0,
            )
            if mb_resp.status_code == 200:
                mb_data = mb_resp.json()
                if mb_data.get("query_status") == "hash_found":
                    mb_info = (mb_data.get("data") or [{}])[0]
                    tags    = mb_info.get("tags", []) or []
                    sig     = mb_info.get("signature", "") or mb_info.get("file_type", "")
                    ha_r = {
                        "score":     85,
                        "tags":      tags,
                        "malware":   sig,
                        "file_type": mb_info.get("file_type", ""),
                        "link":      mb_link,
                    }
                elif mb_data.get("query_status") == "hash_not_found":
                    ha_r = {"score": 0, "status": "not found", "link": mb_link}
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"MalwareBazaar lookup error: {e}")

        # OTX hash lookup
        otx_r = {"score": 0, "pulses": 0, "link": f"https://otx.alienvault.com/indicator/file/{file_hash}"}
        if _otx_key():
            try:
                otx_resp = await c.get(
                    f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general",
                    headers={"X-OTX-API-KEY": _otx_key()},
                    timeout=8.0,
                )
                if otx_resp.status_code == 200:
                    otx_data = otx_resp.json()
                    pulses   = otx_data.get("pulse_info", {}).get("count", 0)
                    otx_r    = {
                        "score":  0 if pulses == 0 else min(60, pulses * 6),
                        "pulses": pulses,
                        "link":   f"https://otx.alienvault.com/indicator/file/{file_hash}",
                    }
            except Exception:
                pass

        sources = {
            "VirusTotal":    vt_r,
            "ThreatFox":     tf_r,
            "MalwareBazaar": ha_r,
            "OTX":           otx_r,
        }

        risk    = generate_risk_score(sources, scrape_data)
        mitre   = map_to_mitre_from_sources(sources, scrape_data, "hash")
        owasp   = map_to_owasp(sources, scrape_data, "hash")
        report  = generate_full_report(file_hash, "hash", risk, mitre, sources, scrape_data, owasp=owasp)
        summary = generate_summary(report)

        narrative   = generate_ai_narrative(file_hash, "hash", risk.get("cvss_score", 0), sources, mitre, {})
        ai_analysis = await generate_ai_analysis_async(
            file_hash, "hash", risk.get("cvss_score", 0), risk.get("verdict", "benign"),
            risk.get("confidence", 0), sources, mitre, {},
        )
        return {**report, "summary": summary, "narrative": narrative, "ai_analysis": ai_analysis, "geo": {}}



async def abstract_email(client: httpx.AsyncClient, email: str) -> Dict:
    """
    Abstract API email validation - free tier, 100 req/month.
    Checks deliverability, disposable, MX records, SMTP validity.
    Set ABSTRACT_API_KEY in .env to enable.
    https://app.abstractapi.com/api/email-validation
    """
    import logging
    key  = os.getenv("ABSTRACT_API_KEY", "")
    link = f"https://emailvalidation.abstractapi.com/v1/?api_key=demo&email={email}"
    if not key:
        return {"score": 0, "link": "https://app.abstractapi.com/api/email-validation"}
    try:
        r = await client.get(
            "https://emailvalidation.abstractapi.com/v1/",
            params={"api_key": key, "email": email},
            timeout=8.0,
        )
        if r.status_code != 200:
            return {"score": 0, "link": link}
        d = r.json()
        is_disposable  = d.get("is_disposable_email",   {}).get("value", False)
        is_valid_fmt   = d.get("is_valid_format",        {}).get("value", True)
        is_mx_found    = d.get("is_mx_found",            {}).get("value", True)
        is_smtp_valid  = d.get("is_smtp_valid",          {}).get("value", True)
        deliverability = d.get("deliverability", "UNKNOWN")  # DELIVERABLE/UNDELIVERABLE/UNKNOWN

        score = 0
        if is_disposable:          score = max(score, 70)
        if not is_mx_found:        score = max(score, 50)
        if deliverability == "UNDELIVERABLE": score = max(score, 40)
        if not is_smtp_valid:      score = max(score, 30)
        if not is_valid_fmt:       score = max(score, 60)

        return {
            "score":         score,
            "disposable":    is_disposable,
            "deliverable":   deliverability,
            "mx_found":      is_mx_found,
            "smtp_valid":    is_smtp_valid,
            "link":          f"https://emailvalidation.abstractapi.com/v1/?api_key={key}&email={email}",
        }
    except Exception as e:
        logging.getLogger(__name__).error(f"Abstract email error: {e}")
        return {"score": 0, "link": link}


async def hunter_email_verify(client: httpx.AsyncClient, email: str) -> Dict:
    """
    Hunter.io email verifier - free tier 25 req/month.
    Verifies email deliverability and catches-all / disposable status.
    Set HUNTER_API_KEY in .env to enable.
    https://hunter.io/api-documentation/v2#email-verifier
    """
    import logging
    key  = os.getenv("HUNTER_API_KEY", "")
    link = f"https://hunter.io/verify/{email}"
    if not key:
        return {"score": 0, "link": link}
    try:
        r = await client.get(
            "https://api.hunter.io/v2/email-verifier",
            params={"email": email, "api_key": key},
            timeout=8.0,
        )
        if r.status_code != 200:
            return {"score": 0, "link": link}
        d      = r.json().get("data", {})
        status = d.get("status", "unknown")   # valid/invalid/accept_all/webmail/disposable/unknown
        score  = 0
        if status == "disposable":  score = 70
        elif status == "invalid":   score = 50
        elif status == "accept_all": score = 15
        return {
            "score":  score,
            "status": status,
            "result": d.get("result", ""),    # deliverable/undeliverable/risky
            "link":   link,
        }
    except Exception as e:
        logging.getLogger(__name__).error(f"Hunter verify error: {e}")
        return {"score": 0, "link": link}


async def hibp_pastes(client: httpx.AsyncClient, email: str) -> Dict:
    """
    HaveIBeenPwned Pastes - checks if email appears in paste sites (Pastebin etc).
    Uses the same HIBP_API_KEY as the breach check. Free key at haveibeenpwned.com/API/Key.
    """
    link = f"https://haveibeenpwned.com/account/{email}#pastes"
    if not _hibp_key():
        return {"score": 0, "pastes": 0, "link": link}
    try:
        r = await client.get(
            f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
            headers={"hibp-api-key": _hibp_key(), "User-Agent": "osint-platform/1.0"},
            timeout=10.0,
        )
        if r.status_code == 404:
            return {"score": 0, "pastes": 0, "paste_sources": [], "link": link}
        if r.status_code != 200:
            return {"score": 0, "pastes": 0, "link": link}
        data   = r.json()
        count  = len(data)
        sources = list({p.get("Source", "") for p in data[:5]})
        # Each paste appearance is a significant exposure signal
        score  = min(100, count * 15)
        return {"score": score, "pastes": count, "paste_sources": sources, "link": link}
    except Exception as e:
        import logging; logging.getLogger(__name__).error(f"HIBP pastes error: {e}")
        return {"score": 0, "pastes": 0, "link": link}


async def disify_check(client: httpx.AsyncClient, email: str) -> Dict:
    """
    Disify - free, no API key required.
    GET https://disify.com/api/email/{email}
    Fields: format, domain, disposable, dns, whitelist, confidence, signals
    """
    api_url = f"https://disify.com/api/email/{email}"
    try:
        r = await client.get(api_url, timeout=8.0)
        if r.status_code != 200:
            return {"score": 0, "disposable": False, "link": api_url}
        d             = r.json()
        is_disposable = d.get("disposable",  False)
        is_dns        = d.get("dns",         True)
        is_format     = d.get("format",      True)
        confidence    = d.get("confidence",  0)
        signals       = d.get("signals",     [])
        domain        = d.get("domain",      "")
        score = 0
        if is_disposable:                          score = max(score, 75)
        if not is_dns:                             score = max(score, 45)
        if not is_format:                          score = max(score, 55)
        if "blacklist_exact" in signals:           score = max(score, 85)
        if confidence >= 80 and is_disposable:     score = max(score, 85)
        import logging
        logging.getLogger(__name__).info(
            f"Disify [{email}]: disposable={is_disposable} dns={is_dns} signals={signals} conf={confidence} → score={score}"
        )
        return {
            "score":      score,
            "disposable": is_disposable,
            "dns_valid":  is_dns,
            "format_ok":  is_format,
            "confidence": confidence,
            "signals":    signals,
            "domain":     domain,
            "link":       api_url,
        }
    except Exception as e:
        import logging; logging.getLogger(__name__).error(f"Disify error: {e}")
        return {"score": 0, "disposable": False, "link": api_url}


async def mailcheck(client: httpx.AsyncClient, email: str) -> Dict:
    """
    MailCheck.ai - free, no API key required.
    GET https://api.mailcheck.ai/email/{email}
    Fields: disposable, mx, spam, role_account, domain_age_in_days
    """
    api_url = f"https://api.mailcheck.ai/email/{email}"
    try:
        r = await client.get(api_url, timeout=8.0)
        if r.status_code == 429:
            import logging; logging.getLogger(__name__).warning("MailCheck rate limited (429)")
            return {"score": 0, "rate_limited": True, "link": api_url}
        if r.status_code != 200:
            return {"score": 0, "link": api_url}
        d              = r.json()
        disposable     = d.get("disposable",     False)
        has_mx         = d.get("mx",             True)
        spam           = d.get("spam",           False)
        role_account   = d.get("role_account",   False)
        domain_age     = d.get("domain_age_in_days", 9999)
        score = 0
        if disposable:            score = max(score, 75)
        if spam:                  score = max(score, 80)
        if not has_mx:            score = max(score, 45)
        if domain_age < 30:       score = max(score, 60)
        elif domain_age < 180:    score = max(score, 30)
        import logging
        logging.getLogger(__name__).info(
            f"MailCheck [{email}]: disposable={disposable} mx={has_mx} spam={spam} age={domain_age}d → score={score}"
        )
        return {
            "score":       score,
            "disposable":  disposable,
            "mx_valid":    has_mx,
            "spam":        spam,
            "role":        role_account,
            "domain_age":  domain_age,
            "link":        api_url,
        }
    except Exception as e:
        import logging; logging.getLogger(__name__).error(f"MailCheck error: {e}")
        return {"score": 0, "link": api_url}



async def emailable_check(client: httpx.AsyncClient, email: str) -> Dict:
    """
    Emailable - email verification API with web UI at emailable.com.
    Set EMAILABLE_API_KEY in .env (free tier available).
    GET https://api.emailable.com/v1/verify?email={email}&api_key={key}
    Returns: state, score, disposable, role, free, reason, safe_to_send
    """
    key  = os.getenv("EMAILABLE_API_KEY", "")
    link = f"https://api.emailable.com/v1/verify?email={email}&api_key={key}"
    api_link = f"https://api.emailable.com/v1/verify?email={email}&api_key={key}" if key else "https://emailable.com/"
    link = api_link
    if not key:
        return {"score": 0, "link": "https://emailable.com/", "no_key": True}
    try:
        r = await client.get(
            "https://api.emailable.com/v1/verify",
            params={"email": email, "api_key": key},
            timeout=10.0,
        )
        if r.status_code == 402:
            return {"score": 0, "link": link, "error": "credits_exhausted"}
        if r.status_code != 200:
            return {"score": 0, "link": link}
        d           = r.json()
        state       = d.get("state",       "unknown")   # deliverable/undeliverable/risky/unknown
        em_score    = d.get("score",       0) or 0      # 0-100 quality score
        disposable  = d.get("disposable",  False)
        role        = d.get("role",        False)
        free        = d.get("free",        False)
        accept_all  = d.get("accept_all",  False)
        reason      = d.get("reason",      "")
        safe        = d.get("safe_to_send",False)

        # Convert emailable score (quality 0-100) to risk score (inverted)
        # High quality score = low risk; low quality = high risk
        risk_score = 0
        if state == "undeliverable":     risk_score = max(risk_score, 70)
        if state == "risky":             risk_score = max(risk_score, 55)
        if disposable:                   risk_score = max(risk_score, 80)
        if not safe and state != "deliverable": risk_score = max(risk_score, 50)
        if em_score < 20:                risk_score = max(risk_score, 65)

        import logging
        logging.getLogger(__name__).info(
            f"Emailable [{email}]: state={state} score={em_score} disposable={disposable} risk={risk_score}"
        )
        return {
            "score":      risk_score,
            "state":      state,
            "em_score":   em_score,
            "disposable": disposable,
            "role":       role,
            "free":       free,
            "reason":     reason,
            "safe":       safe,
            "link":       link,
        }
    except Exception as e:
        import logging; logging.getLogger(__name__).error(f"Emailable error: {e}")
        return {"score": 0, "link": link}

async def enrich_email_async(email: str) -> Dict:
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        disify_r, mailcheck_r, emailable_r = await asyncio.gather(
            disify_check(c, email),
            mailcheck(c, email),
            emailable_check(c, email),
        )
        sources = {
            "Disify":    disify_r,
            "MailCheck": mailcheck_r,
            "Emailable": emailable_r,
        }

        mitre   = map_to_mitre_from_sources(sources, None, "email")
        owasp   = map_to_owasp(sources, None, "email")
        risk    = generate_risk_score(sources, None)
        report  = generate_full_report(email, "email", risk, mitre, sources, None, owasp=owasp)
        summary = generate_summary(report)

        narrative   = generate_ai_narrative(email, "email", risk.get("cvss_score", 0), sources, mitre, {})
        ai_analysis = await generate_ai_analysis_async(
            email, "email", risk.get("cvss_score", 0), risk.get("verdict", "benign"),
            risk.get("confidence", 0), sources, mitre, {},
        )
        return {**report, "summary": summary, "narrative": narrative, "ai_analysis": ai_analysis, "geo": {}}

# ============================================================
# SYNC WRAPPERS
# ============================================================

def enrich_ip(i):       return asyncio.run(enrich_ip_async(i))
def enrich_domain(d):   return asyncio.run(enrich_domain_async(d))
def enrich_url(u):      return asyncio.run(enrich_url_async(u))
def enrich_hash(h):     return asyncio.run(enrich_hash_async(h))
def enrich_email(e):    return asyncio.run(enrich_email_async(e))
