"""
ai_service.py
-------
Calls the Anthropic Claude API to generate a real AI analysis of OSINT
findings for each IOC report.

Requires:  ANTHROPIC_API_KEY environment variable.
Falls back gracefully to an empty string if the key is missing or the
call fails — the rest of the report still renders normally.
"""

import os
import json
import httpx
from typing import Dict, List, Any

# Import from config.py which already called load_dotenv()
try:
    from app.config import settings as _cfg
    def _get_api_key() -> str:
        return _cfg.anthropic_api_key or os.getenv("ANTHROPIC_API_KEY", "")
except ImportError:
    def _get_api_key() -> str:
        return os.getenv("ANTHROPIC_API_KEY", "")

CLAUDE_MODEL      = "claude-sonnet-4-5"
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
TIMEOUT           = httpx.Timeout(30.0)


# - Build a compact data packet to send to Claude --------------

def _build_prompt(
    ioc: str,
    ioc_type: str,
    risk_score: float,
    verdict: str,
    confidence: int,
    sources: Dict[str, Any],
    mitre: List,
    geo: Dict,
) -> str:
    """Serialise the OSINT findings into a structured prompt for Claude."""

    # Source findings — only include fields that are meaningful
    source_lines = []
    for name, data in sources.items():
        if not isinstance(data, dict):
            continue
        score  = data.get("score", 0)
        fields = []
        # Type-specific detail fields
        for key in ("detections", "engines", "pulses", "note", "confidence",
                    "isp", "usageType", "verdict", "safe", "threat_type",
                    "breaches", "breach_names", "reputation", "suspicious",
                    "deliverability", "status", "hits", "malware",
                    "categories", "org", "ports", "vulns"):
            val = data.get(key)
            if val is not None and val != "" and val != [] and val is not False:
                fields.append(f"{key}={val}")
        detail = ", ".join(fields) if fields else "score=0 (clean)"
        source_lines.append(f"  - {name}: score={score}/100 | {detail}")

    sources_block = "\n".join(source_lines) if source_lines else "  - No sources returned data"

    # MITRE tactics
    mitre_list = []
    for m in (mitre or []):
        if isinstance(m, dict):
            mitre_list.append(f"{m.get('id','')} {m.get('name','')}".strip())
        else:
            mitre_list.append(str(m))
    mitre_str = ", ".join(mitre_list) if mitre_list else "None identified"

    # Geo
    geo_parts = []
    for k in ("country_name", "city", "isp", "usageType", "org"):
        v = geo.get(k, "")
        if v:
            geo_parts.append(f"{k}: {v}")
    geo_str = " | ".join(geo_parts) if geo_parts else "N/A"

    return f"""You are a senior threat intelligence analyst. Analyse the following OSINT findings for a {ioc_type.upper()} indicator and write a concise, professional intelligence report.

IOC:        {ioc}
Type:       {ioc_type.upper()}
Verdict:    {verdict.upper()}
Risk Score: {risk_score}/10
Confidence: {confidence}%
Geo:        {geo_str}

Intelligence Source Results:
{sources_block}

MITRE ATT&CK: {mitre_str}

Write a structured analysis with these exact sections:
1. **Executive Summary** — 2-3 sentences: what this indicator is, overall threat assessment, and key risk factor.
2. **Source Analysis** — for each source that returned data, one sentence explaining what it found and what that means in context. Skip sources with no findings.
3. **Threat Assessment** — explain the verdict in detail: why is this malicious/suspicious/benign? What patterns support this conclusion?
4. **Recommended Actions** — specific, prioritised SOC actions (block, monitor, investigate, pivot, etc.) relevant to this IOC type.
5. **Analyst Notes** — any caveats, false positive considerations, or additional context an analyst should know.

Be direct, technical, and concise. Use SOC/threat intel terminology. No filler phrases. Maximum 400 words."""


# - Call Claude API ------------------------------

async def generate_ai_analysis_async(
    ioc: str,
    ioc_type: str,
    risk_score: float,
    verdict: str,
    confidence: int,
    sources: Dict[str, Any],
    mitre: List,
    geo: Dict,
) -> str:
    """Async: call Claude API and return the AI analysis string."""
    api_key = _get_api_key()
    if not api_key:
        return ""

    prompt = _build_prompt(
        ioc, ioc_type, risk_score, verdict, confidence, sources, mitre, geo
    )

    payload = {
        "model":      CLAUDE_MODEL,
        "max_tokens": 1024,
        "messages":   [{"role": "user", "content": prompt}],
    }

    headers = {
        "x-api-key":         api_key,
        "anthropic-version": "2023-06-01",
        "content-type":      "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.post(ANTHROPIC_API_URL, json=payload, headers=headers)
            if r.status_code != 200:
                import logging
                logging.error(f"Claude API error {r.status_code}: {r.text[:200]}")
                return ""
            data = r.json()
            blocks = data.get("content", [])
            text   = " ".join(b.get("text", "") for b in blocks if b.get("type") == "text")
            return text.strip()
    except Exception as e:
        import logging
        logging.error(f"Claude API exception: {e}")
        return ""


def generate_ai_analysis(
    ioc: str,
    ioc_type: str,
    risk_score: float,
    verdict: str,
    confidence: int,
    sources: Dict[str, Any],
    mitre: List,
    geo: Dict,
) -> str:
    """Sync wrapper for use in non-async contexts."""
    import asyncio
    try:
        return asyncio.run(generate_ai_analysis_async(
            ioc, ioc_type, risk_score, verdict, confidence, sources, mitre, geo
        ))
    except Exception:
        return ""