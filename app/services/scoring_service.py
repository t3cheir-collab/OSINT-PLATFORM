from typing import Dict

# ============================================================
# SOURCE WEIGHTS  (0-100 scale throughout — no /10 normalization)
# ============================================================

SOURCE_WEIGHTS = {
    "VirusTotal":      0.35,
    "AbuseIPDB":       0.30,
    "ThreatFox":       0.25,
    "GSB":             0.25,
    "OTX":             0.20,
    "URLScan":         0.12,
    "Shodan":          0.08,
    "Disify":          0.30,
    "Emailable":       0.30,
    "MailCheck":       0.18,
    "MalwareBazaar":   0.28,
    "WHOIS":           0.10,
}

# Authoritative sources — if any of these crosses its threshold alone,
# it overrides the weighted average for the verdict
AUTHORITATIVE_THRESHOLDS = {
    "VirusTotal":      {"malicious": 70, "suspicious": 40},
    "AbuseIPDB":       {"malicious": 70, "suspicious": 35},
    "ThreatFox":       {"malicious": 50, "suspicious": 20},
    "GSB":             {"malicious": 80, "suspicious": 50},
    "MalwareBazaar":   {"malicious": 60, "suspicious": 30},
    "OTX":             {"malicious": 55, "suspicious": 25},
    "Disify":          {"malicious": 60, "suspicious": 30},
    "MailCheck":       {"malicious": 75, "suspicious": 45},
    "Emailable":       {"malicious": 60, "suspicious": 30},
}


def calculate_confidence(sources: Dict) -> int:
    if not sources:
        return 0
    active = sum(1 for s in sources.values() if isinstance(s, dict) and s.get("score", 0) > 0)
    total  = len(sources)
    return round((active / total) * 100)


def calculate_threat_score(sources: Dict) -> float:
    """Weighted sum — stays on 0-100 scale."""
    total = 0.0
    for name, data in sources.items():
        if not isinstance(data, dict):
            continue
        weight = SOURCE_WEIGHTS.get(name, 0.08)
        score  = data.get("score", 0) or 0
        total += score * weight
    return round(total, 2)


def calculate_context_score(scrape: str) -> float:
    if not scrape:
        return 0.0
    keywords = [
        "malware", "phishing", "ransomware", "botnet",
        "exploit", "c2", "command and control", "trojan",
        "infostealer", "backdoor", "rat ", "keylogger",
    ]
    hits = sum(1 for k in keywords if k in scrape.lower())
    return min(15.0, hits * 3.0)


def generate_risk_score(sources: Dict, scrape: str = None) -> Dict:
    threat     = calculate_threat_score(sources)
    confidence = calculate_confidence(sources)
    context    = calculate_context_score(scrape)
    raw_score  = min(100.0, threat + context)

    # - Authoritative override ---------------
    # If any single authoritative source clearly flags malicious,
    # don't let clean sources average it away
    auth_verdict = None
    for src, thresholds in AUTHORITATIVE_THRESHOLDS.items():
        src_score = 0
        if isinstance(sources.get(src), dict):
            src_score = sources[src].get("score", 0) or 0
        if src_score >= thresholds["malicious"]:
            auth_verdict = "malicious"
            break
        elif src_score >= thresholds["suspicious"] and auth_verdict != "malicious":
            auth_verdict = "suspicious"

    # - Final verdict --------------------
    import logging as _log
    _log.getLogger(__name__).info(
        f"Scoring: raw={raw_score:.1f} auth={auth_verdict} "
        f"sources={[(k,v.get('score',0)) for k,v in sources.items() if isinstance(v,dict)]}"
    )
    if auth_verdict == "malicious" or raw_score >= 60:
        verdict    = "malicious"
        risk_level = "HIGH"
    elif auth_verdict == "suspicious" or raw_score >= 25:
        verdict    = "suspicious"
        risk_level = "MEDIUM"
    else:
        verdict    = "benign"
        risk_level = "LOW"
    _log.getLogger(__name__).info(f"Verdict: {verdict}, display_score will be set next")

    # display_score: if an authoritative source triggered malicious verdict,
    # show the highest authoritative source score (not the weighted average)
    # so a hash with 67/69 VT detections shows 99 not 35
    max_auth_score = 0
    for src in AUTHORITATIVE_THRESHOLDS:
        if isinstance(sources.get(src), dict):
            s = sources[src].get("score", 0) or 0
            if s > max_auth_score:
                max_auth_score = s

    if auth_verdict == "malicious" and max_auth_score > raw_score:
        display_score = round(max_auth_score)
    else:
        display_score = round(raw_score)

    # Keep cvss_score as 0-10 for backward compat with narrative/report
    cvss_score = round(raw_score / 10.0, 2)

    return {
        "cvss_score":    cvss_score,
        "raw_score":     display_score,   # display_score on 0-100
        "risk_level":    risk_level,
        "confidence":    confidence,
        "verdict":       verdict,
    }