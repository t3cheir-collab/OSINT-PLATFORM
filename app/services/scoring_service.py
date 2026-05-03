from typing import Dict

# ============================================================
# SOURCE WEIGHTS  (0-100 scale throughout - no /10 normalization)
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

# Authoritative sources - thresholds for override
# OTX is community-contributed and prone to false positives on major infrastructure
# (Google DNS, Cloudflare etc. appear in OTX pulses because malware *uses* them,
#  not because they are C2. OTX alone cannot trigger malicious.)
AUTHORITATIVE_THRESHOLDS = {
    "VirusTotal":      {"malicious": 70, "suspicious": 40},
    "AbuseIPDB":       {"malicious": 70, "suspicious": 35},
    "ThreatFox":       {"malicious": 50, "suspicious": 20},
    "GSB":             {"malicious": 80, "suspicious": 50},
    "MalwareBazaar":   {"malicious": 60, "suspicious": 30},
    "OTX":             {"malicious": 85, "suspicious": 55},  # raised - OTX alone cannot trigger malicious
    "Disify":          {"malicious": 60, "suspicious": 30},
    "MailCheck":       {"malicious": 75, "suspicious": 45},
    "Emailable":       {"malicious": 60, "suspicious": 30},
}

# Sources that are high-confidence enough to trigger malicious verdict alone
# (community-sourced feeds like OTX require corroboration)
SOLO_AUTHORITATIVE = {"VirusTotal", "AbuseIPDB", "ThreatFox", "GSB", "MalwareBazaar"}


def calculate_confidence(sources: Dict) -> int:
    if not sources:
        return 0
    active = sum(1 for s in sources.values() if isinstance(s, dict) and s.get("score", 0) > 0)
    total  = len(sources)
    return round((active / total) * 100)


def calculate_threat_score(sources: Dict) -> float:
    """Weighted sum - stays on 0-100 scale."""
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

    # - Authoritative override ------------------------
    # Rules:
    # 1. A solo-authoritative source (VT, AbuseIPDB, ThreatFox, GSB, MalwareBazaar)
    #    can trigger malicious alone if it crosses its threshold.
    # 2. Community sources (OTX) require corroboration: at least one other source
    #    must also be suspicious/malicious before OTX can push the verdict to malicious.
    # 3. Any authoritative source crossing its suspicious threshold - suspicious
    #    (unless already overridden to malicious).

    malicious_solo    = []   # high-confidence sources at malicious level
    malicious_community = [] # community sources at malicious level
    suspicious_any    = []   # any source at suspicious level

    for src, thresholds in AUTHORITATIVE_THRESHOLDS.items():
        src_score = 0
        if isinstance(sources.get(src), dict):
            src_score = sources[src].get("score", 0) or 0

        if src_score >= thresholds["malicious"]:
            if src in SOLO_AUTHORITATIVE:
                malicious_solo.append(src)
            else:
                malicious_community.append(src)
        elif src_score >= thresholds["suspicious"]:
            suspicious_any.append(src)

    # Determine auth_verdict
    auth_verdict = None
    if malicious_solo:
        # High-confidence source alone is enough
        auth_verdict = "malicious"
    elif malicious_community:
        # Community source (OTX) needs at least one corroborating signal
        corroborated = len(suspicious_any) > 0 or raw_score >= 45
        auth_verdict = "malicious" if corroborated else "suspicious"
    elif suspicious_any:
        auth_verdict = "suspicious"

    # - Final verdict ----------------------------─
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

    _log.getLogger(__name__).info(f"Verdict: {verdict}")

    # display_score: show highest authoritative source score when malicious override triggered
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

    cvss_score = round(raw_score / 10.0, 2)

    return {
        "cvss_score":    cvss_score,
        "raw_score":     display_score,
        "risk_level":    risk_level,
        "confidence":    confidence,
        "verdict":       verdict,
    }