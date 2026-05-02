from typing import Dict, List, Any

# ============================================================
# FULL REPORT BUILDER
# ============================================================

def generate_full_report(
    ioc: str,
    ioc_type: str,
    risk: Dict,
    mitre: List,
    sources: Dict,
    scrape: Any,
    owasp: List = None,
) -> Dict:
    return {
        "ioc":      ioc,
        "type":     ioc_type,

        # Scoring
        "score":      risk.get("cvss_score", 0),
        "raw_score":  risk.get("raw_score", round(risk.get("cvss_score", 0) * 10)),
        "risk_level": risk.get("risk_level", "LOW"),
        "verdict":    risk.get("verdict", "benign"),
        "confidence": risk.get("confidence", 0),

        # Intel
        "mitre_tactics": mitre or [],
        "owasp":         owasp or [],
        "sources":       sources or {},
        "scrape":        scrape,

        # Convenience link map (auto-built from sources)
        "links": {
            name: data.get("link")
            for name, data in (sources or {}).items()
            if isinstance(data, dict) and data.get("link")
        },
    }


# ============================================================
# SUMMARY LINES  —  the SOC-style one-liner block
# Format example:
#   OSINT on [8.8.8.8]:
#   VirusTotal: 0/94 | Google LLC
#   AbuseIPDB: 0% Confidence | google.com | Content Delivery Network
#   AlienVault: 0 Pulses | Known False Positive
#   Location: United States of America
# ============================================================

def build_summary_lines(ioc: str, ioc_type: str, sources: Dict, geo: Dict) -> List[str]:
    lines = [f"OSINT on [{ioc}]:"]

    vt  = sources.get("VirusTotal", {})
    ab  = sources.get("AbuseIPDB",  {})
    otx = sources.get("OTX",        {})
    tf  = sources.get("ThreatFox",  {})
    us  = sources.get("URLScan",    {})
    gsb = sources.get("GSB",        {})
    er  = sources.get("EmailRep",   {})
    hu  = sources.get("Hunter",     {})
    hp  = sources.get("HaveIBeenPwned", {}) or sources.get("HIBP", {})

    # - VirusTotal ---------------------
    if vt:
        det  = vt.get("detections", 0)
        eng  = vt.get("engines", 94) or 94
        org  = vt.get("org", "") or geo.get("org", "")
        cats = vt.get("categories", "")
        line = f"VirusTotal: {det}/{eng}"
        if org:   line += f" | {org}"
        if cats and not org:
            line += f" | {cats}"
        lines.append(line)

    # - AbuseIPDB  (IP only) -----------------
    if ab and ioc_type == "ip":
        conf  = ab.get("confidence", ab.get("score", 0))
        isp   = ab.get("isp", "") or geo.get("isp", "")
        usage = ab.get("usageType", "")
        line  = f"AbuseIPDB: {conf}% Confidence"
        if isp:   line += f" | {isp}"
        if usage: line += f" | {usage}"
        lines.append(line)

    # - AlienVault OTX -------------------
    if otx:
        pulses = otx.get("pulses", 0)
        note   = otx.get("note", "")
        if not note and pulses == 0:
            note = "Known False Positive"
        line = f"AlienVault: {pulses} Pulses"
        if note:
            line += f" | {note}"
        lines.append(line)

    # - ThreatFox ----------------------
    if tf and ioc_type in ("ip", "domain", "hash"):
        hits    = tf.get("hits", 0)
        malware = tf.get("malware", "")
        line    = f"ThreatFox: {hits} Hits"
        if malware:
            line += f" | {malware}"
        lines.append(line)

    # - URLScan  (domain + url) ---------------
    if us and ioc_type in ("domain", "url"):
        verdict_str = us.get("verdict", "unknown")
        score_val   = us.get("score", 0)
        line        = f"URLScan: {verdict_str.capitalize()}"
        if score_val:
            line += f" | Score: {score_val}"
        lines.append(line)

    # - Google Safe Browsing  (domain + url) ---------
    if gsb and ioc_type in ("domain", "url"):
        safe        = gsb.get("safe", True)
        threat_type = gsb.get("threat_type", "")
        line        = f"Google Safe Browsing: {'Safe' if safe else 'Flagged'}"
        if threat_type:
            line += f" | {threat_type.replace('_', ' ').title()}"
        lines.append(line)

    # - EmailRep  (email) ------------------
    if er and ioc_type == "email":
        rep  = er.get("reputation", "unknown")
        susp = er.get("suspicious", False)
        line = f"EmailRep: {rep.capitalize()} reputation | Suspicious: {'Yes' if susp else 'No'}"
        lines.append(line)

    # - Hunter  (email) -------------------
    if hu and ioc_type == "email":
        deliv  = hu.get("deliverability", 0)
        status = hu.get("status", "unknown")
        lines.append(f"Hunter: {deliv}% Deliverability | {status.replace('_', ' ').title()}")

    # - HIBP  (email) --------------------
    if hp and ioc_type == "email":
        breaches = hp.get("breaches", 0)
        names    = hp.get("breach_names", [])
        line     = f"HIBP: {breaches} breach{'es' if breaches != 1 else ''} found"
        if names:
            line += f" | {', '.join(names[:3])}"
        lines.append(line)

    # - Geo location  (IP only) ---------------
    if ioc_type == "ip":
        country = geo.get("country_name", "")
        city    = geo.get("city", "")
        if country:
            loc = f"Location: {country}"
            if city:
                loc += f", {city}"
            lines.append(loc)

    return lines


# ============================================================
# STRUCTURED SUMMARY  (human-readable text block)
# ============================================================

def generate_summary(report: dict) -> str:
    """
    Analyst Assessment — a narrative investigation report written as a case story.
    """
    from datetime import datetime

    ioc        = report.get("ioc", "")
    ioc_type   = report.get("type", "ip")
    verdict    = report.get("verdict", "benign")
    risk_level = report.get("risk_level", "LOW")
    confidence = report.get("confidence", 0)
    score      = report.get("score", 0)
    raw_score  = report.get("raw_score", round(score * 10))
    sources    = report.get("sources", {})
    mitre      = report.get("mitre_tactics", [])
    owasp      = report.get("owasp", [])
    geo        = report.get("geo", {})
    ts         = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    vt  = sources.get("VirusTotal", {}) or {}
    ab  = sources.get("AbuseIPDB",  {}) or {}
    otx = sources.get("OTX",        {}) or {}
    tf  = sources.get("ThreatFox",  {}) or {}
    us  = sources.get("URLScan",    {}) or {}
    gsb = sources.get("GSB",        {}) or {}
    er  = sources.get("EmailRep",   {}) or {}
    hp  = sources.get("HaveIBeenPwned", {}) or {}
    mb  = sources.get("MalwareBazaar",  {}) or {}
    sh  = sources.get("Shodan",     {}) or {}
    uh  = sources.get("URLhaus",    {}) or {}

    vt_det  = vt.get("detections", 0)
    vt_eng  = vt.get("engines",    0)
    tf_hits = tf.get("hits", 0)
    tf_mal  = tf.get("malware", "")
    otx_p   = otx.get("pulses", 0)

    # Verdict opening
    if verdict == "malicious":
        opener = (
            f"This indicator has been assessed as MALICIOUS with {confidence}% confidence "
            f"across {len(sources)} intelligence sources. "
        )
        if vt_det > 0:
            opener += (
                f"VirusTotal returned {vt_det}/{vt_eng} positive detections, "
                f"confirming active classification by multiple security vendors. "
            )
        if tf_hits > 0:
            opener += f"ThreatFox recorded {tf_hits} hit(s)"
            if tf_mal:
                opener += f" associated with the {tf_mal} malware family"
            opener += ". "
        if ab.get("confidence", 0) >= 50:
            opener += (
                f"AbuseIPDB assigns an abuse confidence of {ab.get('confidence')}%, "
                f"corroborating prior malicious activity from this address. "
            )
        action = (
            "IMMEDIATE ACTION REQUIRED: Block this indicator across all perimeter controls "
            "(firewall, proxy, SIEM, EDR). Initiate incident response procedures and pivot "
            "to associated infrastructure to map the full attack surface."
        )
    elif verdict == "suspicious":
        opener = (
            f"This indicator has been flagged as SUSPICIOUS with {confidence}% confidence. "
            f"While not conclusively malicious, multiple intelligence signals warrant further investigation. "
        )
        if vt_det > 0:
            opener += f"{vt_det} of {vt_eng} VirusTotal engines returned positive detections. "
        action = (
            "RECOMMENDED ACTION: Add to watchlist and monitor actively. "
            "Conduct sandbox analysis if a file or URL. Review network logs for "
            "connections to/from this indicator. Consider blocking pending further review."
        )
    else:
        opener = (
            f"This indicator has been assessed as BENIGN with {confidence}% confidence. "
            f"No significant threat signals were detected across {len(sources)} intelligence sources. "
        )
        if otx_p > 0:
            opener += (
                f"AlienVault OTX shows {otx_p} pulse reference(s) — "
                f"these likely reflect this indicator appearing in captured traffic logs "
                f"rather than direct malicious association. "
            )
        action = (
            "No immediate action required. Continue passive monitoring. "
            "If this indicator appears in combination with other confirmed malicious IOCs, "
            "re-evaluate risk posture accordingly."
        )

    # Source findings
    findings = []
    if vt_eng > 0:
        if vt_det == 0:
            findings.append(f"VirusTotal: Clean across {vt_eng} engines — no malware signatures detected.")
        else:
            name_part = f" ({vt.get('name','')})" if vt.get("name") else ""
            findings.append(f"VirusTotal: {vt_det}/{vt_eng} engines flagged as malicious{name_part}.")

    if ioc_type == "ip" and ab:
        conf  = ab.get("confidence", 0)
        isp   = ab.get("isp", "")
        usage = ab.get("usageType", "")
        tor   = ab.get("isTor", False)
        line  = f"AbuseIPDB: {conf}% abuse confidence"
        if isp:    line += f" | ISP: {isp}"
        if usage:  line += f" | {usage}"
        if tor:    line += " | Tor Exit Node confirmed"
        findings.append(line + ".")

    if otx_p > 0:
        note = otx.get("note", "")
        line = f"AlienVault OTX: {otx_p} threat pulse(s)"
        if note: line += f" — {note}"
        findings.append(line + ".")

    if tf_hits > 0:
        line = f"ThreatFox: {tf_hits} IOC record(s)"
        if tf_mal: line += f" — malware family: {tf_mal}"
        findings.append(line + ".")

    if mb.get("malware"):
        ft = mb.get("file_type", "")
        findings.append(f"MalwareBazaar: Identified as {mb['malware']}{(' (' + ft + ')') if ft else ''}.")

    if ioc_type in ("domain", "url"):
        if us.get("verdict"):
            findings.append(f"URLScan: {us.get('verdict','unknown').capitalize()} verdict.")
        if not gsb.get("safe", True) and gsb.get("checked", True):
            tt = gsb.get("threat_type","").replace("_"," ").title() or "Threat detected"
            findings.append(f"Google Safe Browsing: UNSAFE — {tt}.")
        if uh.get("score", 0) > 0:
            findings.append(f"URLhaus: Present in malware distribution database — {uh.get('threat','unknown')}.")

    if ioc_type == "email":
        if er:
            rep  = er.get("reputation","unknown")
            susp = er.get("suspicious", False)
            findings.append(f"EmailRep: {rep.capitalize()} reputation{' — suspicious activity flagged' if susp else ''}.")
        if hp and hp.get("breaches", 0) > 0:
            names = hp.get("breach_names", [])
            findings.append(
                f"HaveIBeenPwned: {hp['breaches']} data breach(es) — "
                f"{', '.join(names[:3]) if names else 'credentials potentially compromised'}."
            )

    if sh.get("ports"):
        findings.append(
            f"Shodan: {len(sh['ports'])} open port(s): {', '.join(str(p) for p in sh['ports'][:6])}."
        )

    if geo.get("country_name"):
        loc = f"Geolocation: {geo['country_name']}"
        if geo.get("city"):      loc += f", {geo['city']}"
        if geo.get("isp"):       loc += f" | {geo['isp']}"
        if geo.get("usageType"): loc += f" | {geo['usageType']}"
        findings.append(loc + ".")

    findings_block = "\n".join(f"  {chr(8226)} {f}" for f in findings) if findings else "  No specific source findings."

    # MITRE + OWASP
    mitre_str = (
        " | ".join(
            f"{m.get('id','')} {m.get('name','')}" if isinstance(m, dict) else str(m)
            for m in mitre[:6]
        ) if mitre else "None identified"
    )
    owasp_str = (
        " | ".join(
            f"{o.get('id','')} {o.get('name','')}" if isinstance(o, dict) else str(o)
            for o in owasp[:4]
        ) if owasp else "None identified"
    )

    divider = "\u2501" * 45
    thin    = "\u2500" * 45
    return (
        f"ANALYST ASSESSMENT REPORT\n"
        f"Generated: {ts}\n"
        f"{divider}\n\n"
        f"INDICATOR:  {ioc}\n"
        f"TYPE:       {ioc_type.upper()}\n"
        f"VERDICT:    {verdict.upper()}   |   SCORE: {raw_score}/100   |   CONFIDENCE: {confidence}%\n\n"
        f"INVESTIGATION SUMMARY\n{thin}\n"
        f"{opener}\n\n"
        f"SOURCE INTELLIGENCE\n{thin}\n"
        f"{findings_block}\n\n"
        f"THREAT FRAMEWORK\n{thin}\n"
        f"MITRE ATT&CK:  {mitre_str}\n"
        f"OWASP Top 10:  {owasp_str}\n\n"
        f"ANALYST RECOMMENDATION\n{thin}\n"
        f"{action}\n\n"
        f"{divider}"
    )


# ============================================================
# AI NARRATIVE  (rule-based, called from enrichment pipelines)
# ============================================================

def generate_ai_narrative(
    ioc: str,
    ioc_type: str,
    risk_score: float,
    sources: Dict,
    mitre: List,
    geo: Dict,
) -> str:
    """
    Rule-based narrative — quick structured summary used as a
    fallback / supplement to the Claude AI analysis.
    """
    verdict = (
        "malicious"  if risk_score >= 7 else
        "suspicious" if risk_score >= 4 else
        "benign"
    )

    mitre_str = (
        ", ".join([m.get("id", str(m)) if isinstance(m, dict) else str(m) for m in mitre])
        if mitre else "None identified"
    )

    observations = []
    vt  = sources.get("VirusTotal", {}) or {}
    ab  = sources.get("AbuseIPDB",  {}) or {}
    otx = sources.get("OTX",        {}) or {}
    tf  = sources.get("ThreatFox",  {}) or {}
    us  = sources.get("URLScan",    {}) or {}
    gsb = sources.get("GSB",        {}) or {}
    er  = sources.get("EmailRep",   {}) or {}
    hp  = sources.get("HaveIBeenPwned", {}) or {}
    mb  = sources.get("MalwareBazaar",  {}) or {}

    if vt:
        det = vt.get("detections", 0)
        eng = vt.get("engines", 94) or 94
        observations.append(
            f"VirusTotal: {det}/{eng} engines flagged as {'malicious' if det > 0 else 'clean'}."
        )

    if ab and ioc_type == "ip":
        conf = ab.get("confidence", 0)
        isp  = ab.get("isp", "")
        observations.append(
            f"AbuseIPDB: {conf}% abuse confidence{(' — ' + isp) if isp else ''}."
        )

    if otx:
        pulses = otx.get("pulses", 0)
        note   = otx.get("note", "")
        observations.append(
            f"AlienVault OTX: {pulses} pulse(s){(' — ' + note) if note else ''}."
        )

    if tf and ioc_type in ("ip", "domain", "hash"):
        hits    = tf.get("hits", 0)
        malware = tf.get("malware", "")
        if hits > 0:
            observations.append(
                f"ThreatFox: {hits} hit(s){(' — ' + malware) if malware else ''}."
            )
        else:
            observations.append("ThreatFox: no known malware associations.")

    if mb.get("malware"):
        observations.append(f"MalwareBazaar: {mb['malware']}.")

    if us and ioc_type in ("domain", "url"):
        observations.append(f"URLScan: {us.get('verdict', 'unknown')} verdict.")

    if gsb and ioc_type in ("domain", "url"):
        safe = gsb.get("safe", True)
        observations.append(
            f"Google Safe Browsing: {'safe' if safe else 'UNSAFE — ' + gsb.get('threat_type','flagged')}."
        )

    if er and ioc_type == "email":
        rep  = er.get("reputation", "unknown")
        susp = er.get("suspicious", False)
        observations.append(
            f"EmailRep: {rep} reputation{'— suspicious' if susp else ''}."
        )

    if hp and ioc_type == "email":
        breaches = hp.get("breaches", 0)
        observations.append(
            f"HIBP: {breaches} breach(es) found."
        )

    if ioc_type == "ip" and geo:
        country = geo.get("country_name", "")
        isp_val = geo.get("isp", "")
        if country:
            observations.append(
                f"Location: {country}{(', ISP: ' + isp_val) if isp_val else ''}."
            )

    obs_block = "\n".join(f"  • {o}" for o in observations) if observations else "  • No source data returned."

    action_map = {
        "malicious":  "Block immediately. Initiate incident response and pivot to related infrastructure.",
        "suspicious": "Investigate further via sandbox/network review. Add to watchlist.",
        "benign":     "No immediate action. Continue passive monitoring.",
    }

    return (
        f"Threat Intelligence Narrative\n"
        f"{'-' * 40}\n"
        f"Indicator: {ioc}  |  Type: {ioc_type.upper()}  |  Verdict: {verdict.upper()}\n\n"
        f"Key Observations:\n{obs_block}\n\n"
        f"MITRE ATT&CK: {mitre_str}\n\n"
        f"Recommended Action:\n  {action_map.get(verdict, action_map['benign'])}"
    )