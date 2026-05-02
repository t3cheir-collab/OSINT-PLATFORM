from typing import List, Dict, Any

# ============================================================
# MITRE ATT&CK TECHNIQUE MAPPING
# Maps keywords found in OSINT scrape/source data to real
# ATT&CK technique IDs with URLs, names, and tactic context.
# ============================================================

MITRE_TECHNIQUES: List[Dict[str, Any]] = [
    # - Initial Access -------------------
    {
        "id": "T1566", "name": "Phishing",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "url": "https://attack.mitre.org/techniques/T1566/",
        "keywords": ["phishing", "spearphish", "malicious email", "credential harvesting", "lure"],
    },
    {
        "id": "T1566.001", "name": "Spearphishing Attachment",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
        "keywords": ["spearphishing attachment", "malicious attachment", "malicious document"],
    },
    {
        "id": "T1566.002", "name": "Spearphishing Link",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
        "keywords": ["spearphishing link", "malicious link", "phishing url", "phishing link"],
    },
    {
        "id": "T1190", "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "keywords": ["exploit", "vulnerability", "cve", "remote code execution", "rce", "sqli", "sql injection"],
    },
    {
        "id": "T1133", "name": "External Remote Services",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "url": "https://attack.mitre.org/techniques/T1133/",
        "keywords": ["vpn", "rdp", "remote desktop", "citrix", "external remote"],
    },
    # - Execution ---------------------
    {
        "id": "T1059", "name": "Command and Scripting Interpreter",
        "tactic": "Execution", "tactic_id": "TA0002",
        "url": "https://attack.mitre.org/techniques/T1059/",
        "keywords": ["powershell", "cmd", "bash", "shell", "script", "dropper", "payload", "malware execution"],
    },
    {
        "id": "T1204", "name": "User Execution",
        "tactic": "Execution", "tactic_id": "TA0002",
        "url": "https://attack.mitre.org/techniques/T1204/",
        "keywords": ["user execution", "malicious file", "user clicked", "macro"],
    },
    # - Persistence --------------------
    {
        "id": "T1547", "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence", "tactic_id": "TA0003",
        "url": "https://attack.mitre.org/techniques/T1547/",
        "keywords": ["persistence", "registry run", "autorun", "startup", "autostart", "boot"],
    },
    {
        "id": "T1053", "name": "Scheduled Task/Job",
        "tactic": "Persistence", "tactic_id": "TA0003",
        "url": "https://attack.mitre.org/techniques/T1053/",
        "keywords": ["scheduled task", "cron", "crontab", "at job"],
    },
    {
        "id": "T1078", "name": "Valid Accounts",
        "tactic": "Persistence", "tactic_id": "TA0003",
        "url": "https://attack.mitre.org/techniques/T1078/",
        "keywords": ["valid account", "stolen credential", "compromised account", "credential abuse"],
    },
    # - Privilege Escalation ----------------
    {
        "id": "T1068", "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "url": "https://attack.mitre.org/techniques/T1068/",
        "keywords": ["privilege escalation", "sudo exploit", "kernel exploit", "local privilege"],
    },
    # - Defense Evasion ------------------
    {
        "id": "T1027", "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "url": "https://attack.mitre.org/techniques/T1027/",
        "keywords": ["obfuscation", "obfuscated", "packing", "packed", "encoded", "evasion"],
    },
    {
        "id": "T1562", "name": "Impair Defenses",
        "tactic": "Defense Evasion", "tactic_id": "TA0005",
        "url": "https://attack.mitre.org/techniques/T1562/",
        "keywords": ["disable antivirus", "disable firewall", "impair defense", "kill security"],
    },
    # - Credential Access -----------------
    {
        "id": "T1555", "name": "Credentials from Password Stores",
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "url": "https://attack.mitre.org/techniques/T1555/",
        "keywords": ["credential dump", "password theft", "password store", "keychain", "credential stealer"],
    },
    {
        "id": "T1110", "name": "Brute Force",
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "keywords": ["brute force", "bruteforce", "password spray", "credential stuffing"],
    },
    {
        "id": "T1056", "name": "Input Capture",
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "url": "https://attack.mitre.org/techniques/T1056/",
        "keywords": ["keylogger", "keylogging", "input capture", "form grabbing"],
    },
    # - Discovery ---------------------
    {
        "id": "T1046", "name": "Network Service Discovery",
        "tactic": "Discovery", "tactic_id": "TA0007",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "keywords": ["network scan", "port scan", "nmap", "service enumeration", "enumeration"],
    },
    {
        "id": "T1082", "name": "System Information Discovery",
        "tactic": "Discovery", "tactic_id": "TA0007",
        "url": "https://attack.mitre.org/techniques/T1082/",
        "keywords": ["system information", "os fingerprint", "fingerprinting", "recon"],
    },
    # - Lateral Movement ------------------
    {
        "id": "T1021", "name": "Remote Services",
        "tactic": "Lateral Movement", "tactic_id": "TA0008",
        "url": "https://attack.mitre.org/techniques/T1021/",
        "keywords": ["lateral movement", "pivot", "smb", "wmi", "psexec", "remote service"],
    },
    # - Command and Control ----------------
    {
        "id": "T1071", "name": "Application Layer Protocol",
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "keywords": ["c2", "command and control", "beaconing", "beacon", "http c2", "dns c2", "c&c"],
    },
    {
        "id": "T1090", "name": "Proxy",
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "url": "https://attack.mitre.org/techniques/T1090/",
        "keywords": ["proxy", "tor", "vpn tunnel", "anonymization", "anonymizer"],
    },
    {
        "id": "T1219", "name": "Remote Access Software",
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "url": "https://attack.mitre.org/techniques/T1219/",
        "keywords": ["rat", "remote access", "remote access trojan", "teamviewer", "anydesk"],
    },
    # - Exfiltration --------------------
    {
        "id": "T1048", "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "url": "https://attack.mitre.org/techniques/T1048/",
        "keywords": ["data exfiltration", "data leak", "exfiltrate", "exfil", "data theft"],
    },
    # - Impact -----------------------
    {
        "id": "T1486", "name": "Data Encrypted for Impact",
        "tactic": "Impact", "tactic_id": "TA0040",
        "url": "https://attack.mitre.org/techniques/T1486/",
        "keywords": ["ransomware", "encrypt files", "ransom", "file encryption"],
    },
    {
        "id": "T1499", "name": "Endpoint Denial of Service",
        "tactic": "Impact", "tactic_id": "TA0040",
        "url": "https://attack.mitre.org/techniques/T1499/",
        "keywords": ["ddos", "dos", "denial of service", "flood"],
    },
    # - Malware families (map to closest technique) ----
    {
        "id": "T1587.001", "name": "Develop Capabilities: Malware",
        "tactic": "Resource Development", "tactic_id": "TA0042",
        "url": "https://attack.mitre.org/techniques/T1587/001/",
        "keywords": ["malware", "trojan", "infostealer", "stealer", "backdoor", "botnet", "worm", "virus"],
    },
]

# ============================================================
# OWASP TOP 10 MAPPING
# Maps IOC characteristics to relevant OWASP categories.
# ============================================================

OWASP_TECHNIQUES: List[Dict[str, Any]] = [
    {
        "id": "A01:2021", "name": "Broken Access Control",
        "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "keywords": ["access control", "privilege escalation", "unauthorized access", "idor", "path traversal"],
    },
    {
        "id": "A02:2021", "name": "Cryptographic Failures",
        "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "keywords": ["cleartext", "weak encryption", "ssl", "tls", "certificate", "crypto", "hash collision"],
    },
    {
        "id": "A03:2021", "name": "Injection",
        "url": "https://owasp.org/Top10/A03_2021-Injection/",
        "keywords": ["sql injection", "sqli", "xss", "cross-site scripting", "command injection", "ldap injection", "injection"],
    },
    {
        "id": "A04:2021", "name": "Insecure Design",
        "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        "keywords": ["insecure design", "security misconfiguration", "design flaw"],
    },
    {
        "id": "A05:2021", "name": "Security Misconfiguration",
        "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "keywords": ["misconfiguration", "default credential", "exposed service", "open port", "exposed admin", "directory listing"],
    },
    {
        "id": "A06:2021", "name": "Vulnerable and Outdated Components",
        "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        "keywords": ["outdated", "vulnerable component", "cve", "unpatched", "known vulnerability"],
    },
    {
        "id": "A07:2021", "name": "Identification and Authentication Failures",
        "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "keywords": ["credential", "brute force", "password", "authentication", "session hijack", "weak password", "credential stuffing"],
    },
    {
        "id": "A08:2021", "name": "Software and Data Integrity Failures",
        "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        "keywords": ["supply chain", "untrusted source", "integrity", "tamper", "unsigned"],
    },
    {
        "id": "A09:2021", "name": "Security Logging and Monitoring Failures",
        "url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
        "keywords": ["no logging", "log evasion", "evade detection", "cover tracks"],
    },
    {
        "id": "A10:2021", "name": "Server-Side Request Forgery",
        "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        "keywords": ["ssrf", "server-side request forgery", "internal request", "metadata endpoint"],
    },
]

# ============================================================
# SOURCE → TECHNIQUE ENRICHMENT
# Some sources return fields we can directly map to techniques
# even without scrape text.
# ============================================================

def _techniques_from_sources(sources: Dict, ioc_type: str) -> List[str]:
    """Derive MITRE technique IDs from source data fields."""
    matched = set()

    vt  = sources.get("VirusTotal", {}) or {}
    tf  = sources.get("ThreatFox",  {}) or {}
    otx = sources.get("OTX",        {}) or {}
    ab  = sources.get("AbuseIPDB",  {}) or {}
    gsb = sources.get("GSB",        {}) or {}
    us  = sources.get("URLScan",    {}) or {}

    vt_score = vt.get("score", 0) or 0
    vt_dets  = vt.get("detections", 0) or 0

    # - VT detections on any IOC type -----------
    if vt_dets > 0:
        matched.add("T1587.001")   # Malware / malicious file/url/domain
    if vt_dets >= 5:
        matched.add("T1071")       # Likely C2 or malicious comms
    if vt_dets >= 20:
        matched.add("T1566")       # High detection = likely phishing or delivery

    # - ThreatFox malware family --------------
    malware = (tf.get("malware") or "").lower()
    tf_hits = tf.get("hits", 0) or 0
    if tf_hits > 0:
        matched.add("T1587.001")
    if malware:
        if any(k in malware for k in ["ransomware", "locker", "crypt", "wannacry", "ryuk"]):
            matched.add("T1486")
        if any(k in malware for k in ["rat", "remote", "backdoor", "njrat", "asyncrat", "quasar"]):
            matched.add("T1219")
        if any(k in malware for k in ["stealer", "infostealer", "keylog", "redline", "raccoon", "vidar"]):
            matched.add("T1056")
        if any(k in malware for k in ["loader", "dropper", "downloader", "smoke", "bumblebee"]):
            matched.add("T1059")
        if any(k in malware for k in ["bot", "botnet", "spam", "emotet", "dridex"]):
            matched.add("T1071")
        if any(k in malware for k in ["miner", "cryptominer", "xmrig"]):
            matched.add("T1499")

    # - VT categories (domain/url) -------------
    cats = (vt.get("categories") or "").lower()
    if "phishing" in cats:
        matched.add("T1566")
    if "malware" in cats or "malicious" in cats:
        matched.add("T1587.001")
    if "c2" in cats or "command" in cats or "cnc" in cats:
        matched.add("T1071")
    if "spam" in cats:
        matched.add("T1071")

    # - AbuseIPDB ---------------------
    usage = (ab.get("usageType") or "").lower()
    ab_score = ab.get("score", 0) or 0
    if "tor" in usage or ab.get("isTor"):
        matched.add("T1090")
    if "proxy" in usage or ab.get("isProxy"):
        matched.add("T1090")
    if "datacenter" in usage or "hosting" in usage or "vpn" in usage:
        matched.add("T1090")
    if ab_score >= 50:
        matched.add("T1071")   # Likely C2/scanning/attack traffic

    # - OTX pulses --------------------
    pulses = otx.get("pulses", 0) or 0
    note   = (otx.get("note") or "").lower()
    if pulses > 0:
        matched.add("T1587.001")
    for kw, tid in [("c2","T1071"),("botnet","T1071"),("phishing","T1566"),
                    ("ransomware","T1486"),("stealer","T1056"),("scan","T1046")]:
        if kw in note:
            matched.add(tid)

    # - GSB flagged --------------------
    if not gsb.get("safe", True):
        tt = gsb.get("threat_type", "")
        if "SOCIAL_ENGINEERING" in tt:
            matched.add("T1566")
        if "MALWARE" in tt:
            matched.add("T1587.001")
        if not tt:
            matched.add("T1566")   # GSB flagged = phishing/malware delivery

    # - URLScan verdict ------------------
    if us.get("verdict") in ("malicious", "suspicious"):
        matched.add("T1566")

    # - IOC type context -----------------
    if ioc_type == "email":
        matched.add("T1566")       # Emails used in phishing
        matched.add("T1566.001")   # Spearphishing
    if ioc_type == "hash" and vt_dets > 0:
        matched.add("T1204")       # User Execution (file was executed)

    return list(matched)


# ============================================================
# MAIN MAPPING FUNCTION
# ============================================================

def map_to_mitre(scrape_text: str) -> List[Dict]:
    """
    Returns a list of matched MITRE technique dicts.
    Falls back to empty list if no scrape text.
    """
    if not scrape_text:
        return []

    text    = scrape_text.lower()
    matched = {}

    for technique in MITRE_TECHNIQUES:
        if any(kw in text for kw in technique["keywords"]):
            # Deduplicate by base technique ID
            base_id = technique["id"].split(".")[0]
            if base_id not in matched:
                matched[base_id] = technique.copy()

    return list(matched.values())


def map_to_mitre_from_sources(sources: Dict, scrape_text: str, ioc_type: str) -> List[Dict]:
    """
    Full mapping: combines scrape-text keyword matching with
    direct source-field inference for richer coverage.
    """
    # 1. Keyword-based from scrape text
    text_matches = map_to_mitre(scrape_text)
    matched_ids  = {t["id"].split(".")[0] for t in text_matches}

    # 2. Source-field inference — returns list of technique ID strings
    source_ids = _techniques_from_sources(sources, ioc_type)
    for tid in source_ids:
        base = tid.split(".")[0]
        if base not in matched_ids:
            for t in MITRE_TECHNIQUES:
                if t["id"] == tid or t["id"] == base or t["id"].startswith(base + "."):
                    matched_ids.add(base)
                    text_matches.append(t.copy())
                    break
            else:
                # Technique ID not in our list — add a minimal entry
                matched_ids.add(base)
                text_matches.append({
                    "id": tid, "name": tid,
                    "tactic": "Unknown", "tactic_id": "",
                    "url": f"https://attack.mitre.org/techniques/{tid.replace('.','/')}/"
                })

    return text_matches


def map_to_owasp(sources: Dict, scrape_text: str, ioc_type: str) -> List[Dict]:
    """
    Maps IOC findings to relevant OWASP Top 10 categories.
    Most relevant for url/domain/hash IOC types.
    """
    # OWASP is most relevant for web-facing indicators
    if ioc_type not in ("url", "domain", "hash", "ip"):
        return []

    text    = (scrape_text or "").lower()
    matched = {}

    # Keyword scan on scrape text
    for item in OWASP_TECHNIQUES:
        if any(kw in text for kw in item["keywords"]):
            matched[item["id"]] = item.copy()

    # Source-field enrichment
    vt   = sources.get("VirusTotal", {})
    gsb  = sources.get("GSB", {})
    us   = sources.get("URLScan", {})
    ab   = sources.get("AbuseIPDB", {})
    tf   = sources.get("ThreatFox", {})
    mb   = sources.get("MalwareBazaar", {})

    # Hash-specific OWASP mapping — malicious files map to software integrity + vulns
    if ioc_type == "hash":
        vt_dets = vt.get("detections", 0) if isinstance(vt, dict) else 0
        if vt_dets > 0:
            # A08: Software and Data Integrity Failures (malicious/tampered file)
            matched["A08:2021"] = next((o for o in OWASP_TECHNIQUES if o["id"] == "A08:2021"), {})
        if vt_dets >= 10:
            # A06: Vulnerable and Outdated Components (widespread malware)
            matched["A06:2021"] = next((o for o in OWASP_TECHNIQUES if o["id"] == "A06:2021"), {})
        malware_name = ""
        if isinstance(tf, dict):  malware_name = (tf.get("malware") or "").lower()
        if isinstance(mb, dict):  malware_name = malware_name or (mb.get("malware") or "").lower()
        if any(k in malware_name for k in ["ransomware","locker","crypt"]):
            matched["A09:2021"] = next((o for o in OWASP_TECHNIQUES if o["id"] == "A09:2021"), {})
        if any(k in malware_name for k in ["stealer","keylog","infostealer","credential"]):
            matched["A07:2021"] = next((o for o in OWASP_TECHNIQUES if o["id"] == "A07:2021"), {})

    # GSB flagged → likely injection or phishing
    if isinstance(gsb, dict) and not gsb.get("safe", True):
        tt = gsb.get("threat_type", "")
        if "SOCIAL_ENGINEERING" in tt:
            matched["A07:2021"] = next((o for o in OWASP_TECHNIQUES if o["id"] == "A07:2021"), {})
        if "MALWARE" in tt:
            matched["A06:2021"] = next((o for o in OWASP_TECHNIQUES if o["id"] == "A06:2021"), {})

    # VT categories
    cats = vt.get("categories", "").lower() if isinstance(vt, dict) else ""
    if "phishing" in cats:
        matched["A07:2021"] = next((o for o in OWASP_TECHNIQUES if o["id"] == "A07:2021"), {})
    if any(k in cats for k in ["malware", "exploit"]):
        matched["A06:2021"] = next((o for o in OWASP_TECHNIQUES if o["id"] == "A06:2021"), {})

    # AbuseIPDB with open ports (from Shodan data passed through sources)
    sh = sources.get("Shodan", {})
    if isinstance(sh, dict):
        ports = sh.get("ports", [])
        if ports:
            matched["A05:2021"] = next((o for o in OWASP_TECHNIQUES if o["id"] == "A05:2021"), {})
        vulns = sh.get("vulns", [])
        if vulns:
            matched["A06:2021"] = next((o for o in OWASP_TECHNIQUES if o["id"] == "A06:2021"), {})

    return [v for v in matched.values() if v]