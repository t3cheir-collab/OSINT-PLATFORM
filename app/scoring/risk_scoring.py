def calculate_risk_score(results):

    score = 0

    if results.get("virustotal", {}).get("malicious", 0) > 5:
        score += 40

    if results.get("otx"):
        score += 25

    if results.get("abuseipdb", {}).get("confidence", 0) > 50:
        score += 35

    if score > 70:
        verdict = "malicious"
    elif score > 40:
        verdict = "suspicious"
    else:
        verdict = "benign"

    return score, verdict
