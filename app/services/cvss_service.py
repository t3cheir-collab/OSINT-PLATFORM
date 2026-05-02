# app/services/cvss_service.py

from typing import Dict, Any


def calculate_cvss_score(results: Dict[str, Any]) -> float:
    """
    Lightweight IOC risk scoring inspired by CVSS.

    NOTE:
    This is NOT a true vulnerability CVSS.
    It is an IOC risk heuristic for analysts.
    """

    if not results:
        return 0.0

    scores = []
    malicious_sources = 0

    for source, data in results.items():
        if not isinstance(data, dict):
            continue

        score = data.get("score", 0)
        scores.append(score)

        if score >= 70:
            malicious_sources += 1

    if not scores:
        return 0.0

    avg_score = sum(scores) / len(scores)

    # --- weighting logic ---
    weight_bonus = min(malicious_sources * 5, 20)

    final_score = min(avg_score + weight_bonus, 100)

    return round(final_score, 2)