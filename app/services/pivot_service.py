import re
from typing import List

IP_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"


def extract_pivots_from_text(text: str) -> List[str]:
    pivots = set()

    if not text:
        return []

    pivots.update(re.findall(IP_REGEX, text))
    pivots.update(re.findall(DOMAIN_REGEX, text))

    return list(pivots)[:10]  # limit for safety