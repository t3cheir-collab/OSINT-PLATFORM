import re


IP_REGEX = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
DOMAIN_REGEX = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
HASH_REGEX = r"^[A-Fa-f0-9]{32,64}$"


def validate_ioc(ioc: str, ioc_type: str):

    if ioc_type == "ip":
        return re.match(IP_REGEX, ioc)

    if ioc_type == "domain":
        return re.match(DOMAIN_REGEX, ioc)

    if ioc_type == "hash":
        return re.match(HASH_REGEX, ioc)

    return False