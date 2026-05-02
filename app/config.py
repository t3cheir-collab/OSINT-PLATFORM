import os
from dotenv import load_dotenv

# Load .env from the project root — this runs first before any service imports
load_dotenv()

class Settings:
    # VirusTotal
    vt_api_key:          str = os.getenv("VT_API_KEY", "")
    # AbuseIPDB
    abuseipdb_api_key:   str = os.getenv("ABUSEIPDB_API_KEY", "")
    # AlienVault OTX
    otx_api_key:         str = os.getenv("OTX_API_KEY", "")
    # URLScan
    urlscan_api_key:     str = os.getenv("URLSCAN_API_KEY", "")
    # Google Safe Browsing
    google_safe_api_key: str = os.getenv("GOOGLE_SAFE_API_KEY", "")
    # Hunter.io
    hunter_api_key:      str = os.getenv("HUNTER_API_KEY", "")
    # HaveIBeenPwned
    hibp_api_key:        str = os.getenv("HIBP_API_KEY", "")
    # Anthropic Claude
    anthropic_api_key:   str = os.getenv("ANTHROPIC_API_KEY", "")
    # Shodan
    shodan_api_key:      str = os.getenv("SHODAN_API_KEY", "")
    # PhishTank (optional — register at phishtank.org/api_register.php)
    phishtank_api_key:   str = os.getenv("PHISHTANK_API_KEY", "")

settings = Settings()