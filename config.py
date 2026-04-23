"""
Configuration module for OSINT Search Tool
"""
import os
from dotenv import load_dotenv

load_dotenv()

# =====================================================
# DATABASE
# =====================================================
DB_FILE = os.getenv("DB_FILE", "data/threat_intel_db.json")

# Set MONGODB_URI to use MongoDB instead of the local JSON file.
# Example: mongodb://user:pass@localhost:27017/threatintel
MONGODB_URI = os.getenv("MONGODB_URI", "")

# Set POSTGRES_URI to use PostgreSQL instead of the local JSON file.
# Example: postgresql://user:pass@localhost:5432/threatintel
POSTGRES_URI = os.getenv("POSTGRES_URI", "")

# =====================================================
# API KEYS & ENDPOINTS (Loaded once from .env)
# =====================================================
VT_KEY = os.getenv("VT_API_KEY", "")
HA_KEY = os.getenv("HA_API_KEY", "")
MB_API_KEY = os.getenv("MB_API_KEY", "")
MALSHARE_API_KEY = os.getenv("MALSHARE_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
CYMRU_API_USERNAME = os.getenv("CYMRU_API_USERNAME", "")
CYMRU_API_PASSWORD = os.getenv("CYMRU_API_PASSWORD", "")
ANYRUN_API_KEY = os.getenv("ANYRUN_API_KEY", "")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
XFORCE_API_KEY = os.getenv("XFORCE_API_KEY", "")
XFORCE_API_PASSWORD = os.getenv("XFORCE_API_PASSWORD", "")

# API URLs
MB_API_URL = "https://mb-api.abuse.ch/api/v1/"
VT_API_URL = "https://www.virustotal.com/api/v3"
OTX_API_URL = "https://otx.alienvault.com/api/v1"
MALSHARE_API_URL = "https://malshare.com/api.php"
HA_API_URL = "https://www.hybrid-analysis.com/api/v2"
CYMRU_API_URL = "https://hash.cymru.com/v2"
ANYRUN_API_URL = "https://api.any.run/v1"
SECURITYTRAILS_API_URL = "https://api.securitytrails.com/v1"
SHODAN_API_URL = "https://api.shodan.io"
GREYNOISE_API_URL = "https://api.greynoise.io/v3"
XFORCE_API_URL = "https://api.xforce.ibmcloud.com"

# =====================================================
# IOC TYPES REFERENCE
# =====================================================
IOC_TYPES = {
    "hash_md5": "MD5 Hash",
    "hash_sha1": "SHA1 Hash",
    "hash_sha256": "SHA256 Hash",
    "ip_v4": "IPv4 Address",
    "ip_v6": "IPv6 Address",
    "domain": "Domain Name",
    "url": "URL",
    "email": "Email Address",
    "country": "Country Name",
    "apt": "APT Group",
    "malware_family": "Malware Family",
    "os": "Operating System",
    "cve": "CVE Identifier",
    "unknown": "Unknown IOC Type"
}

# =====================================================
# HTTP CLIENT SETTINGS
# =====================================================
HTTP_TIMEOUT = 10  # Increased from 20 to handle slow APIs like OTX
MAX_RETRIES = 1    # Increased from 3 for better resilience
BACKOFF_FACTOR = 1

# =====================================================
# PER-SOURCE TIMEOUTS (overrides HTTP_TIMEOUT if set)
# =====================================================
SOURCE_TIMEOUTS = {
    "otx": 50,                    # OTX needs more time for reputation queries
    "hybrid_analysis": 35,
    "virustotal": 40,
    "greynoise": 45,
}
