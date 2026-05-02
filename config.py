"""
Configuration module for OSINT Search Tool.

Manages all configuration settings including API keys, database connection
strings, HTTP client parameters, IOC type definitions, and per-source
timeouts. Configuration values are loaded from environment variables via
the python-dotenv package.

Database Backends:
  - JSON file (default): data/threat_intel_db.json
  - MongoDB: Set MONGODB_URI environment variable
  - PostgreSQL: Set POSTGRES_URI environment variable

API Keys:
  Load all API keys from .env file or environment variables. Example:
    VT_API_KEY=your-virustotal-key
    OTX_API_KEY=your-otx-key
    XFORCE_API_KEY=your-xforce-key
    XFORCE_API_PASSWORD=your-xforce-password

Author: Agrashandhani
Version: 1.1
"""
import os
from dotenv import load_dotenv

load_dotenv()

# =====================================================
# DATABASE CONFIGURATION
# =====================================================

DB_FILE = os.getenv("DB_FILE", "data/threat_intel_db.json")

MONGODB_URI = os.getenv("MONGODB_URI", "")
POSTGRES_URI = os.getenv("POSTGRES_URI", "")

# =====================================================
# API KEYS (Loaded once from .env)
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

# =====================================================
# API ENDPOINTS
# =====================================================

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
    "unknown": "Unknown IOC Type",
}

# =====================================================
# HTTP CLIENT SETTINGS
# =====================================================

HTTP_TIMEOUT = 10
MAX_RETRIES = 1
BACKOFF_FACTOR = 1

# =====================================================
# PER-SOURCE TIMEOUTS (overrides HTTP_TIMEOUT if set)
# =====================================================

SOURCE_TIMEOUTS = {
    "otx": 50,
    "hybrid_analysis": 35,
    "virustotal": 40,
    "greynoise": 45,
}
