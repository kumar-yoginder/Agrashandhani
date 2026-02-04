"""
Configuration module for OSINT Search Tool
"""
import os
from dotenv import load_dotenv

load_dotenv()

# =====================================================
# DATABASE
# =====================================================
DB_FILE = "threat_intel_db.json"

# =====================================================
# API KEYS & ENDPOINTS
# =====================================================
VT_KEY = os.getenv("VT_API_KEY")
HA_KEY = os.getenv("HA_API_KEY")
OPSWAT_KEY = os.getenv("OPSWAT_API_KEY")

MB_API_URL = "https://mb-api.abuse.ch/api/v1/"
VT_API_URL = "https://www.virustotal.com/api/v3"

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
HTTP_TIMEOUT = 20
MAX_RETRIES = 3
BACKOFF_FACTOR = 1
