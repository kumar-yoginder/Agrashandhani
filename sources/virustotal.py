"""
VirusTotal threat intelligence source
"""
from sources.base import Source
from clients import RateLimitedClient
from config import VT_KEY, VT_API_URL


vt_client = RateLimitedClient(max_retries=3)


class VirusTotalSource(Source):
    """VirusTotal source handler"""
    
    def __init__(self):
        super().__init__("virustotal")
    
    def query(self, ioc_type: str, value: str) -> dict:
        """Query VirusTotal API"""
        if not VT_KEY:
            return {"error": "VirusTotal API key missing"}
        
        headers = {"x-apikey": VT_KEY}
        
        # Handle hash types (hash_md5, hash_sha1, hash_sha256)
        if ioc_type.startswith("hash_"):
            url = f"{VT_API_URL}/files/{value}"
        elif ioc_type.startswith("ip_"):
            url = f"{VT_API_URL}/ip_addresses/{value}"
        else:
            return {"error": "VT unsupported IOC type"}
        
        return vt_client.request("GET", url, headers=headers)
