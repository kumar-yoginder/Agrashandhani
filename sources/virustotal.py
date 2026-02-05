"""
VirusTotal threat intelligence source
API Reference: https://docs.virustotal.com/reference/overview
"""
from sources.base import Source
from clients import RateLimitedClient
from config import VT_KEY, VT_API_URL
import base64
import urllib.parse


vt_client = RateLimitedClient(max_retries=3)


class VirusTotalSource(Source):
    """VirusTotal source handler - queries 70+ antivirus engines and security tools"""
    
    def __init__(self):
        super().__init__("virustotal")
        self.api_url = VT_API_URL
        self.api_key = VT_KEY
    
    def query(self, ioc_type: str, value: str) -> dict:
        """
        Query VirusTotal API
        Supported IOC types:
            - hash_md5: Query by MD5 hash
            - hash_sha1: Query by SHA1 hash
            - hash_sha256: Query by SHA256 hash
            - ip_v4: Query by IPv4 address
            - ip_v6: Query by IPv6 address
            - domain: Query by domain name
            - url: Query by URL
        """
        if not self.api_key:
            return {"error": "VirusTotal API key missing. Get it from https://www.virustotal.com/gui/my-apikey"}
        
        headers = {"x-apikey": self.api_key}
        
        try:
            # Handle hash types (md5, sha1, sha256)
            if ioc_type.startswith("hash_"):
                url = f"{self.api_url}/files/{value}"
            
            # Handle IP addresses (IPv4 and IPv6)
            elif ioc_type.startswith("ip_"):
                url = f"{self.api_url}/ip_addresses/{value}"
            
            # Handle domains
            elif ioc_type == "domain":
                url = f"{self.api_url}/domains/{value}"
            
            # Handle URLs - requires special encoding
            elif ioc_type == "url":
                # URL identifier: base64 without padding
                url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')
                url = f"{self.api_url}/urls/{url_id}"
            
            else:
                return {"error": f"VirusTotal does not support {ioc_type}"}
            
            response = vt_client.request("GET", url, headers=headers)
            return self._normalize_response(response, ioc_type)
        
        except Exception as e:
            return {"error": str(e)}
    
    def _normalize_response(self, response: dict, ioc_type: str) -> dict:
        """Normalize VirusTotal API response"""
        if isinstance(response, dict) and "error" in response:
            return response
        
        # Check for 404 or not found responses
        if isinstance(response, dict):
            if response.get("error", {}).get("code") in ["NotFoundError", "invalid_resource"]:
                return {"query_status": "not_found", "data": []}
        
        # Return successful response with normalized structure
        return {
            "query_status": "ok",
            "source": "virustotal",
            "data": response
        }
