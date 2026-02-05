"""
Hybrid Analysis (Falcon Sandbox) threat intelligence source
API Reference: https://hybrid-analysis.com/knowledge-base/searching-the-database-using-api
VxAPI Wrapper: https://github.com/PayloadSecurity/VxAPI
"""
from sources.base import Source
from clients import RateLimitedClient
from config import HA_KEY


ha_client = RateLimitedClient(max_retries=3)

# Hybrid Analysis API base URL
HYBRID_ANALYSIS_API_URL = "https://www.hybrid-analysis.com/api/v2"


class HybridAnalysisSource(Source):
    """
    Hybrid Analysis (Falcon Sandbox) source handler
    
    Features:
    - Hash-based file analysis lookups (MD5, SHA1, SHA256)
    - Advanced search with multiple IOC types
    - Network indicators (IP, domain, port, URL)
    - Malware classification and tagging
    - Similarity search (similar-to:)
    
    Rate Limits (Public Sandbox):
    - 5 queries per minute
    - 200 queries per hour
    """
    
    def __init__(self):
        super().__init__("hybrid_analysis")
        self.api_url = HYBRID_ANALYSIS_API_URL
    
    def query(self, ioc_type: str, value: str) -> dict:
        """
        Query Hybrid Analysis API
        Supported IOC types:
            - hash_md5: Query by MD5 hash
            - hash_sha1: Query by SHA1 hash
            - hash_sha256: Query by SHA256 hash
            - ip_v4: Query by IPv4 address (host:)
            - domain: Query by domain name
            - url: Query by URL
        
        Advanced search supports:
            - similar-to: Find similar samples
            - vxfamily: Search by virus family
            - tag: Search by tag
            - filetype: Search by file type
        
        API Reference: https://hybrid-analysis.com/knowledge-base/searching-the-database-using-api
        """
        if not HA_KEY:
            return {
                "error": "Hybrid Analysis API key missing. "
                         "Get it from https://www.hybrid-analysis.com/apikeys"
            }
        
        headers = {
            "api-key": HA_KEY,
            "User-Agent": "Falcon Sandbox"
        }
        
        try:
            # Route to appropriate endpoint based on IOC type
            if ioc_type.startswith("hash_"):
                # Hash-based lookup
                return self._query_hash(value, headers)
            elif ioc_type == "ip_v4":
                # IP address search
                return self._search_terms(f"host:{value}", headers)
            elif ioc_type == "domain":
                # Domain search
                return self._search_terms(f"domain:{value}", headers)
            elif ioc_type == "url":
                # URL search
                return self._search_terms(f"url:{value}", headers)
            else:
                return {"error": f"Hybrid Analysis does not support {ioc_type}"}
        
        except Exception as e:
            return {"error": str(e)}
    
    def _query_hash(self, hash_value: str, headers: dict) -> dict:
        """Search for hash in Hybrid Analysis database"""
        # Endpoint: POST /api/v2/search/hash
        url = f"{self.api_url}/search/hash"
        params = {"hash": hash_value}
        
        response = ha_client.request("GET", url, headers=headers, params=params)
        return self._normalize_response(response)
    
    def _search_terms(self, search_query: str, headers: dict) -> dict:
        """Advanced search using search terms/prefixes"""
        # Endpoint: POST /api/v2/search/terms
        url = f"{self.api_url}/search/terms"
        data = {"query": search_query}
        
        response = ha_client.request("POST", url, headers=headers, json=data)
        return self._normalize_response(response)
    
    def _normalize_response(self, response: dict) -> dict:
        """
        Normalize Hybrid Analysis API response
        
        Response codes:
        - 200: Success
        - 400: Bad request - invalid parameters
        - 401: Unauthorized - invalid API key
        - 403: Forbidden - insufficient permissions
        - 404: Not found - no results
        - 429: Rate limited - too many requests
        """
        if isinstance(response, dict) and "error" in response:
            return response
        
        # Check for empty results
        if not response or (isinstance(response, dict) and len(response) == 0):
            return {"query_status": "not_found", "data": []}
        
        # Return successful response with normalized structure
        return {
            "query_status": "ok",
            "source": "hybrid_analysis",
            "data": response
        }
