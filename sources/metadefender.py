"""
MetaDefender threat intelligence source
API Reference: https://www.opswat.com/docs/mdcore/metadefender-core
OpenAPI Spec: https://github.com/OPSWAT/metadefender-core-openapi3
"""
from sources.base import Source
from clients import RateLimitedClient
from config import OPSWAT_KEY


opswat_client = RateLimitedClient(max_retries=3)

# MetaDefender Core API base URL - configurable for on-premises deployments
# Cloud API: https://api.metadefender.com/v4
# On-premises: http://localhost:8008 (or your MetaDefender Core server)
METADEFENDER_API_URL = "https://api.metadefender.com/v4"


class MetaDefenderSource(Source):
    """
    MetaDefender source handler - queries 40+ antivirus engines and security tools
    
    Features:
    - Hash-based file analysis lookups
    - Support for multiple hash types (MD5, SHA1, SHA256, SHA512)
    - Integrates with 40+ antivirus engines
    - Available as cloud API and on-premises deployment
    """
    
    def __init__(self):
        super().__init__("metadefender")
        self.api_url = METADEFENDER_API_URL
    
    def query(self, ioc_type: str, value: str) -> dict:
        """
        Query MetaDefender API for file hash analysis
        Supported IOC types:
            - hash_md5: Query by MD5 hash
            - hash_sha1: Query by SHA1 hash
            - hash_sha256: Query by SHA256 hash
            - hash_sha512: Query by SHA512 hash
        
        Endpoint: GET /hash/{hash_type}?first={offset}&size={limit}
        API Reference: https://www.opswat.com/docs/mdcore/metadefender-core/ref#hashget
        
        Optional headers:
        - rule: Filter by detection rule
        - selfonly: Include only self detections
        - timerange: Time range filter (e.g., 7d, 30d)
        - include-inprogress: Include in-progress analyses
        """
        if not OPSWAT_KEY:
            return {
                "error": "MetaDefender API key missing. "
                         "Configure OPSWAT_API_KEY in environment or .env file"
            }
        
        # Validate IOC type - MetaDefender only supports hash lookups
        if not ioc_type.startswith("hash_"):
            return {"error": f"MetaDefender does not support {ioc_type}. Only hash queries are supported."}
        
        # Extract hash type (md5, sha1, sha256, sha512)
        hash_type = ioc_type.split("_")[1]
        
        # Validate hash type is supported
        supported_hashes = ["md5", "sha1", "sha256", "sha512"]
        if hash_type not in supported_hashes:
            return {"error": f"Unsupported hash type: {hash_type}. Supported: {', '.join(supported_hashes)}"}
        
        headers = {"apikey": OPSWAT_KEY}
        
        # For hash search: /hash/{hash_type} endpoint returns paginated results
        # The 'value' parameter contains the hash to filter by or search for
        url = f"{self.api_url}/hash/{hash_type}"
        
        # Query parameters for pagination and filtering
        params = {
            "first": 0,   # Start offset
            "size": 100   # Results per page (max may vary by server config)
        }
        
        try:
            response = opswat_client.request("GET", url, headers=headers, params=params)
            return self._normalize_response(response, value)
        except Exception as e:
            return {"error": str(e)}
    
    def _normalize_response(self, response: dict, search_hash: str = None) -> dict:
        """
        Normalize MetaDefender API response
        
        The /hash/{hash_type} endpoint returns paginated results, so we filter
        for the specific hash value requested.
        
        Response codes:
        - 200: Success - results returned (may be paginated)
        - 404: Endpoint not found
        - 401: Authentication failed - invalid API key
        - 400: Bad request - invalid parameters
        """
        if isinstance(response, dict) and "error" in response:
            # Check for authentication errors
            if "401" in str(response.get("error", "")) or "Unauthorized" in str(response.get("error", "")):
                return {
                    "error": "MetaDefender authentication failed. Verify API key is valid.",
                    "status_code": 401
                }
            return response
        
        # Check for empty or not found responses
        if isinstance(response, dict):
            if response.get("error", {}).get("code") in ["NotFoundError", "invalid_resource", "hash_not_found"]:
                return {"query_status": "not_found", "data": []}
            
            # Filter results if search_hash provided
            if search_hash and "data" in response and isinstance(response.get("data"), list):
                filtered_data = [item for item in response["data"] 
                               if item.get("file_info", {}).get("md5") == search_hash or
                                  item.get("file_info", {}).get("sha1") == search_hash or
                                  item.get("file_info", {}).get("sha256") == search_hash or
                                  item.get("file_info", {}).get("sha512") == search_hash]
                
                if filtered_data:
                    return {
                        "query_status": "ok",
                        "source": "metadefender",
                        "data": filtered_data
                    }
                else:
                    return {"query_status": "not_found", "data": []}
        
        # Return successful response with normalized structure
        return {
            "query_status": "ok",
            "source": "metadefender",
            "data": response
        }
