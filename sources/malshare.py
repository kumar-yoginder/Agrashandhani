"""
MalShare Threat Intelligence Source

Queries the MalShare API for malware samples and threat intelligence.
Reference: https://malshare.com/
"""

import os
from typing import Dict, Any
from sources.base import Source
from clients import RateLimitedClient


MALSHARE_API_URL = "https://malshare.com/api.php"


class MalShareSource(Source):
    """
    MalShare API source for threat intelligence queries.
    
    Supported IOC types:
    - hash_md5: MD5 hash search
    - hash_sha1: SHA1 hash search
    - hash_sha256: SHA256 hash search
    
    Features:
    - Hash-based sample lookup
    - Detailed file analysis results
    - Malware classification and metadata
    
    Rate Limits:
    - API rate limits vary by account tier (free accounts have limits)
    - Implements exponential backoff for rate limiting
    
    Reference:
    - https://malshare.com/api.php (API documentation)
    - https://malshare.com/ (MalShare platform)
    """
    
    def __init__(self):
        """Initialize MalShare source with API key from environment."""
        super().__init__("malshare")
        self.api_key = os.getenv('MALSHARE_API_KEY', '')
        self.api_url = MALSHARE_API_URL
        
        if not self.api_key:
            print(
                "Warning: MalShare API key not found. Set MALSHARE_API_KEY environment variable. "
                "Get API key from https://malshare.com/register.php"
            )
    
    def query(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """
        Query MalShare API for threat intelligence.
        
        Args:
            ioc_type: Type of IOC (hash_md5, hash_sha1, hash_sha256)
            value: The IOC value to search for
            
        Returns:
            Normalized response dictionary with query_status, source, and data
        """
        if not self.api_key:
            return self._error_response(
                "API key not configured",
                "MalShare API key not set. Get key from https://malshare.com/register.php"
            )
        
        if ioc_type not in ["hash_md5", "hash_sha1", "hash_sha256"]:
            return self._error_response(
                f"Unsupported IOC type: {ioc_type}",
                f"MalShare only supports: hash_md5, hash_sha1, hash_sha256"
            )
        
        # Normalize hash to lowercase
        hash_value = value.lower()
        
        # First get detailed information
        details_response = self._get_details(hash_value)
        
        return details_response
    
    def _get_details(self, hash_value: str) -> Dict[str, Any]:
        """
        Get detailed information about a malware sample.
        
        Endpoint: GET /api.php?action=details&hash={hash}&api_key={key}
        
        Args:
            hash_value: The hash to query
            
        Returns:
            Normalized response with sample details
        """
        try:
            params = {
                "api_key": self.api_key,
                "action": "details",
                "hash": hash_value
            }
            
            headers = {
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)"
            }
            
            ms_client = RateLimitedClient(rate_limit=2, time_window=1)  # 2 req/sec
            response = ms_client.request(
                "GET",
                self.api_url,
                params=params,
                headers=headers,
                timeout=10
            )
            
            if response is None:
                return self._error_response(
                    "API request failed",
                    "Connection error or timeout querying MalShare"
                )
            
            # Check for error responses
            if isinstance(response, dict):
                if "error" in response or response.get("status") == "error":
                    error_msg = response.get("error", response.get("message", "Unknown error"))
                    
                    if "not found" in str(error_msg).lower() or "invalid hash" in str(error_msg).lower():
                        return self._success_response({"found": False, "message": error_msg})
                    
                    return self._error_response(
                        f"MalShare API error: {error_msg}",
                        "Hash not found or API limit exceeded"
                    )
                
                # Successful response - normalize it
                return self._normalize_response(response)
            
            # If response is empty string, hash not found
            if response == "" or response is None:
                return self._success_response({"found": False, "message": "Hash not found"})
            
            # Attempt to normalize the response
            return self._normalize_response(response)
        
        except Exception as e:
            return self._error_response(
                f"Query failed: {str(e)}",
                "Error querying MalShare API"
            )
    
    def _normalize_response(self, data: Any) -> Dict[str, Any]:
        """
        Normalize MalShare API response to standard format.
        
        Args:
            data: Raw API response data
            
        Returns:
            Normalized response dictionary
        """
        if isinstance(data, dict):
            # Extract key threat indicators
            normalized_data = {
                "hash": data.get("hash"),
                "md5": data.get("md5"),
                "sha1": data.get("sha1"),
                "sha256": data.get("sha256"),
                "type": data.get("type"),
                "source": data.get("source"),
                "first_seen": data.get("first_seen"),
                "last_seen": data.get("last_seen"),
                "tags": data.get("tags", []),
                "analysis": data.get("analysis"),
                "raw_data": data
            }
            
            # Filter out None values
            normalized_data = {k: v for k, v in normalized_data.items() if v is not None}
            
            return self._success_response(normalized_data)
        
        return self._success_response({"raw_data": data})
    
    def _success_response(self, data: Any) -> Dict[str, Any]:
        """Create a success response in standard format."""
        return {
            "query_status": "ok",
            "source": "malshare",
            "data": data
        }
    
    def _error_response(self, message: str, details: str = "") -> Dict[str, Any]:
        """Create an error response in standard format."""
        return {
            "query_status": "error",
            "source": "malshare",
            "data": {
                "error": message,
                "details": details
            }
        }
