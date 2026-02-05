"""
AlienVault OTX (Open Threat Exchange) Source

Queries the AlienVault OTX API for threat intelligence indicators.
Reference: https://otx.alienvault.com/
"""

import os
import requests
from typing import Dict, Any
from sources.base import Source
from clients import RateLimitedClient


OTX_API_URL = "https://otx.alienvault.com/api/v1"


class OTXSource(Source):
    """
    AlienVault OTX (Open Threat Exchange) API source for threat intelligence.
    
    Supported IOC types:
    - hash_md5: MD5 file hash
    - hash_sha1: SHA1 file hash
    - hash_sha256: SHA256 file hash
    - ip_v4: IPv4 address
    - ip_v6: IPv6 address
    - domain: Domain name
    - url: URL
    
    Features:
    - Multi-type indicator lookups (hashes, IPs, domains, URLs)
    - Detailed threat analysis and passive DNS data
    - Community threat intelligence (pulses)
    - CVE correlation
    - Reputation scoring
    
    Rate Limits:
    - Free tier: 600 requests/hour
    - Premium tiers: Higher limits based on subscription
    - Implements exponential backoff for rate limiting
    
    Reference:
    - https://otx.alienvault.com/ (OTX platform)
    - https://otx.alienvault.com/api (API documentation)
    - Get API key: https://otx.alienvault.com/account/profile
    """
    
    def __init__(self):
        """Initialize OTX source with API key from environment."""
        super().__init__("otx")
        self.api_key = os.getenv('OTX_API_KEY', '')
        self.api_url = OTX_API_URL
        
        if not self.api_key:
            print(
                "Warning: OTX API key not found. Set OTX_API_KEY environment variable. "
                "Get API key from https://otx.alienvault.com/account/profile"
            )
    
    def query(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """
        Query OTX API for threat intelligence.
        
        Args:
            ioc_type: Type of IOC (hash_md5, hash_sha1, hash_sha256, ip_v4, ip_v6, domain, url)
            value: The IOC value to search for
            
        Returns:
            Normalized response dictionary with query_status, source, and data
        """
        if not self.api_key:
            return self._error_response(
                "API key not configured",
                "OTX API key not set. Get key from https://otx.alienvault.com/account/profile"
            )
        
        # Map IOC type to OTX endpoint
        ioc_map = {
            "hash_md5": "file",
            "hash_sha1": "file",
            "hash_sha256": "file",
            "ip_v4": "IPv4",
            "ip_v6": "IPv6",
            "domain": "domain",
            "url": "url"
        }
        
        if ioc_type not in ioc_map:
            return self._error_response(
                f"Unsupported IOC type: {ioc_type}",
                f"OTX supports: {', '.join(ioc_map.keys())}"
            )
        
        endpoint_type = ioc_map[ioc_type]
        
        # Query based on IOC type
        if ioc_type.startswith("hash_"):
            return self._query_hash(value, endpoint_type)
        elif ioc_type.startswith("ip_"):
            return self._query_indicator(endpoint_type, value, "reputation")
        elif ioc_type == "domain":
            return self._query_indicator(endpoint_type, value, "general")
        elif ioc_type == "url":
            return self._query_indicator(endpoint_type, value, "general")
        
        return self._error_response(
            "Query routing failed",
            f"Unable to route query for IOC type: {ioc_type}"
        )
    
    def _query_hash(self, hash_value: str, endpoint_type: str) -> Dict[str, Any]:
        """
        Query OTX for file hash information.
        
        Endpoint: GET /indicators/file/{hash}/general
        
        Args:
            hash_value: The hash to query
            endpoint_type: Type of endpoint (file, IPv4, domain, url)
            
        Returns:
            Normalized response with file analysis data
        """
        try:
            url = f"{self.api_url}/indicators/{endpoint_type}/{hash_value}/general"
            
            headers = {
                "X-OTX-API-KEY": self.api_key,
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Content-Type": "application/json"
            }
            
            otx_client = RateLimitedClient(rate_limit=10, time_window=1)  # 10 req/sec
            response = otx_client.request(
                "GET",
                url,
                headers=headers,
                timeout=10
            )
            
            if response is None:
                return self._error_response(
                    "API request failed",
                    "Connection error or timeout querying OTX"
                )
            
            # Check for error responses
            if isinstance(response, dict):
                if response.get("error") or response.get("status") == "error":
                    error_msg = response.get("error", response.get("message", "Unknown error"))
                    
                    if "not found" in str(error_msg).lower():
                        return self._success_response({"found": False, "message": error_msg})
                    
                    return self._error_response(
                        f"OTX API error: {error_msg}",
                        "Hash not found or API limit exceeded"
                    )
                
                # Successful response
                return self._normalize_response(response)
            
            return self._error_response(
                "Unexpected response format",
                "OTX returned non-JSON response"
            )
        
        except Exception as e:
            return self._error_response(
                f"Query failed: {str(e)}",
                "Error querying OTX API"
            )
    
    def _query_indicator(self, indicator_type: str, value: str, section: str = "general") -> Dict[str, Any]:
        """
        Query OTX for indicator information (IP, domain, URL, etc.).
        
        Endpoint: GET /indicators/{type}/{value}/{section}
        
        Args:
            indicator_type: Type of indicator (IPv4, IPv6, domain, url)
            value: The indicator value
            section: API section (general, reputation, geo, malware, etc.)
            
        Returns:
            Normalized response with indicator details
        """
        try:
            url = f"{self.api_url}/indicators/{indicator_type}/{value}/{section}"
            
            headers = {
                "X-OTX-API-KEY": self.api_key,
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Content-Type": "application/json"
            }
            
            otx_client = RateLimitedClient(rate_limit=10, time_window=1)
            response = otx_client.request(
                "GET",
                url,
                headers=headers,
                timeout=10
            )
            
            if response is None:
                return self._error_response(
                    "API request failed",
                    "Connection error or timeout querying OTX"
                )
            
            # Check for error responses
            if isinstance(response, dict):
                if response.get("error") or response.get("status") == "error":
                    error_msg = response.get("error", response.get("message", "Unknown error"))
                    
                    if "not found" in str(error_msg).lower():
                        return self._success_response({"found": False, "message": error_msg})
                    
                    return self._error_response(
                        f"OTX API error: {error_msg}",
                        "Indicator not found or invalid"
                    )
                
                return self._normalize_response(response)
            
            return self._error_response(
                "Unexpected response format",
                "OTX returned non-JSON response"
            )
        
        except Exception as e:
            return self._error_response(
                f"Query failed: {str(e)}",
                "Error querying OTX API"
            )
    
    def _normalize_response(self, data: Any) -> Dict[str, Any]:
        """
        Normalize OTX API response to standard format.
        
        Args:
            data: Raw API response data
            
        Returns:
            Normalized response dictionary
        """
        if isinstance(data, dict):
            # Extract key threat indicators from OTX response
            normalized_data = {
                "indicator": data.get("indicator"),
                "type": data.get("type"),
                "pulse_info": data.get("pulse_info"),
                "reputation": data.get("reputation"),
                "ali_as": data.get("ali_as"),
                "country_code": data.get("country_code"),
                "country_name": data.get("country_name"),
                "validation": data.get("validation"),
                "asn": data.get("asn"),
                "whois": data.get("whois"),
                "sections": data.get("sections", []),
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
            "source": "otx",
            "data": data
        }
    
    def _error_response(self, message: str, details: str = "") -> Dict[str, Any]:
        """Create an error response in standard format."""
        return {
            "query_status": "error",
            "source": "otx",
            "data": {
                "error": message,
                "details": details
            }
        }
