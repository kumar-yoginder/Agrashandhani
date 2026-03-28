"""
Any.run Threat Intelligence Source

Queries the Any.run TI Lookup API for sandbox analysis and threat intelligence.
Reference: https://any.run/api-documentation/#ti-lookup
"""

from typing import Dict, Any
from sources.base import Source
from clients import RateLimitedClient
from config import ANYRUN_API_URL, ANYRUN_API_KEY


class AnyRunSource(Source):
    """
    Any.run API source for sandbox-based threat intelligence.

    Supported IOC types:
    - hash_md5: MD5 file hash
    - hash_sha1: SHA1 file hash
    - hash_sha256: SHA256 file hash
    - ip_v4: IPv4 address
    - domain: Domain name
    - url: URL

    Features:
    - Sandbox analysis results for malware samples
    - Threat indicators from dynamic analysis
    - IOC lookup across submitted tasks
    - Network activity correlation

    Reference:
    - https://any.run/api-documentation/#ti-lookup (API documentation)
    - Register at: https://app.any.run/
    """

    def __init__(self):
        """Initialize Any.run source with API key from config."""
        super().__init__("anyrun")
        self.api_url = ANYRUN_API_URL
        self.api_key = ANYRUN_API_KEY

    def query(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """
        Query Any.run TI Lookup API.

        Args:
            ioc_type: Type of IOC (hash_md5, hash_sha1, hash_sha256, ip_v4, domain, url)
            value: The IOC value to search for

        Returns:
            Normalized response dictionary with query_status, source, and data
        """
        if not self.api_key:
            return self._error_response(
                "Any.run API key not configured",
                "Set ANYRUN_API_KEY environment variable. "
                "Register at https://app.any.run/"
            )

        ioc_map = {
            "hash_md5": "filehash",
            "hash_sha1": "filehash",
            "hash_sha256": "filehash",
            "ip_v4": "ip",
            "domain": "domain",
            "url": "url"
        }

        if ioc_type not in ioc_map:
            return self._error_response(
                f"Unsupported IOC type: {ioc_type}",
                f"Any.run TI Lookup supports: {', '.join(ioc_map.keys())}"
            )

        return self._query_ti_lookup(ioc_map[ioc_type], value)

    def _query_ti_lookup(self, indicator_type: str, value: str) -> Dict[str, Any]:
        """
        Query Any.run TI Lookup endpoint.

        Endpoint: GET /v1/intelligence/iocs/lookup

        Args:
            indicator_type: Type of indicator (filehash, ip, domain, url)
            value: The indicator value

        Returns:
            Normalized response with threat intelligence data
        """
        try:
            url = f"{self.api_url}/intelligence/iocs/lookup"
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Accept": "application/json"
            }
            params = {
                "type": indicator_type,
                "value": value
            }

            anyrun_client = RateLimitedClient(max_retries=3)
            response = anyrun_client.request(
                "GET",
                url,
                headers=headers,
                params=params,
                timeout=20
            )

            if response is None:
                return self._error_response(
                    "API request failed",
                    "Connection error or timeout querying Any.run"
                )

            if isinstance(response, dict):
                if response.get("error"):
                    error_msg = response.get("message", str(response.get("error")))
                    return self._error_response(
                        f"Any.run API error: {error_msg}",
                        "Check API key or query parameters"
                    )

                data = response.get("data", response)
                return self._success_response(data)

            return self._error_response(
                "Unexpected response format",
                "Any.run returned non-JSON response"
            )

        except Exception as e:
            return self._error_response(
                f"Query failed: {str(e)}",
                "Error querying Any.run API"
            )

    def _success_response(self, data: Any) -> Dict[str, Any]:
        """Create a success response in standard format."""
        return {
            "query_status": "ok",
            "source": "anyrun",
            "data": data
        }

    def _error_response(self, message: str, details: str = "") -> Dict[str, Any]:
        """Create an error response in standard format."""
        return {
            "query_status": "error",
            "source": "anyrun",
            "data": {
                "error": message,
                "details": details
            }
        }
