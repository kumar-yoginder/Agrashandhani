"""
Team Cymru Hash/IP Reputation Source

Queries the Team Cymru REST API for hash and IP reputation data.
Reference: https://hash.cymru.com/docs_rest
"""

from typing import Dict, Any
from sources.base import Source
from clients import RateLimitedClient
from config import CYMRU_API_URL, CYMRU_API_USERNAME, CYMRU_API_PASSWORD


class CymruSource(Source):
    """
    Team Cymru API source for hash and IP reputation lookups.

    Supported IOC types:
    - hash_md5: MD5 file hash
    - hash_sha1: SHA1 file hash
    - hash_sha256: SHA256 file hash
    - ip_v4: IPv4 address

    Features:
    - Hash reputation (antivirus detection rate, last seen date)
    - IP to ASN/BGP prefix mapping
    - Authenticated REST API with HTTP Basic auth

    Reference:
    - https://hash.cymru.com/docs_rest (API documentation)
    - Register at: https://hash.cymru.com/
    """

    def __init__(self):
        """Initialize Cymru source with credentials from config."""
        super().__init__("cymru")
        self.api_url = CYMRU_API_URL
        self.username = CYMRU_API_USERNAME
        self.password = CYMRU_API_PASSWORD

    def query(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """
        Query Team Cymru API for threat intelligence.

        Args:
            ioc_type: Type of IOC (hash_md5, hash_sha1, hash_sha256, ip_v4)
            value: The IOC value to look up

        Returns:
            Normalized response dictionary with query_status, source, and data
        """
        if not self.username or not self.password:
            return self._error_response(
                "Cymru credentials not configured",
                "Set CYMRU_API_USERNAME and CYMRU_API_PASSWORD environment variables. "
                "Register at https://hash.cymru.com/"
            )

        if ioc_type.startswith("hash_"):
            return self._query_hash(value)
        elif ioc_type == "ip_v4":
            return self._query_ip(value)
        else:
            return self._error_response(
                f"Unsupported IOC type: {ioc_type}",
                "Cymru supports: hash_md5, hash_sha1, hash_sha256, ip_v4"
            )

    def _query_hash(self, hash_value: str) -> Dict[str, Any]:
        """
        Query Cymru for hash reputation.

        Endpoint: GET /v2/query/{hash}

        Args:
            hash_value: The hash to look up (MD5, SHA1, or SHA256)

        Returns:
            Normalized response with hash reputation data
        """
        try:
            url = f"{self.api_url}/query/{hash_value}"
            headers = {
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Accept": "application/json"
            }

            cymru_client = RateLimitedClient(max_retries=3)
            response = cymru_client.request(
                "GET",
                url,
                headers=headers,
                auth=(self.username, self.password),
                timeout=15
            )

            if response is None:
                return self._error_response(
                    "API request failed",
                    "Connection error or timeout querying Cymru"
                )

            if isinstance(response, dict):
                if "error" in response:
                    return self._error_response(
                        f"Cymru API error: {response['error']}",
                        str(response.get("message", ""))
                    )
                return self._success_response(response)

            return self._error_response(
                "Unexpected response format",
                "Cymru returned non-JSON response"
            )

        except Exception as e:
            return self._error_response(
                f"Query failed: {str(e)}",
                "Error querying Cymru API"
            )

    def _query_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Query Cymru for IP to ASN/BGP mapping.

        Endpoint: GET /v2/query/{ip}

        Args:
            ip_address: IPv4 address to look up

        Returns:
            Normalized response with ASN/BGP data
        """
        try:
            url = f"{self.api_url}/query/{ip_address}"
            headers = {
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Accept": "application/json"
            }

            cymru_client = RateLimitedClient(max_retries=3)
            response = cymru_client.request(
                "GET",
                url,
                headers=headers,
                auth=(self.username, self.password),
                timeout=15
            )

            if response is None:
                return self._error_response(
                    "API request failed",
                    "Connection error or timeout querying Cymru"
                )

            if isinstance(response, dict):
                if "error" in response:
                    return self._error_response(
                        f"Cymru API error: {response['error']}",
                        str(response.get("message", ""))
                    )
                return self._success_response(response)

            return self._error_response(
                "Unexpected response format",
                "Cymru returned non-JSON response"
            )

        except Exception as e:
            return self._error_response(
                f"Query failed: {str(e)}",
                "Error querying Cymru API"
            )

    def _success_response(self, data: Any) -> Dict[str, Any]:
        """Create a success response in standard format."""
        return {
            "query_status": "ok",
            "source": "cymru",
            "data": data
        }

    def _error_response(self, message: str, details: str = "") -> Dict[str, Any]:
        """Create an error response in standard format."""
        return {
            "query_status": "error",
            "source": "cymru",
            "data": {
                "error": message,
                "details": details
            }
        }
