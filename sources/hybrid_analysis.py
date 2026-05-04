"""
Hybrid Analysis (Falcon Sandbox) threat intelligence source.

API Reference: https://hybrid-analysis.com/docs/api/v2
Official API Docs: https://hybrid-analysis.com/knowledge-base/searching-the-database-using-api

Author: Agrashandhani
Version: 1.1
"""
import logging

from sources.base import Source
from config import HA_API_URL, HA_KEY

logger = logging.getLogger(__name__)


class HybridAnalysisSource(Source):
    """Hybrid Analysis (Falcon Sandbox) source - Search API Implementation.

    Implements two primary search endpoints:
    - GET /search/hash: Direct hash search (MD5, SHA1, SHA256)
    - POST /search/terms: Advanced search with query filters

    Supported IOC types:
    - ``hash_md5`` / ``hash_sha1`` / ``hash_sha256``: file hash lookup via GET /search/hash
    - ``ip_v4``: IPv4 address search via POST /search/terms
    - ``domain``: Domain search via POST /search/terms
    - ``url``: URL search via POST /search/terms

    Rate limits (Public Sandbox):
    - 5 queries per minute
    - 200 queries per hour

    API v2 Endpoints (v2.35.0+):
    - GET /search/hash: Direct hash search (recommended for hash IOCs)
    - POST /search/terms: Advanced multi-parameter search (for domains, IPs, URLs, etc.)

    Attributes:
        api_url: Hybrid Analysis API base URL (v2).
        api_key: API key loaded from config.
    """

    def __init__(self) -> None:
        super().__init__("hybrid_analysis")
        self.api_url = HA_API_URL
        self.api_key = HA_KEY

    def query(self, ioc_type: str, value: str) -> dict:
        """Query the Hybrid Analysis Search API.

        Routes to appropriate endpoint based on IOC type:
        - Hash types: GET /search/hash
        - Other types (IP, domain, URL): POST /search/terms

        Args:
            ioc_type: IOC classification (``hash_*``, ``ip_v4``, ``domain``, ``url``).
            value: The IOC value to look up.

        Returns:
            Normalised response dict with query_status, source, and data.
        """
        if not self.api_key:
            return self._error_response(
                "Hybrid Analysis API key missing",
                "Get it from https://hybrid-analysis.com/my-account?tab=%23api-key-tab",
            )

        headers = {
            "api-key": self.api_key,
            "User-Agent": "Falcon",  # Required to bypass User-Agent blacklist
        }

        try:
            # Route to appropriate search method
            if ioc_type.startswith("hash_"):
                return self._search_hash(value, headers)
            elif ioc_type in ("ip_v4", "domain", "url"):
                return self._search_terms(ioc_type, value, headers)
            else:
                return self._not_found_response(
                    f"IOC type '{ioc_type}' not supported. Supported types: "
                    "hash_md5, hash_sha1, hash_sha256, ip_v4, domain, url"
                )

        except Exception as exc:
            logger.exception("[hybrid_analysis] Unexpected error querying %s", value)
            return self._error_response(f"Unexpected error: {exc}", log=False)

    def _search_hash(self, hash_value: str, headers: dict) -> dict:
        """Search for a file hash using the Hybrid Analysis GET /search/hash endpoint.

        Recommended method for direct hash lookups (v2.35.0+).
        Supports MD5, SHA1, or SHA256 hashes.

        Args:
            hash_value: MD5, SHA1, or SHA256 hash.
            headers: HTTP headers including the API key.

        Returns:
            Normalised response dict.
        """
        # Use GET method (v2.35.0+) - POST is deprecated
        url = f"{self.api_url}/search/hash"
        params = {"hash": hash_value}
        
        response = self.client.request(
            "GET",
            url,
            headers=headers,
            params=params,
            timeout=self.timeout,
        )
        
        return self._normalize_hash_response(response)

    def _search_terms(self, ioc_type: str, value: str, headers: dict) -> dict:
        """Search using the Hybrid Analysis POST /search/terms endpoint.

        Advanced search for domains, IPs, URLs, and other threat indicators.
        Maps IOC types to appropriate query parameters.

        Args:
            ioc_type: IOC type (ip_v4, domain, url).
            value: The IOC value to search for.
            headers: HTTP headers including the API key.

        Returns:
            Normalised response dict.
        """
        url = f"{self.api_url}/search/terms"
        
        # Map IOC types to query parameters
        params = {}
        if ioc_type == "ip_v4":
            params["host"] = value  # Host/IP parameter
        elif ioc_type == "domain":
            params["domain"] = value  # Domain parameter
        elif ioc_type == "url":
            params["url"] = value  # URL substring parameter
        
        response = self.client.request(
            "POST",
            url,
            headers=headers,
            data=params,
            timeout=self.timeout,
        )
        
        return self._normalize_terms_response(response)

    def _normalize_hash_response(self, response: dict) -> dict:
        """Normalise a Hybrid Analysis GET /search/hash API response.

        The /search/hash endpoint returns a single object with response_code:
        - response_code: 1 = found, 0 = not found
        - response: "found" or "not found"
        - results: Object with file details (if found)

        Args:
            response: Raw dict from :class:`~.clients.RateLimitedClient`.

        Returns:
            Normalised response dict (success, not_found, or error).
        """
        # Handle error responses from the client
        if "error" in response:
            error_msg = response.get("error", "Unknown error")
            return self._error_response(
                f"Hybrid Analysis API error: {error_msg}",
                log=False
            )

        # Empty response means hash not found in database
        if not response or response.get("response_code") == 0:
            return self._not_found_response(
                "Hash not found in Hybrid Analysis database"
            )

        # Successful response with data
        if response.get("response_code") == 1:
            return self._success_response(response)

        # Unknown response format
        return self._not_found_response(
            f"Unexpected response format: {response}"
        )

    def _normalize_terms_response(self, response: dict | list) -> dict:
        """Normalise a Hybrid Analysis POST /search/terms API response.

        The /search/terms endpoint returns a list of matching samples:
        - Returns: List of sample objects (each with sha256, md5, etc.)
        - Empty list: No matches found
        - Error dict: Request failed

        Args:
            response: Raw dict or list from :class:`~.clients.RateLimitedClient`.

        Returns:
            Normalised response dict (success, not_found, or error).
        """
        # Handle error responses from the client
        if isinstance(response, dict) and "error" in response:
            error_msg = response.get("error", "Unknown error")
            return self._error_response(
                f"Hybrid Analysis API error: {error_msg}",
                log=False
            )

        # Handle list responses (expected format)
        if isinstance(response, list):
            if not response:  # Empty list means no matches
                return self._not_found_response(
                    "No matching samples found in Hybrid Analysis database"
                )
            # Found results
            return self._success_response({"results": response})

        # Handle unexpected response format
        if isinstance(response, dict) and not response:
            return self._not_found_response(
                "No matching samples found in Hybrid Analysis database"
            )

        # Unknown response format
        return self._error_response(
            f"Unexpected response format: {response}",
            log=False
        )

