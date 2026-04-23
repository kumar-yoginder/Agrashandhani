"""
Hybrid Analysis (Falcon Sandbox) threat intelligence source.

API Reference: https://hybrid-analysis.com/docs/api/v2
Official API Docs: https://hybrid-analysis.com/knowledge-base/searching-the-database-using-api

Author: Agrashandhani
Version: 1.2
"""
import logging

from sources.base import Source
from config import HA_API_URL, HA_KEY

logger = logging.getLogger(__name__)


class HybridAnalysisSource(Source):
    """Hybrid Analysis (Falcon Sandbox) source - Search API Implementation.

    Supported IOC types:
    - ``hash_md5`` / ``hash_sha1`` / ``hash_sha256``: file hash lookup via /search/hash
    - ``ip_v4``, ``domain``, ``url``: Search endpoint (limited support)

    Rate limits (Public Sandbox):
    - 5 queries per minute
    - 200 queries per hour

    API v2 Features:
    - GET /search/hash: Direct hash search (recommended)
    - POST /search/hash: Hash search (deprecated, use GET instead)
    - POST /search/hashes: Batch hash search
    - POST /search/terms: Advanced search with query terms

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
            
            # Other IOC types not directly supported by /search/hash
            # Fall back to not found for now (Search API is primarily for hashes)
            return self._not_found_response(
                f"Search API primarily supports hash lookups. IOC type '{ioc_type}' not supported."
            )

        except Exception as exc:
            logger.exception("[hybrid_analysis] Unexpected error querying %s", value)
            return self._error_response(f"Unexpected error: {exc}", log=False)

    def _search_hash(self, hash_value: str, headers: dict) -> dict:
        """Search for a file hash using the Hybrid Analysis /search/hash endpoint.

        Uses the recommended GET method (POST is deprecated).

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
        
        return self._normalize_response(response)

    def _normalize_response(self, response: dict) -> dict:
        """Normalise a Hybrid Analysis API response.

        Args:
            response: Raw dict from :class:`~clients.RateLimitedClient`.

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

