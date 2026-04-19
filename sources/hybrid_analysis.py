"""
Hybrid Analysis (Falcon Sandbox) threat intelligence source.

API Reference: https://hybrid-analysis.com/knowledge-base/searching-the-database-using-api
VxAPI Wrapper: https://github.com/PayloadSecurity/VxAPI

Author: Agrashandhani
Version: 1.1
"""
import logging

from sources.base import Source
from config import HA_API_URL, HA_KEY

logger = logging.getLogger(__name__)


class HybridAnalysisSource(Source):
    """Hybrid Analysis (Falcon Sandbox) source.

    Supported IOC types:
    - ``hash_md5`` / ``hash_sha1`` / ``hash_sha256``: file hash lookup
    - ``ip_v4``: IP address search (``host:`` prefix)
    - ``domain``: domain search
    - ``url``: URL search

    Rate limits (Public Sandbox):
    - 5 queries per minute
    - 200 queries per hour

    Attributes:
        api_url: Hybrid Analysis API base URL.
        api_key: API key loaded from config.
    """

    def __init__(self) -> None:
        super().__init__("hybrid_analysis")
        self.api_url = HA_API_URL
        self.api_key = HA_KEY

    def query(self, ioc_type: str, value: str) -> dict:
        """Query the Hybrid Analysis API.

        Args:
            ioc_type: IOC classification (``hash_*``, ``ip_v4``, ``domain``,
                ``url``).
            value: The IOC value to look up.

        Returns:
            Normalised response dict.
        """
        if not self.api_key:
            return self._error_response(
                "Hybrid Analysis API key missing",
                "Get it from https://www.hybrid-analysis.com/apikeys",
            )

        headers = {
            "api-key": self.api_key,
            "User-Agent": "Falcon Sandbox",
        }

        try:
            if ioc_type.startswith("hash_"):
                return self._query_hash(value, headers)
            if ioc_type == "ip_v4":
                return self._search_terms(f"host:{value}", headers)
            if ioc_type == "domain":
                return self._search_terms(f"domain:{value}", headers)
            if ioc_type == "url":
                return self._search_terms(f"url:{value}", headers)

            return self._error_response(
                f"Unsupported IOC type: {ioc_type}",
                "Hybrid Analysis supports: hash_*, ip_v4, domain, url",
            )

        except Exception as exc:
            logger.exception("[hybrid_analysis] Unexpected error querying %s", value)
            return self._error_response(f"Unexpected error: {exc}")

    def _query_hash(self, hash_value: str, headers: dict) -> dict:
        """Look up a file hash in the Hybrid Analysis database.

        Args:
            hash_value: MD5, SHA1, or SHA256 hash.
            headers: HTTP headers including the API key.

        Returns:
            Normalised response dict.
        """
        url = f"{self.api_url}/search/hash"
        response = self.client.request("GET", url, headers=headers, params={"hash": hash_value})
        return self._normalize_response(response)

    def _search_terms(self, search_query: str, headers: dict) -> dict:
        """Advanced search using Hybrid Analysis search terms/prefixes.

        Args:
            search_query: Prefixed search string (e.g. ``"host:1.2.3.4"``).
            headers: HTTP headers including the API key.

        Returns:
            Normalised response dict.
        """
        url = f"{self.api_url}/search/terms"
        response = self.client.request("POST", url, headers=headers, json={"query": search_query})
        return self._normalize_response(response)

    def _normalize_response(self, response: dict) -> dict:
        """Normalise a Hybrid Analysis API response.

        Args:
            response: Raw dict from :class:`~clients.RateLimitedClient`.

        Returns:
            Normalised response dict.
        """
        if "error" in response:
            return self._error_response(str(response["error"]))

        if not response:
            return self._not_found_response()

        return self._success_response(response)
