"""
ThreatFox threat intelligence source.

Queries the ThreatFox Community API for indicators of compromise (IOCs).
ThreatFox is an open IOC sharing platform by abuse.ch.

API Reference: https://threatfox.abuse.ch/api/
Auth Portal: https://auth.abuse.ch/

Supported IOC types:
  - hash_md5 / hash_sha256: File hash lookup (search_hash endpoint)
  - ip_v4 / ip_v6: IP address lookup (search_ioc endpoint)
  - domain: Domain name lookup (search_ioc endpoint)
  - url: URL lookup (search_ioc endpoint)

Rate Limits:
  Community API: Fair use principles
  For commercial use: requires paid subscription

Author: Agrashandhani
Version: 1.1
"""
import logging
import json
from typing import Dict, Any

from sources.base import Source
from config import THREATFOX_API_URL, THREATFOX_API_KEY

logger = logging.getLogger(__name__)

# Map IOC types to ThreatFox search endpoints
_IOC_TYPE_MAP = {
    "hash_md5": "search_hash",
    "hash_sha256": "search_hash",
    "ip_v4": "search_ioc",
    "ip_v6": "search_ioc",
    "domain": "search_ioc",
    "url": "search_ioc",
}

# Supported IOC types - used for validation and help text
SUPPORTED_IOC_TYPES = set(_IOC_TYPE_MAP.keys())


class ThreatFoxSource(Source):
    """ThreatFox source queries the open IOC sharing platform.

    Provides comprehensive IOC lookups across domains, IPs, URLs, and file hashes
    contributed by the threat intelligence community.

    Supported IOC types:
      - hash_md5 / hash_sha256: File hash lookup
      - ip_v4 / ip_v6: IP address lookup
      - domain: Domain name lookup
      - url: URL lookup

    Attributes:
        api_url: Base URL for the ThreatFox API.
        api_key: ThreatFox authentication key loaded from config.

    Example:
        >>> source = ThreatFoxSource()
        >>> result = source.query("domain", "example.com")
        >>> print(result["query_status"])
        'ok'
    """

    def __init__(self) -> None:
        """Initialize ThreatFox source with API configuration."""
        super().__init__("threatfox", timeout=15)
        self.api_url = THREATFOX_API_URL
        self.api_key = THREATFOX_API_KEY

    def get_supported_types(self) -> set:
        """Get the set of IOC types supported by ThreatFox.

        Returns:
            Set of supported IOC type strings.
        """
        return SUPPORTED_IOC_TYPES.copy()

    def is_supported(self, ioc_type: str) -> bool:
        """Check if an IOC type is supported.

        Args:
            ioc_type: The IOC type to check.

        Returns:
            True if supported, False otherwise.
        """
        return ioc_type in SUPPORTED_IOC_TYPES

    def query(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """Query the ThreatFox API.

        Args:
            ioc_type: IOC classification (hash_md5, hash_sha256, ip_v4, ip_v6,
                domain, url).
            value: The IOC value to look up.

        Returns:
            Normalized response dict with query_status, source, and data keys.
        """
        if not self.api_key:
            return self._error_response(
                "ThreatFox API key missing",
                "Get it from https://auth.abuse.ch/",
            )

        if ioc_type not in _IOC_TYPE_MAP:
            supported_str = ", ".join(sorted(SUPPORTED_IOC_TYPES))
            return self._error_response(
                f"Unsupported IOC type: {ioc_type}",
                f"ThreatFox supports: {supported_str}",
            )

        try:
            endpoint = _IOC_TYPE_MAP[ioc_type]

            # Build request payload
            if endpoint == "search_hash":
                payload = {
                    "query": "search_hash",
                    "hash": value,
                }
            elif endpoint == "search_ioc":
                payload = {
                    "query": "search_ioc",
                    "search_term": value,
                    "exact_match": True,
                }
            else:
                return self._error_response(f"Unknown endpoint: {endpoint}")

            # Prepare headers with authentication
            headers = {
                "Auth-Key": self.api_key,
                "Content-Type": "application/json",
            }

            # Make API request using data parameter with JSON string
            response = self.client.request(
                "POST",
                self.api_url,
                data=json.dumps(payload),
                headers=headers,
                timeout=self.timeout,
            )

            # Check if response is an error dict (from RateLimitedClient)
            if isinstance(response, dict) and "error" in response:
                return self._error_response(
                    "ThreatFox API request failed",
                    response.get("error", "Unknown error"),
                )

            # Check query status - accept both "ok" and "no_result"
            query_status = response.get("query_status", "unknown")
            if query_status == "ok":
                # Return success response with API data
                return self._success_response(response.get("data", []))
            elif query_status == "no_result":
                # Return success response with empty data for no results
                return self._success_response([])
            else:
                # Handle other error statuses
                return self._error_response(
                    f"API query failed with status: {query_status}",
                    response.get("errors", "No error details provided"),
                )

        except Exception as e:
            return self._error_response(
                f"ThreatFox API query failed: {type(e).__name__}",
                str(e),
            )
