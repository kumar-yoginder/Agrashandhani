"""
Any.run Threat Intelligence Source.

Queries the Any.run TI Lookup API for sandbox analysis and threat intelligence.
Reference: https://any.run/api-documentation/#ti-lookup

Author: Agrashandhani
Version: 1.1
"""
import logging
from typing import Any

from sources.base import Source
from config import ANYRUN_API_KEY, ANYRUN_API_URL

logger = logging.getLogger(__name__)

_IOC_TYPE_MAP = {
    "hash_md5": "filehash",
    "hash_sha1": "filehash",
    "hash_sha256": "filehash",
    "ip_v4": "ip",
    "domain": "domain",
    "url": "url",
}


class AnyRunSource(Source):
    """Any.run API source for sandbox-based threat intelligence.

    Supported IOC types:
    - ``hash_md5`` / ``hash_sha1`` / ``hash_sha256``: file hash lookup
    - ``ip_v4``: IP address lookup
    - ``domain``: domain lookup
    - ``url``: URL lookup

    Attributes:
        api_url: Any.run API base URL.
        api_key: Any.run authentication token.
    """

    def __init__(self) -> None:
        super().__init__("anyrun")
        self.api_url = ANYRUN_API_URL
        self.api_key = ANYRUN_API_KEY

    def query(self, ioc_type: str, value: str) -> dict:
        """Query the Any.run TI Lookup API.

        Args:
            ioc_type: IOC classification (``hash_*``, ``ip_v4``, ``domain``,
                ``url``).
            value: The IOC value to look up.

        Returns:
            Normalised response dict.
        """
        if not self.api_key:
            return self._error_response(
                "Any.run API key not configured",
                "Set ANYRUN_API_KEY. Register at https://app.any.run/",
            )

        if ioc_type not in _IOC_TYPE_MAP:
            return self._error_response(
                f"Unsupported IOC type: {ioc_type}",
                f"Any.run supports: {', '.join(_IOC_TYPE_MAP)}",
            )

        return self._query_ti_lookup(_IOC_TYPE_MAP[ioc_type], value)

    def _query_ti_lookup(self, indicator_type: str, value: str) -> dict:
        """Hit the Any.run TI Lookup endpoint.

        Endpoint: ``GET /v1/intelligence/iocs/lookup``

        Args:
            indicator_type: Any.run indicator type string (``"filehash"``,
                ``"ip"``, ``"domain"``, ``"url"``).
            value: Indicator value.

        Returns:
            Normalised response dict.
        """
        try:
            url = f"{self.api_url}/intelligence/iocs/lookup"
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Accept": "application/json",
            }
            params = {"type": indicator_type, "value": value}

            response = self.client.request("GET", url, headers=headers, params=params)

            if not isinstance(response, dict):
                return self._error_response(
                    "Unexpected response format",
                    "Any.run returned a non-JSON response",
                )

            if response.get("error"):
                error_msg = response.get("message", str(response["error"]))
                return self._error_response(
                    f"Any.run API error: {error_msg}",
                    "Check API key or query parameters",
                )

            return self._success_response(response.get("data", response))

        except Exception as exc:
            logger.exception("[anyrun] Unexpected error querying %s", value)
            return self._error_response(f"Unexpected error: {exc}", log=False)
