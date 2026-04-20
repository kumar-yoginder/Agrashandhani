"""
Team Cymru Hash/IP Reputation Source.

Queries the Team Cymru REST API for hash and IP reputation data.
Reference: https://hash.cymru.com/docs_rest

Author: Agrashandhani
Version: 1.1
"""
import logging
from typing import Any

from sources.base import Source
from config import CYMRU_API_PASSWORD, CYMRU_API_URL, CYMRU_API_USERNAME

logger = logging.getLogger(__name__)


class CymruSource(Source):
    """Team Cymru API source for hash and IP reputation lookups.

    Supported IOC types:
    - ``hash_md5`` / ``hash_sha1`` / ``hash_sha256``: hash reputation
    - ``ip_v4``: IP-to-ASN/BGP mapping

    Authentication uses HTTP Basic auth.

    Attributes:
        api_url: Team Cymru REST API base URL.
        username: Cymru API username.
        password: Cymru API password.
    """

    def __init__(self) -> None:
        super().__init__("cymru")
        self.api_url = CYMRU_API_URL
        self.username = CYMRU_API_USERNAME
        self.password = CYMRU_API_PASSWORD

    def query(self, ioc_type: str, value: str) -> dict:
        """Query Team Cymru for hash or IP reputation.

        Args:
            ioc_type: IOC classification (``hash_*`` or ``ip_v4``).
            value: The IOC value to look up.

        Returns:
            Normalised response dict.
        """
        if not self.username or not self.password:
            return self._error_response(
                "Cymru credentials not configured",
                "Set CYMRU_API_USERNAME and CYMRU_API_PASSWORD. "
                "Register at https://hash.cymru.com/",
            )

        if ioc_type.startswith("hash_"):
            return self._query_endpoint(value)
        if ioc_type == "ip_v4":
            return self._query_endpoint(value)

        return self._error_response(
            f"Unsupported IOC type: {ioc_type}",
            "Cymru supports: hash_md5, hash_sha1, hash_sha256, ip_v4",
        )

    def _query_endpoint(self, indicator: str) -> dict:
        """Query a Cymru endpoint for the given indicator (hash or IP).

        Endpoint: ``GET /v2/query/{indicator}``

        Args:
            indicator: Hash or IPv4 address to look up.

        Returns:
            Normalised response dict.
        """
        try:
            url = f"{self.api_url}/query/{indicator}"
            headers = {
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Accept": "application/json",
            }

            response = self.client.request(
                "GET",
                url,
                headers=headers,
                auth=(self.username, self.password),
            )

            if not isinstance(response, dict):
                return self._error_response(
                    "Unexpected response format",
                    "Cymru returned a non-JSON response",
                )

            if "error" in response:
                return self._error_response(
                    f"Cymru API error: {response['error']}",
                    str(response.get("message", "")),
                )

            return self._success_response(response)

        except Exception as exc:
            logger.exception("[cymru] Unexpected error querying %s", indicator)
            return self._error_response(f"Unexpected error: {exc}", log=False)
