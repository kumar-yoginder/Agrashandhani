"""
GreyNoise Community Threat Intelligence Source.

Queries the GreyNoise Community API for IP context and background noise
analysis.
Reference: https://docs.greynoise.io/reference/get_v3-community-ip

Author: Agrashandhani
Version: 1.1
"""
import logging
from typing import Any

from sources.base import Source
from config import GREYNOISE_API_KEY, GREYNOISE_API_URL

logger = logging.getLogger(__name__)


class GreyNoiseSource(Source):
    """GreyNoise Community API source for IP reputation and context.

    Supported IOC types:
    - ``ip_v4``: internet background-noise classification

    Attributes:
        api_url: GreyNoise API base URL.
        api_key: GreyNoise API key.
    """

    def __init__(self) -> None:
        super().__init__("greynoise")
        self.api_url = GREYNOISE_API_URL
        self.api_key = GREYNOISE_API_KEY

    def query(self, ioc_type: str, value: str) -> dict:
        """Query the GreyNoise Community API.

        Args:
            ioc_type: IOC classification (``ip_v4``).
            value: IPv4 address to look up.

        Returns:
            Normalised response dict.
        """
        if not self.api_key:
            return self._error_response(
                "GreyNoise API key not configured",
                "Set GREYNOISE_API_KEY. "
                "Register at https://www.greynoise.io/account/signup",
            )

        if ioc_type == "ip_v4":
            return self._query_ip(value)

        return self._error_response(
            f"Unsupported IOC type: {ioc_type}",
            "GreyNoise Community API supports: ip_v4",
        )

    def _query_ip(self, ip_address: str) -> dict:
        """Fetch IP classification from the GreyNoise Community endpoint.

        Endpoint: ``GET /v3/community/{ip}``

        Args:
            ip_address: IPv4 address to look up.

        Returns:
            Normalised response dict.
        """
        try:
            url = f"{self.api_url}/community/{ip_address}"
            headers = {
                "key": self.api_key,
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Accept": "application/json",
            }

            response = self.client.request("GET", url, headers=headers)

            if not isinstance(response, dict):
                return self._error_response("Unexpected response format")

            if response.get("message") == "This IP is not in our database.":
                return self._not_found_response(response["message"])

            if response.get("message") and not response.get("ip"):
                return self._error_response(
                    f"GreyNoise API error: {response['message']}",
                    "Check your API key or query parameters",
                )

            return self._success_response(self._normalize_response(response))

        except Exception as exc:
            logger.exception("[greynoise] Unexpected error querying %s", ip_address)
            return self._error_response(f"Unexpected error: {exc}")

    def _normalize_response(self, data: dict) -> dict:
        """Extract the key fields from a GreyNoise community response.

        Args:
            data: Raw GreyNoise response.

        Returns:
            Normalised dict.
        """
        return {
            "ip": data.get("ip"),
            "noise": data.get("noise"),
            "riot": data.get("riot"),
            "classification": data.get("classification"),
            "name": data.get("name"),
            "link": data.get("link"),
            "last_seen": data.get("last_seen"),
            "message": data.get("message"),
            "raw_data": data,
        }
