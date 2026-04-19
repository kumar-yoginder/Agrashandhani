"""
Shodan Threat Intelligence Source.

Queries the Shodan API for internet-wide scan data, open ports, and host
information.
Reference: https://developer.shodan.io/api

Author: Agrashandhani
Version: 1.1
"""
import logging
from typing import Any

from sources.base import Source
from config import SHODAN_API_KEY, SHODAN_API_URL

logger = logging.getLogger(__name__)


class ShodanSource(Source):
    """Shodan API source for internet-connected device and host intelligence.

    Supported IOC types:
    - ``ip_v4``: host scan data (open ports, services, CVEs)
    - ``domain``: DNS records and subdomains

    Attributes:
        api_url: Shodan API base URL.
        api_key: Shodan API key.
    """

    def __init__(self) -> None:
        super().__init__("shodan")
        self.api_url = SHODAN_API_URL
        self.api_key = SHODAN_API_KEY

    def query(self, ioc_type: str, value: str) -> dict:
        """Query the Shodan API.

        Args:
            ioc_type: IOC classification (``ip_v4`` or ``domain``).
            value: The IOC value to look up.

        Returns:
            Normalised response dict.
        """
        if not self.api_key:
            return self._error_response(
                "Shodan API key not configured",
                "Set SHODAN_API_KEY. Register at https://account.shodan.io/",
            )

        if ioc_type == "ip_v4":
            return self._query_host(value)
        if ioc_type == "domain":
            return self._query_domain(value)

        return self._error_response(
            f"Unsupported IOC type: {ioc_type}",
            "Shodan supports: ip_v4, domain",
        )

    def _build_headers(self) -> dict:
        return {
            "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
            "Accept": "application/json",
        }

    def _query_host(self, ip_address: str) -> dict:
        """Fetch host scan data by IP address from Shodan.

        Endpoint: ``GET /shodan/host/{ip}``

        Args:
            ip_address: IPv4 address to look up.

        Returns:
            Normalised response dict.
        """
        try:
            response = self.client.request(
                "GET",
                f"{self.api_url}/shodan/host/{ip_address}",
                headers=self._build_headers(),
                params={"key": self.api_key},
            )

            if not isinstance(response, dict):
                return self._error_response("Unexpected response format")

            if "error" in response:
                error_msg = response["error"]
                if "no information available" in str(error_msg).lower():
                    return self._not_found_response(str(error_msg))
                return self._error_response(
                    f"Shodan API error: {error_msg}",
                    "Check your API key or query",
                )

            return self._success_response(self._normalize_host(response))

        except Exception as exc:
            logger.exception("[shodan] Unexpected error querying host %s", ip_address)
            return self._error_response(f"Unexpected error: {exc}", log=False)

    def _query_domain(self, domain: str) -> dict:
        """Fetch domain DNS information from Shodan.

        Endpoint: ``GET /dns/domain/{domain}``

        Args:
            domain: Domain name to look up.

        Returns:
            Normalised response dict.
        """
        try:
            response = self.client.request(
                "GET",
                f"{self.api_url}/dns/domain/{domain}",
                headers=self._build_headers(),
                params={"key": self.api_key},
            )

            if not isinstance(response, dict):
                return self._error_response("Unexpected response format")

            if "error" in response:
                return self._error_response(
                    f"Shodan API error: {response['error']}",
                    "Check your API key or domain",
                )

            return self._success_response(response)

        except Exception as exc:
            logger.exception("[shodan] Unexpected error querying domain %s", domain)
            return self._error_response(f"Unexpected error: {exc}", log=False)

    def _normalize_host(self, data: dict) -> dict:
        """Extract key threat indicators from a Shodan host response.

        Args:
            data: Raw Shodan host response.

        Returns:
            Normalised dict with the most relevant fields.
        """
        return {
            "ip_str": data.get("ip_str"),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            "country_name": data.get("country_name"),
            "country_code": data.get("country_code"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "os": data.get("os"),
            "tags": data.get("tags", []),
            "vulns": data.get("vulns", []),
            "last_update": data.get("last_update"),
            "data": data.get("data", []),
            "raw_data": data,
        }
