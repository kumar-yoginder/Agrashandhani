"""
SecurityTrails Threat Intelligence Source.

Queries the SecurityTrails API for domain, hostname, and IP intelligence.
Reference: https://docs.securitytrails.com/reference

Author: Agrashandhani
Version: 1.1
"""
import logging
from typing import Any

from sources.base import Source
from config import SECURITYTRAILS_API_KEY, SECURITYTRAILS_API_URL

logger = logging.getLogger(__name__)


class SecurityTrailsSource(Source):
    """SecurityTrails API source for domain and IP intelligence.

    Supported IOC types:
    - ``ip_v4``: IP-to-hostname associations
    - ``domain``: DNS records and WHOIS data

    Attributes:
        api_url: SecurityTrails API base URL.
        api_key: SecurityTrails API key.
    """

    def __init__(self) -> None:
        super().__init__("securitytrails")
        self.api_url = SECURITYTRAILS_API_URL
        self.api_key = SECURITYTRAILS_API_KEY

    def query(self, ioc_type: str, value: str) -> dict:
        """Query the SecurityTrails API.

        Args:
            ioc_type: IOC classification (``ip_v4`` or ``domain``).
            value: The IOC value to look up.

        Returns:
            Normalised response dict.
        """
        if not self.api_key:
            return self._error_response(
                "SecurityTrails API key not configured",
                "Set SECURITYTRAILS_API_KEY. "
                "Register at https://securitytrails.com/app/account/credentials",
            )

        if ioc_type == "domain":
            return self._query_domain(value)
        if ioc_type == "ip_v4":
            return self._query_ip(value)

        return self._error_response(
            f"Unsupported IOC type: {ioc_type}",
            "SecurityTrails supports: domain, ip_v4",
        )

    def _build_headers(self) -> dict:
        return {
            "APIKEY": self.api_key,
            "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
            "Accept": "application/json",
        }

    def _query_domain(self, domain: str) -> dict:
        """Fetch domain DNS and WHOIS data from SecurityTrails.

        Endpoint: ``GET /v1/domain/{domain}``

        Args:
            domain: Domain name to look up.

        Returns:
            Normalised response dict.
        """
        try:
            response = self.client.request(
                "GET",
                f"{self.api_url}/domain/{domain}",
                headers=self._build_headers(),
            )

            if not isinstance(response, dict):
                return self._error_response("Unexpected response format")

            if response.get("message") and not response.get("hostname"):
                return self._error_response(
                    f"SecurityTrails API error: {response['message']}",
                    "Domain not found or API limit exceeded",
                )

            return self._success_response(response)

        except Exception as exc:
            logger.exception("[securitytrails] Unexpected error querying domain %s", domain)
            return self._error_response(f"Unexpected error: {exc}")

    def _query_ip(self, ip_address: str) -> dict:
        """Fetch hostname associations for an IP from SecurityTrails.

        Endpoint: ``GET /v1/ips/nearby/{ip}``

        Args:
            ip_address: IPv4 address to look up.

        Returns:
            Normalised response dict.
        """
        try:
            response = self.client.request(
                "GET",
                f"{self.api_url}/ips/nearby/{ip_address}",
                headers=self._build_headers(),
            )

            if not isinstance(response, dict):
                return self._error_response("Unexpected response format")

            if response.get("message") and not response.get("blocks"):
                return self._error_response(
                    f"SecurityTrails API error: {response['message']}",
                    "IP not found or API limit exceeded",
                )

            return self._success_response(response)

        except Exception as exc:
            logger.exception("[securitytrails] Unexpected error querying IP %s", ip_address)
            return self._error_response(f"Unexpected error: {exc}")
