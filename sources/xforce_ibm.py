"""
IBM X-Force Exchange Threat Intelligence Source.

Queries the IBM X-Force Exchange API for IP, domain, URL, and hash
intelligence.
Reference: https://api.xforce.ibmcloud.com/doc/

Author: Agrashandhani
Version: 1.1
"""
import base64
import logging
from typing import Any

from sources.base import Source
from config import XFORCE_API_KEY, XFORCE_API_PASSWORD, XFORCE_API_URL

logger = logging.getLogger(__name__)


class XForceIBMSource(Source):
    """IBM X-Force Exchange API source for comprehensive threat intelligence.

    Supported IOC types:
    - ``hash_md5`` / ``hash_sha1`` / ``hash_sha256``: malware analysis
    - ``ip_v4`` / ``ip_v6``: IP reputation and geolocation
    - ``domain``: domain DNS and reputation data
    - ``url``: URL threat score and categorisation

    Authentication uses HTTP Basic auth (API key + password).

    Attributes:
        api_url: X-Force API base URL.
        api_key: X-Force API key.
        api_password: X-Force API password.
    """

    def __init__(self) -> None:
        super().__init__("xforce_ibm")
        self.api_url = XFORCE_API_URL
        self.api_key = XFORCE_API_KEY
        self.api_password = XFORCE_API_PASSWORD

    def _auth_header(self) -> str:
        """Build a Base64-encoded HTTP Basic auth header value.

        Returns:
            ``"Basic <base64(key:password)>"`` string.
        """
        credentials = f"{self.api_key}:{self.api_password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"

    def _build_headers(self) -> dict:
        return {
            "Authorization": self._auth_header(),
            "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
            "Accept": "application/json",
        }

    def query(self, ioc_type: str, value: str) -> dict:
        """Query the IBM X-Force Exchange API.

        Args:
            ioc_type: IOC classification (``hash_*``, ``ip_*``, ``domain``,
                ``url``).
            value: The IOC value to look up.

        Returns:
            Normalised response dict.
        """
        if not self.api_key or not self.api_password:
            return self._error_response(
                "X-Force IBM API credentials not configured",
                "Set XFORCE_API_KEY and XFORCE_API_PASSWORD. "
                "Register at https://exchange.xforce.ibmcloud.com/settings/api",
            )

        if ioc_type.startswith("hash_"):
            return self._query_hash(value)
        if ioc_type.startswith("ip_"):
            return self._query_ip(value)
        if ioc_type == "domain":
            return self._query_domain(value)
        if ioc_type == "url":
            return self._query_url(value)

        return self._error_response(
            f"Unsupported IOC type: {ioc_type}",
            "X-Force IBM supports: hash_*, ip_v4, ip_v6, domain, url",
        )

    def _query_hash(self, hash_value: str) -> dict:
        """Fetch malware hash analysis from X-Force.

        Endpoint: ``GET /malware/{hash}``

        Args:
            hash_value: MD5, SHA1, or SHA256 hash.

        Returns:
            Normalised response dict.
        """
        try:
            response = self.client.request(
                "GET",
                f"{self.api_url}/malware/{hash_value}",
                headers=self._build_headers(),
            )
            return self._handle_response(response)
        except Exception as exc:
            logger.exception("[xforce_ibm] Unexpected error querying hash %s", hash_value)
            return self._error_response(f"Unexpected error: {exc}", log=False)

    def _query_ip(self, ip_address: str) -> dict:
        """Fetch IP reputation data from X-Force.

        Endpoint: ``GET /ipr/{ip}``

        Args:
            ip_address: IPv4 or IPv6 address.

        Returns:
            Normalised response dict.
        """
        try:
            response = self.client.request(
                "GET",
                f"{self.api_url}/ipr/{ip_address}",
                headers=self._build_headers(),
            )
            return self._handle_response(response)
        except Exception as exc:
            logger.exception("[xforce_ibm] Unexpected error querying IP %s", ip_address)
            return self._error_response(f"Unexpected error: {exc}", log=False)

    def _query_domain(self, domain: str) -> dict:
        """Fetch domain intelligence from X-Force.

        Endpoint: ``GET /resolve/{domain}``

        Args:
            domain: Domain name to look up.

        Returns:
            Normalised response dict.
        """
        try:
            response = self.client.request(
                "GET",
                f"{self.api_url}/resolve/{domain}",
                headers=self._build_headers(),
            )
            return self._handle_response(response)
        except Exception as exc:
            logger.exception("[xforce_ibm] Unexpected error querying domain %s", domain)
            return self._error_response(f"Unexpected error: {exc}", log=False)

    def _query_url(self, url_value: str) -> dict:
        """Fetch URL threat analysis from X-Force.

        Endpoint: ``GET /url/{url}``

        Args:
            url_value: URL to analyse.

        Returns:
            Normalised response dict.
        """
        try:
            response = self.client.request(
                "GET",
                f"{self.api_url}/url/{url_value}",
                headers=self._build_headers(),
            )
            return self._handle_response(response)
        except Exception as exc:
            logger.exception("[xforce_ibm] Unexpected error querying URL %s", url_value)
            return self._error_response(f"Unexpected error: {exc}", log=False)

    def _handle_response(self, response: Any) -> dict:
        """Normalise an X-Force API response.

        Args:
            response: Raw response dict from :class:`~clients.RateLimitedClient`.

        Returns:
            Normalised response dict.
        """
        if not isinstance(response, dict):
            return self._error_response("Unexpected response format")

        if "error" in response:
            error_msg = response["error"]
            if "not found" in str(error_msg).lower():
                return self._not_found_response(str(error_msg))
            return self._error_response(
                f"X-Force IBM API error: {error_msg}",
                "Check your API credentials or query",
            )

        return self._success_response(response)
