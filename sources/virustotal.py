"""
VirusTotal threat intelligence source.

Queries the VirusTotal v3 API for comprehensive file reputation and
malware analysis across 70+ antivirus engines and security tools.

API Reference: https://docs.virustotal.com/reference/overview
API Key: https://www.virustotal.com/gui/my-apikey

Supported IOC types:
  - hash_md5 / hash_sha1 / hash_sha256: File hash reputation lookup
  - ip_v4 / ip_v6: IP address reputation and geo-location
  - domain: Domain name reputation and DNS records
  - url: URL threat assessment and categorization

Rate Limits:
  - Free tier: 500 requests/day
  - Standard/Premium: Higher limits based on subscription

Author: Agrashandhani
Version: 1.1
"""
import base64
import logging
from typing import Dict, Any

from sources.base import Source
from config import VT_API_URL, VT_KEY

logger = logging.getLogger(__name__)


class VirusTotalSource(Source):
    """VirusTotal source queries 70+ antivirus engines and security tools.

    Provides comprehensive file reputation lookups, IP address threat assessment,
    domain reputation, and URL safety analysis.

    Supported IOC types:
      - hash_md5 / hash_sha1 / hash_sha256: File hash lookup
      - ip_v4 / ip_v6: IP address lookup
      - domain: Domain name lookup
      - url: URL lookup (base64-encoded identifier)

    Attributes:
        api_url: Base URL for the VirusTotal v3 API.
        api_key: VirusTotal API key loaded from config.

    Example:
        >>> source = VirusTotalSource()
        >>> result = source.query("hash_sha256", "...")
        >>> print(result["query_status"])
        'ok'
    """

    def __init__(self) -> None:
        """Initialize VirusTotal source with API configuration."""
        super().__init__("virustotal")
        self.api_url = VT_API_URL
        self.api_key = VT_KEY

    def query(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """Query the VirusTotal v3 API.

        Args:
            ioc_type: IOC classification (hash_*, ip_v4, ip_v6, domain, url).
            value: The IOC value to look up.

        Returns:
            Normalized response dict with query_status, source, and data keys.
        """
        if not self.api_key:
            return self._error_response(
                "VirusTotal API key missing",
                "Get it from https://www.virustotal.com/gui/my-apikey",
            )

        headers = {"x-apikey": self.api_key}

        try:
            if ioc_type.startswith("hash_"):
                endpoint = f"{self.api_url}/files/{value}"
            elif ioc_type.startswith("ip_"):
                endpoint = f"{self.api_url}/ip_addresses/{value}"
            elif ioc_type == "domain":
                endpoint = f"{self.api_url}/domains/{value}"
            elif ioc_type == "url":
                # VT URL identifier: URL-safe base64 without padding
                url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
                endpoint = f"{self.api_url}/urls/{url_id}"
            else:
                return self._error_response(
                    f"Unsupported IOC type: {ioc_type}",
                    "VirusTotal supports: hash_*, ip_v4, ip_v6, domain, url",
                )

            response = self.client.request(
                "GET",
                endpoint,
                headers=headers,
                timeout=self.timeout,
            )
            return self._normalize_response(response)

        except Exception as exc:
            logger.exception("[virustotal] Unexpected error querying %s", value)
            return self._error_response(f"Unexpected error: {exc}", log=False)

    def _normalize_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a VirusTotal API response.

        Converts API-specific error codes to standardized response format.

        Args:
            response: Raw dict returned by :class:`~.clients.RateLimitedClient`.

        Returns:
            Normalized response dict.
        """
        if "error" in response:
            error_code = response.get("error", {})
            if isinstance(error_code, dict) and error_code.get("code") in (
                "NotFoundError",
                "invalid_resource",
            ):
                return self._not_found_response()
            return self._error_response(str(response["error"]))

        return self._success_response(response)
