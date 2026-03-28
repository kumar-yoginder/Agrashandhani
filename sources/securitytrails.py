"""
SecurityTrails Threat Intelligence Source

Queries the SecurityTrails API for domain, hostname, and IP intelligence.
Reference: https://docs.securitytrails.com/reference
"""

from typing import Dict, Any
from sources.base import Source
from clients import RateLimitedClient
from config import SECURITYTRAILS_API_URL, SECURITYTRAILS_API_KEY


class SecurityTrailsSource(Source):
    """
    SecurityTrails API source for domain and IP intelligence.

    Supported IOC types:
    - ip_v4: IPv4 address
    - domain: Domain name

    Features:
    - Current and historical DNS records
    - IP to hostname mapping
    - Domain reputation and WHOIS data
    - Subdomain enumeration
    - Associated infrastructure discovery

    Reference:
    - https://docs.securitytrails.com/reference (API documentation)
    - Register at: https://securitytrails.com/app/account/credentials
    """

    def __init__(self):
        """Initialize SecurityTrails source with API key from config."""
        super().__init__("securitytrails")
        self.api_url = SECURITYTRAILS_API_URL
        self.api_key = SECURITYTRAILS_API_KEY

    def query(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """
        Query SecurityTrails API.

        Args:
            ioc_type: Type of IOC (ip_v4, domain)
            value: The IOC value to search for

        Returns:
            Normalized response dictionary with query_status, source, and data
        """
        if not self.api_key:
            return self._error_response(
                "SecurityTrails API key not configured",
                "Set SECURITYTRAILS_API_KEY environment variable. "
                "Register at https://securitytrails.com/app/account/credentials"
            )

        if ioc_type == "domain":
            return self._query_domain(value)
        elif ioc_type == "ip_v4":
            return self._query_ip(value)
        else:
            return self._error_response(
                f"Unsupported IOC type: {ioc_type}",
                "SecurityTrails supports: domain, ip_v4"
            )

    def _query_domain(self, domain: str) -> Dict[str, Any]:
        """
        Query SecurityTrails for domain information.

        Endpoint: GET /v1/domain/{domain}

        Args:
            domain: Domain name to look up

        Returns:
            Normalized response with domain DNS and WHOIS data
        """
        try:
            url = f"{self.api_url}/domain/{domain}"
            headers = {
                "APIKEY": self.api_key,
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Accept": "application/json"
            }

            st_client = RateLimitedClient(max_retries=3)
            response = st_client.request(
                "GET",
                url,
                headers=headers,
                timeout=15
            )

            if response is None:
                return self._error_response(
                    "API request failed",
                    "Connection error or timeout querying SecurityTrails"
                )

            if isinstance(response, dict):
                if response.get("message") and not response.get("hostname"):
                    return self._error_response(
                        f"SecurityTrails API error: {response['message']}",
                        "Domain not found or API limit exceeded"
                    )
                return self._success_response(response)

            return self._error_response(
                "Unexpected response format",
                "SecurityTrails returned non-JSON response"
            )

        except Exception as e:
            return self._error_response(
                f"Query failed: {str(e)}",
                "Error querying SecurityTrails API"
            )

    def _query_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Query SecurityTrails for IP address information.

        Endpoint: GET /v1/ips/nearby/{ip}

        Args:
            ip_address: IPv4 address to look up

        Returns:
            Normalized response with hostname/domain associations
        """
        try:
            url = f"{self.api_url}/ips/nearby/{ip_address}"
            headers = {
                "APIKEY": self.api_key,
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Accept": "application/json"
            }

            st_client = RateLimitedClient(max_retries=3)
            response = st_client.request(
                "GET",
                url,
                headers=headers,
                timeout=15
            )

            if response is None:
                return self._error_response(
                    "API request failed",
                    "Connection error or timeout querying SecurityTrails"
                )

            if isinstance(response, dict):
                if response.get("message") and not response.get("blocks"):
                    return self._error_response(
                        f"SecurityTrails API error: {response['message']}",
                        "IP not found or API limit exceeded"
                    )
                return self._success_response(response)

            return self._error_response(
                "Unexpected response format",
                "SecurityTrails returned non-JSON response"
            )

        except Exception as e:
            return self._error_response(
                f"Query failed: {str(e)}",
                "Error querying SecurityTrails API"
            )

    def _success_response(self, data: Any) -> Dict[str, Any]:
        """Create a success response in standard format."""
        return {
            "query_status": "ok",
            "source": "securitytrails",
            "data": data
        }

    def _error_response(self, message: str, details: str = "") -> Dict[str, Any]:
        """Create an error response in standard format."""
        return {
            "query_status": "error",
            "source": "securitytrails",
            "data": {
                "error": message,
                "details": details
            }
        }
