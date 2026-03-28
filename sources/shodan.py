"""
Shodan Threat Intelligence Source

Queries the Shodan API for internet-wide scan data, open ports, and host information.
Reference: https://developer.shodan.io/api
"""

from typing import Dict, Any
from sources.base import Source
from clients import RateLimitedClient
from config import SHODAN_API_URL, SHODAN_API_KEY


class ShodanSource(Source):
    """
    Shodan API source for internet-connected device and host intelligence.

    Supported IOC types:
    - ip_v4: IPv4 address
    - domain: Domain name

    Features:
    - Open ports and running services per host
    - Banner/fingerprint data for exposed services
    - Vulnerability (CVE) associations
    - Geolocation and ASN data
    - Domain to IP resolution

    Reference:
    - https://developer.shodan.io/api (API documentation)
    - Register at: https://account.shodan.io/
    """

    def __init__(self):
        """Initialize Shodan source with API key from config."""
        super().__init__("shodan")
        self.api_url = SHODAN_API_URL
        self.api_key = SHODAN_API_KEY

    def query(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """
        Query Shodan API.

        Args:
            ioc_type: Type of IOC (ip_v4, domain)
            value: The IOC value to search for

        Returns:
            Normalized response dictionary with query_status, source, and data
        """
        if not self.api_key:
            return self._error_response(
                "Shodan API key not configured",
                "Set SHODAN_API_KEY environment variable. "
                "Register at https://account.shodan.io/"
            )

        if ioc_type == "ip_v4":
            return self._query_host(value)
        elif ioc_type == "domain":
            return self._query_domain(value)
        else:
            return self._error_response(
                f"Unsupported IOC type: {ioc_type}",
                "Shodan supports: ip_v4, domain"
            )

    def _query_host(self, ip_address: str) -> Dict[str, Any]:
        """
        Query Shodan for host information by IP address.

        Endpoint: GET /shodan/host/{ip}

        Args:
            ip_address: IPv4 address to look up

        Returns:
            Normalized response with open ports, services, and vulnerability data
        """
        try:
            url = f"{self.api_url}/shodan/host/{ip_address}"
            params = {"key": self.api_key}
            headers = {
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Accept": "application/json"
            }

            shodan_client = RateLimitedClient(max_retries=3)
            response = shodan_client.request(
                "GET",
                url,
                headers=headers,
                params=params,
                timeout=20
            )

            if response is None:
                return self._error_response(
                    "API request failed",
                    "Connection error or timeout querying Shodan"
                )

            if isinstance(response, dict):
                if "error" in response:
                    error_msg = response["error"]
                    if "no information available" in str(error_msg).lower():
                        return {
                            "query_status": "not_found",
                            "source": "shodan",
                            "data": {"message": error_msg}
                        }
                    return self._error_response(
                        f"Shodan API error: {error_msg}",
                        "Check your API key or query"
                    )
                return self._success_response(self._normalize_host(response))

            return self._error_response(
                "Unexpected response format",
                "Shodan returned non-JSON response"
            )

        except Exception as e:
            return self._error_response(
                f"Query failed: {str(e)}",
                "Error querying Shodan API"
            )

    def _query_domain(self, domain: str) -> Dict[str, Any]:
        """
        Query Shodan for domain DNS information.

        Endpoint: GET /dns/domain/{domain}

        Args:
            domain: Domain name to look up

        Returns:
            Normalized response with DNS records and subdomains
        """
        try:
            url = f"{self.api_url}/dns/domain/{domain}"
            params = {"key": self.api_key}
            headers = {
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Accept": "application/json"
            }

            shodan_client = RateLimitedClient(max_retries=3)
            response = shodan_client.request(
                "GET",
                url,
                headers=headers,
                params=params,
                timeout=20
            )

            if response is None:
                return self._error_response(
                    "API request failed",
                    "Connection error or timeout querying Shodan"
                )

            if isinstance(response, dict):
                if "error" in response:
                    return self._error_response(
                        f"Shodan API error: {response['error']}",
                        "Check your API key or domain"
                    )
                return self._success_response(response)

            return self._error_response(
                "Unexpected response format",
                "Shodan returned non-JSON response"
            )

        except Exception as e:
            return self._error_response(
                f"Query failed: {str(e)}",
                "Error querying Shodan API"
            )

    def _normalize_host(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize Shodan host response to highlight key threat indicators.

        Args:
            data: Raw Shodan host response

        Returns:
            Normalized dictionary with key fields extracted
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
            "raw_data": data
        }

    def _success_response(self, data: Any) -> Dict[str, Any]:
        """Create a success response in standard format."""
        return {
            "query_status": "ok",
            "source": "shodan",
            "data": data
        }

    def _error_response(self, message: str, details: str = "") -> Dict[str, Any]:
        """Create an error response in standard format."""
        return {
            "query_status": "error",
            "source": "shodan",
            "data": {
                "error": message,
                "details": details
            }
        }
