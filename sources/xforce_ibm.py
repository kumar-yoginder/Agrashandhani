"""
IBM X-Force Exchange Threat Intelligence Source

Queries the IBM X-Force Exchange API for IP, domain, URL, and hash intelligence.
Reference: https://api.xforce.ibmcloud.com/doc/
"""

import base64
from typing import Dict, Any
from sources.base import Source
from clients import RateLimitedClient
from config import XFORCE_API_URL, XFORCE_API_KEY, XFORCE_API_PASSWORD


class XForceIBMSource(Source):
    """
    IBM X-Force Exchange API source for comprehensive threat intelligence.

    Supported IOC types:
    - hash_md5: MD5 file hash
    - hash_sha1: SHA1 file hash
    - hash_sha256: SHA256 file hash
    - ip_v4: IPv4 address
    - ip_v6: IPv6 address
    - domain: Domain name
    - url: URL

    Features:
    - IP reputation and geolocation
    - Domain/URL threat scoring and categorization
    - Malware hash analysis and family attribution
    - Passive DNS data
    - Vulnerability intelligence
    - Threat actor and campaign correlation

    Reference:
    - https://api.xforce.ibmcloud.com/doc/ (API documentation)
    - Register at: https://exchange.xforce.ibmcloud.com/settings/api
    """

    def __init__(self):
        """Initialize X-Force source with API credentials from config."""
        super().__init__("xforce_ibm")
        self.api_url = XFORCE_API_URL
        self.api_key = XFORCE_API_KEY
        self.api_password = XFORCE_API_PASSWORD

    def _get_auth_header(self) -> str:
        """
        Build HTTP Basic Auth header from API key and password.

        Returns:
            Base64-encoded Basic auth header value
        """
        credentials = f"{self.api_key}:{self.api_password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"

    def query(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """
        Query IBM X-Force Exchange API.

        Args:
            ioc_type: Type of IOC (hash_*, ip_v4, ip_v6, domain, url)
            value: The IOC value to search for

        Returns:
            Normalized response dictionary with query_status, source, and data
        """
        if not self.api_key or not self.api_password:
            return self._error_response(
                "X-Force IBM API credentials not configured",
                "Set XFORCE_API_KEY and XFORCE_API_PASSWORD environment variables. "
                "Register at https://exchange.xforce.ibmcloud.com/settings/api"
            )

        if ioc_type.startswith("hash_"):
            return self._query_hash(value)
        elif ioc_type.startswith("ip_"):
            return self._query_ip(value)
        elif ioc_type == "domain":
            return self._query_domain(value)
        elif ioc_type == "url":
            return self._query_url(value)
        else:
            return self._error_response(
                f"Unsupported IOC type: {ioc_type}",
                "X-Force IBM supports: hash_md5, hash_sha1, hash_sha256, ip_v4, ip_v6, domain, url"
            )

    def _query_hash(self, hash_value: str) -> Dict[str, Any]:
        """
        Query X-Force for malware hash analysis.

        Endpoint: GET /malware/{hash}

        Args:
            hash_value: MD5, SHA1, or SHA256 hash to look up

        Returns:
            Normalized response with malware analysis data
        """
        try:
            url = f"{self.api_url}/malware/{hash_value}"
            headers = {
                "Authorization": self._get_auth_header(),
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Accept": "application/json"
            }

            xforce_client = RateLimitedClient(max_retries=3)
            response = xforce_client.request(
                "GET",
                url,
                headers=headers,
                timeout=20
            )

            return self._handle_response(response)

        except Exception as e:
            return self._error_response(
                f"Query failed: {str(e)}",
                "Error querying X-Force IBM API"
            )

    def _query_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Query X-Force for IP reputation.

        Endpoint: GET /ipr/{ip}

        Args:
            ip_address: IPv4 or IPv6 address to look up

        Returns:
            Normalized response with IP reputation and geolocation data
        """
        try:
            url = f"{self.api_url}/ipr/{ip_address}"
            headers = {
                "Authorization": self._get_auth_header(),
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Accept": "application/json"
            }

            xforce_client = RateLimitedClient(max_retries=3)
            response = xforce_client.request(
                "GET",
                url,
                headers=headers,
                timeout=20
            )

            return self._handle_response(response)

        except Exception as e:
            return self._error_response(
                f"Query failed: {str(e)}",
                "Error querying X-Force IBM API"
            )

    def _query_domain(self, domain: str) -> Dict[str, Any]:
        """
        Query X-Force for domain intelligence.

        Endpoint: GET /resolve/{domain}

        Args:
            domain: Domain name to look up

        Returns:
            Normalized response with domain DNS and reputation data
        """
        try:
            url = f"{self.api_url}/resolve/{domain}"
            headers = {
                "Authorization": self._get_auth_header(),
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Accept": "application/json"
            }

            xforce_client = RateLimitedClient(max_retries=3)
            response = xforce_client.request(
                "GET",
                url,
                headers=headers,
                timeout=20
            )

            return self._handle_response(response)

        except Exception as e:
            return self._error_response(
                f"Query failed: {str(e)}",
                "Error querying X-Force IBM API"
            )

    def _query_url(self, url_value: str) -> Dict[str, Any]:
        """
        Query X-Force for URL threat analysis.

        Endpoint: GET /url/{url}

        Args:
            url_value: URL to look up

        Returns:
            Normalized response with URL threat score and categorization
        """
        try:
            endpoint_url = f"{self.api_url}/url/{url_value}"
            headers = {
                "Authorization": self._get_auth_header(),
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Accept": "application/json"
            }

            xforce_client = RateLimitedClient(max_retries=3)
            response = xforce_client.request(
                "GET",
                endpoint_url,
                headers=headers,
                timeout=20
            )

            return self._handle_response(response)

        except Exception as e:
            return self._error_response(
                f"Query failed: {str(e)}",
                "Error querying X-Force IBM API"
            )

    def _handle_response(self, response: Any) -> Dict[str, Any]:
        """
        Handle and normalize an X-Force API response.

        Args:
            response: Raw API response

        Returns:
            Normalized response dictionary
        """
        if response is None:
            return self._error_response(
                "API request failed",
                "Connection error or timeout querying X-Force IBM"
            )

        if isinstance(response, dict):
            if "error" in response:
                error_msg = response["error"]
                if "not found" in str(error_msg).lower():
                    return {
                        "query_status": "not_found",
                        "source": "xforce_ibm",
                        "data": {"message": error_msg}
                    }
                return self._error_response(
                    f"X-Force IBM API error: {error_msg}",
                    "Check your API credentials or query"
                )
            return self._success_response(response)

        return self._error_response(
            "Unexpected response format",
            "X-Force IBM returned non-JSON response"
        )

    def _success_response(self, data: Any) -> Dict[str, Any]:
        """Create a success response in standard format."""
        return {
            "query_status": "ok",
            "source": "xforce_ibm",
            "data": data
        }

    def _error_response(self, message: str, details: str = "") -> Dict[str, Any]:
        """Create an error response in standard format."""
        return {
            "query_status": "error",
            "source": "xforce_ibm",
            "data": {
                "error": message,
                "details": details
            }
        }
