"""
GreyNoise Community Threat Intelligence Source

Queries the GreyNoise Community API for IP context and background noise analysis.
Reference: https://docs.greynoise.io/reference/get_v3-community-ip
"""

from typing import Dict, Any
from sources.base import Source
from clients import RateLimitedClient
from config import GREYNOISE_API_URL, GREYNOISE_API_KEY


class GreyNoiseSource(Source):
    """
    GreyNoise Community API source for IP reputation and context.

    Supported IOC types:
    - ip_v4: IPv4 address

    Features:
    - Identifies internet background noise and scanner activity
    - Distinguishes malicious from benign mass-scanning IPs
    - Classification: benign, malicious, or unknown
    - Organization and actor attribution
    - Last seen activity timestamps

    Reference:
    - https://docs.greynoise.io/reference/get_v3-community-ip (API documentation)
    - Register at: https://www.greynoise.io/account/signup
    """

    def __init__(self):
        """Initialize GreyNoise source with API key from config."""
        super().__init__("greynoise")
        self.api_url = GREYNOISE_API_URL
        self.api_key = GREYNOISE_API_KEY

    def query(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """
        Query GreyNoise Community API.

        Args:
            ioc_type: Type of IOC (ip_v4)
            value: The IOC value to search for

        Returns:
            Normalized response dictionary with query_status, source, and data
        """
        if not self.api_key:
            return self._error_response(
                "GreyNoise API key not configured",
                "Set GREYNOISE_API_KEY environment variable. "
                "Register at https://www.greynoise.io/account/signup"
            )

        if ioc_type == "ip_v4":
            return self._query_ip(value)
        else:
            return self._error_response(
                f"Unsupported IOC type: {ioc_type}",
                "GreyNoise Community API supports: ip_v4"
            )

    def _query_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Query GreyNoise Community API for IP context.

        Endpoint: GET /v3/community/{ip}

        Args:
            ip_address: IPv4 address to look up

        Returns:
            Normalized response with IP classification and context
        """
        try:
            url = f"{self.api_url}/community/{ip_address}"
            headers = {
                "key": self.api_key,
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Accept": "application/json"
            }

            gn_client = RateLimitedClient(max_retries=3)
            response = gn_client.request(
                "GET",
                url,
                headers=headers,
                timeout=15
            )

            if response is None:
                return self._error_response(
                    "API request failed",
                    "Connection error or timeout querying GreyNoise"
                )

            if isinstance(response, dict):
                if response.get("message") == "This IP is not in our database.":
                    return {
                        "query_status": "not_found",
                        "source": "greynoise",
                        "data": {"message": response["message"], "ip": ip_address}
                    }

                if response.get("message") and not response.get("ip"):
                    return self._error_response(
                        f"GreyNoise API error: {response['message']}",
                        "Check your API key or query parameters"
                    )

                return self._success_response(self._normalize_response(response))

            return self._error_response(
                "Unexpected response format",
                "GreyNoise returned non-JSON response"
            )

        except Exception as e:
            return self._error_response(
                f"Query failed: {str(e)}",
                "Error querying GreyNoise API"
            )

    def _normalize_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize GreyNoise Community API response.

        Args:
            data: Raw GreyNoise response

        Returns:
            Normalized dictionary with key threat indicators
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
            "raw_data": data
        }

    def _success_response(self, data: Any) -> Dict[str, Any]:
        """Create a success response in standard format."""
        return {
            "query_status": "ok",
            "source": "greynoise",
            "data": data
        }

    def _error_response(self, message: str, details: str = "") -> Dict[str, Any]:
        """Create an error response in standard format."""
        return {
            "query_status": "error",
            "source": "greynoise",
            "data": {
                "error": message,
                "details": details
            }
        }
