"""
IBM X-Force Threat Intelligence API Source.

Queries the IBM X-Force Exchange API for comprehensive threat intelligence on
IP addresses, domains, URLs, malware, and vulnerabilities.

API Reference: https://api.xforce.ibmcloud.com/doc/
Base URL: https://api.xforce.ibmcloud.com

Supported Endpoints:
- GET /ipr/{ip}           - IP Reputation (requires premium subscription)
- GET /malware/{hash}     - Malware analysis by hash
- GET /resolve/{domain}   - Domain DNS and reputation
- GET /url/{url}          - URL threat assessment
- GET /whois/{ip}         - WHOIS information
- GET /dns/{domain}       - DNS records

Author: Agrashandhani
Version: 1.2
"""
import base64
import logging
from typing import Any, Optional

from sources.base import Source
from config import XFORCE_API_KEY, XFORCE_API_PASSWORD, XFORCE_API_URL

logger = logging.getLogger(__name__)


class XForceIBMSource(Source):
    """IBM X-Force Threat Intelligence API source.

    X-Force is IBM's cloud-based threat intelligence sharing platform that
    aggregates threat data from multiple sources including:
    - Advanced malware analysis
    - IP and domain reputation
    - URL categorization and malware detection
    - Vulnerability information
    - Early warning data
    - Threat group tracking

    Supported IOC types:
    - ``hash_md5`` / ``hash_sha1`` / ``hash_sha256``: Malware analysis
    - ``ip_v4`` / ``ip_v6``: IP reputation and geolocation
    - ``domain``: Domain DNS records and reputation
    - ``url``: URL threat score and categorization

    Authentication:
    - Uses HTTP Basic Authentication (API key + password)
    - Must set XFORCE_API_KEY and XFORCE_API_PASSWORD environment variables
    - Generate credentials at https://exchange.xforce.ibmcloud.com/settings/api

    Rate Limits:
    - Free tier: Limited requests per day
    - Premium tier: 3,000 requests per minute
    - 402 status code: Quota exceeded (monthly limit reached)

    Response Codes:
    - 2xx: Success
    - 4xx: Client error (invalid input, auth failure, quota exceeded)
    - 5xx: Server error

    Subscription Tiers:
    - Essentials: Basic IP, URL, malware, domain enrichment
    - Standard: Real-time threat detection feeds via STIX/TAXII
    - Premium: Threat groups, campaigns, industry-specific analysis

    Attributes:
        api_url: X-Force API base URL (https://api.xforce.ibmcloud.com).
        api_key: API key for authentication.
        api_password: API password for authentication.
    """

    def __init__(self) -> None:
        """Initialize X-Force IBM source with API credentials."""
        super().__init__("xforce_ibm")
        self.api_url = XFORCE_API_URL
        self.api_key = XFORCE_API_KEY
        self.api_password = XFORCE_API_PASSWORD

    def _auth_header(self) -> str:
        """Build HTTP Basic Authentication header.

        X-Force API requires HTTP Basic Auth with API key as username
        and API password as password.

        Returns:
            Authorization header value: "Basic <base64(key:password)>"
        """
        credentials = f"{self.api_key}:{self.api_password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"

    def _build_headers(self) -> dict:
        """Build standard HTTP headers for X-Force API requests.

        Returns:
            Dict with Authorization, User-Agent, and Accept headers.
        """
        return {
            "Authorization": self._auth_header(),
            "User-Agent": "Agrashandhani/1.2 (OSINT Tool)",
            "Accept": "application/json",
        }

    def query(self, ioc_type: str, value: str) -> dict:
        """Query the IBM X-Force Threat Intelligence API.

        Routes to appropriate endpoint based on IOC type and queries the API
        with proper authentication and error handling.

        Args:
            ioc_type: IOC classification (hash_*, ip_v4, ip_v6, domain, url).
            value: The IOC value to look up.

        Returns:
            Normalized response dict with query_status, source, and data.
        """
        if not self.api_key or not self.api_password:
            return self._error_response(
                "X-Force IBM API credentials not configured",
                "Set XFORCE_API_KEY and XFORCE_API_PASSWORD environment variables. "
                "Generate at https://exchange.xforce.ibmcloud.com/settings/api",
            )

        if ioc_type.startswith("hash_"):
            return self._query_malware(value)
        elif ioc_type.startswith("ip_"):
            return self._query_ip_reputation(value)
        elif ioc_type == "domain":
            return self._query_domain(value)
        elif ioc_type == "url":
            return self._query_url(value)
        else:
            return self._error_response(
                f"Unsupported IOC type: {ioc_type}",
                "X-Force IBM supports: hash_md5, hash_sha1, hash_sha256, "
                "ip_v4, ip_v6, domain, url",
            )

    def _query_malware(self, hash_value: str) -> dict:
        """Query X-Force for malware analysis by file hash.

        API Endpoint: GET /malware/{hash}

        Returns malware metadata including:
        - File hash (MD5, SHA1, SHA256)
        - Detection status
        - Family classification
        - File type and properties
        - AV detection count
        - First/last seen dates
        - Associated URLs and IPs

        Args:
            hash_value: MD5, SHA1, or SHA256 file hash.

        Returns:
            Normalized response dict (success, not_found, or error).
        """
        try:
            url = f"{self.api_url}/malware/{hash_value}"
            response = self.client.request(
                "GET",
                url,
                headers=self._build_headers(),
                timeout=self.timeout,
            )
            return self._normalize_malware_response(response, hash_value)
        except Exception as exc:
            logger.exception("[xforce_ibm] Unexpected error querying malware hash %s", hash_value)
            return self._error_response(f"Unexpected error: {exc}", log=False)

    def _query_ip_reputation(self, ip_address: str) -> dict:
        """Query X-Force for IP reputation and threat analysis.

        API Endpoint: GET /ipr/{ip}

        Returns IP threat intelligence including:
        - IP address and geolocation
        - Reputation score (0-100)
        - Threat categories
        - Risk rating
        - Recent activity
        - Malware and phishing associations
        - Blocked status
        - Historical data

        Note: Requires premium subscription tier.

        Args:
            ip_address: IPv4 or IPv6 address.

        Returns:
            Normalized response dict (success, not_found, or error).
        """
        try:
            url = f"{self.api_url}/ipr/{ip_address}"
            response = self.client.request(
                "GET",
                url,
                headers=self._build_headers(),
                timeout=self.timeout,
            )
            return self._normalize_ip_response(response, ip_address)
        except Exception as exc:
            logger.exception("[xforce_ibm] Unexpected error querying IP %s", ip_address)
            return self._error_response(f"Unexpected error: {exc}", log=False)

    def _query_domain(self, domain: str) -> dict:
        """Query X-Force for domain DNS and reputation data.

        API Endpoint: GET /resolve/{domain}

        Returns domain intelligence including:
        - DNS A, MX, NS records
        - Domain age and registrar
        - Associated IPs
        - Reputation score
        - Category classification
        - Known vulnerabilities
        - Phishing/malware status

        Args:
            domain: Domain name to look up.

        Returns:
            Normalized response dict (success, not_found, or error).
        """
        try:
            url = f"{self.api_url}/resolve/{domain}"
            response = self.client.request(
                "GET",
                url,
                headers=self._build_headers(),
                timeout=self.timeout,
            )
            return self._normalize_domain_response(response, domain)
        except Exception as exc:
            logger.exception("[xforce_ibm] Unexpected error querying domain %s", domain)
            return self._error_response(f"Unexpected error: {exc}", log=False)

    def _query_url(self, url_value: str) -> dict:
        """Query X-Force for URL threat assessment.

        API Endpoint: GET /url/{url}

        Returns URL threat intelligence including:
        - URL risk/threat score
        - Malware detection status
        - Phishing indicators
        - Content categories
        - Reputation history
        - Domain information
        - SSL certificate details

        Args:
            url_value: URL to analyze.

        Returns:
            Normalized response dict (success, not_found, or error).
        """
        try:
            url = f"{self.api_url}/url/{url_value}"
            response = self.client.request(
                "GET",
                url,
                headers=self._build_headers(),
                timeout=self.timeout,
            )
            return self._normalize_url_response(response, url_value)
        except Exception as exc:
            logger.exception("[xforce_ibm] Unexpected error querying URL %s", url_value)
            return self._error_response(f"Unexpected error: {exc}", log=False)

    def _normalize_malware_response(self, response: dict, hash_value: str) -> dict:
        """Normalize X-Force malware analysis response.

        Args:
            response: Raw API response.
            hash_value: Hash that was queried.

        Returns:
            Normalized response dict.
        """
        if not isinstance(response, dict):
            return self._error_response(
                "Unexpected response format from X-Force",
                f"Expected JSON, got {type(response).__name__}"
            )

        # Check for errors
        if "error" in response:
            error_msg = response.get("error", "Unknown error")
            if "not found" in str(error_msg).lower():
                return self._not_found_response(f"Malware hash not found: {hash_value}")
            return self._error_response(f"X-Force API error: {error_msg}")

        # 402: Quota exceeded (monthly limit)
        # This typically comes through as an error in the response
        if response.get("status_code") == 402 or "quota" in str(response).lower():
            return self._error_response(
                "X-Force quota exceeded",
                "Monthly record limit reached. Upgrade subscription or wait for reset."
            )

        # No data found (hash exists but no detections)
        if not response or response.get("count", 0) == 0:
            return self._not_found_response(f"No malware data for hash: {hash_value}")

        # Successful response
        return self._success_response(response)

    def _normalize_ip_response(self, response: dict, ip_address: str) -> dict:
        """Normalize X-Force IP reputation response.

        Args:
            response: Raw API response.
            ip_address: IP that was queried.

        Returns:
            Normalized response dict.
        """
        if not isinstance(response, dict):
            return self._error_response(
                "Unexpected response format from X-Force",
                f"Expected JSON, got {type(response).__name__}"
            )

        # Check for errors
        if "error" in response:
            error_msg = response.get("error", "Unknown error")
            if "invalid" in str(error_msg).lower() or "not found" in str(error_msg).lower():
                return self._not_found_response(f"IP not found or invalid: {ip_address}")
            return self._error_response(f"X-Force API error: {error_msg}")

        # 402: Quota exceeded
        if response.get("status_code") == 402:
            return self._error_response(
                "X-Force quota exceeded",
                "Monthly record limit reached. Upgrade subscription or wait for reset."
            )

        # Empty response (IP not in threat database - may still be valid)
        if not response or len(response) == 0:
            return self._not_found_response(f"No X-Force data available for IP: {ip_address}")

        # Successful response
        return self._success_response(response)

    def _normalize_domain_response(self, response: dict, domain: str) -> dict:
        """Normalize X-Force domain DNS/reputation response.

        Args:
            response: Raw API response.
            domain: Domain that was queried.

        Returns:
            Normalized response dict.
        """
        if not isinstance(response, dict):
            return self._error_response(
                "Unexpected response format from X-Force",
                f"Expected JSON, got {type(response).__name__}"
            )

        # Check for errors
        if "error" in response:
            error_msg = response.get("error", "Unknown error")
            if "not found" in str(error_msg).lower():
                return self._not_found_response(f"Domain not found: {domain}")
            return self._error_response(f"X-Force API error: {error_msg}")

        # 402: Quota exceeded
        if response.get("status_code") == 402:
            return self._error_response(
                "X-Force quota exceeded",
                "Monthly record limit reached. Upgrade subscription or wait for reset."
            )

        # Empty response
        if not response:
            return self._not_found_response(f"No X-Force data available for domain: {domain}")

        # Successful response
        return self._success_response(response)

    def _normalize_url_response(self, response: dict, url_value: str) -> dict:
        """Normalize X-Force URL threat assessment response.

        Args:
            response: Raw API response.
            url_value: URL that was queried.

        Returns:
            Normalized response dict.
        """
        if not isinstance(response, dict):
            return self._error_response(
                "Unexpected response format from X-Force",
                f"Expected JSON, got {type(response).__name__}"
            )

        # Check for errors
        if "error" in response:
            error_msg = response.get("error", "Unknown error")
            if "not found" in str(error_msg).lower():
                return self._not_found_response(f"URL not found: {url_value}")
            return self._error_response(f"X-Force API error: {error_msg}")

        # 402: Quota exceeded
        if response.get("status_code") == 402:
            return self._error_response(
                "X-Force quota exceeded",
                "Monthly record limit reached. Upgrade subscription or wait for reset."
            )

        # Empty response
        if not response:
            return self._not_found_response(f"No X-Force data available for URL: {url_value}")

        # Successful response
        return self._success_response(response)

