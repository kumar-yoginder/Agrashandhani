"""
Shodan Threat Intelligence Source.

Queries the Shodan API for internet-wide scan data, open ports, and host
information.

API Reference: https://developer.shodan.io/api
Base URL: https://api.shodan.io

Supported Endpoints:
- GET /shodan/host/{ip}        - Host/IP lookup with service details
- GET /dns/domain/{domain}     - Domain DNS records and subdomains

Author: Agrashandhani
Version: 1.2
"""
import logging
from typing import Any, Optional

from sources.base import Source
from config import SHODAN_API_KEY, SHODAN_API_URL

logger = logging.getLogger(__name__)


class ShodanSource(Source):
    """Shodan API source for internet-connected device and host intelligence.

    The Shodan Search Engine has indexed information on every host on the
    internet. Using the API, you can access this data and integrate it into
    your security tools and applications.

    Supported IOC types:
    - ``ip_v4``: IPv4 address - returns host scan data (open ports, services, CVEs, etc.)
    - ``domain``: Domain name - returns DNS records and subdomains

    Rate Limits (varies by subscription):
    - Basic: 1 query/second
    - Premium: Higher limits available

    API Features:
    - Comprehensive open port data with banners
    - CVE information and vulnerabilities
    - Geolocation and ASN details
    - Hostname and domain information
    - Operating system detection
    - Historical data access

    Attributes:
        api_url: Shodan API base URL (https://api.shodan.io).
        api_key: API key for authentication.
    """

    def __init__(self) -> None:
        """Initialize Shodan source with API credentials."""
        super().__init__("shodan")
        self.api_url = SHODAN_API_URL
        self.api_key = SHODAN_API_KEY

    def query(self, ioc_type: str, value: str) -> dict:
        """Query the Shodan API based on IOC type.

        Args:
            ioc_type: IOC classification (``ip_v4`` or ``domain``).
            value: The IOC value to look up.

        Returns:
            Normalized response dict with query_status, source, and data.
        """
        if not self.api_key:
            return self._error_response(
                "Shodan API key not configured",
                "Set SHODAN_API_KEY environment variable. "
                "Register at https://account.shodan.io/",
            )

        if ioc_type == "ip_v4":
            return self._query_host(value)
        elif ioc_type == "domain":
            return self._query_domain(value)
        else:
            return self._error_response(
                f"Unsupported IOC type: {ioc_type}",
                "Shodan supports: ip_v4, domain",
            )

    def _build_headers(self) -> dict:
        """Build standard HTTP headers for Shodan API requests.

        Returns:
            Dict with User-Agent and Accept headers.
        """
        return {
            "User-Agent": "Agrashandhani/1.2 (OSINT Tool)",
            "Accept": "application/json",
        }

    def _query_host(self, ip_address: str) -> dict:
        """Query Shodan for host/IP information.

        API Endpoint: GET /shodan/host/{ip}

        Parameters:
            - ip (required): The IP address to look up
            - key (required): API key for authentication
            - history (optional): Show historical data (boolean)
            - minify (optional): Minimize response (boolean)

        Returns:
            Dict containing:
            - ip_str: IP address
            - ports: List of open ports
            - hostnames: Associated hostnames
            - org: Organization name
            - isp: ISP name
            - country_name: Country name
            - vulns: List of CVEs
            - data: List of banner data for each port
            - last_update: Last update timestamp

        Args:
            ip_address: IPv4 address to look up.

        Returns:
            Normalized response dict (success, not_found, or error).
        """
        try:
            url = f"{self.api_url}/shodan/host/{ip_address}"
            params = {
                "key": self.api_key,
                "minify": True,  # Reduce response size
            }

            response = self.client.request(
                "GET",
                url,
                headers=self._build_headers(),
                params=params,
                timeout=self.timeout,
            )

            return self._handle_response(response, "host", ip_address)

        except Exception as exc:
            logger.exception("[shodan] Unexpected error querying host %s", ip_address)
            return self._error_response(f"Unexpected error: {exc}", log=False)

    def _query_domain(self, domain: str) -> dict:
        """Query Shodan for domain DNS information.

        API Endpoint: GET /dns/domain/{domain}

        Parameters:
            - domain (required): Domain name to look up
            - key (required): API key for authentication

        Returns:
            Dict containing:
            - domain: Domain name
            - subdomain: List of subdomains
            - tags: Associated tags
            - last_update: Last update timestamp
            - all: List of all DNS records

        Args:
            domain: Domain name to look up.

        Returns:
            Normalized response dict (success, not_found, or error).
        """
        try:
            url = f"{self.api_url}/dns/domain/{domain}"
            params = {"key": self.api_key}

            response = self.client.request(
                "GET",
                url,
                headers=self._build_headers(),
                params=params,
                timeout=self.timeout,
            )

            return self._handle_response(response, "domain", domain)

        except Exception as exc:
            logger.exception("[shodan] Unexpected error querying domain %s", domain)
            return self._error_response(f"Unexpected error: {exc}", log=False)

    def _handle_response(self, response: dict, query_type: str, query_value: str) -> dict:
        """Handle and normalize Shodan API responses.

        Per API documentation, error responses include an "error" key with
        the reason for failure. HTTP status codes indicate request status.

        Args:
            response: Raw response dict from client.request().
            query_type: Type of query ("host" or "domain").
            query_value: The value that was queried.

        Returns:
            Normalized response dict.
        """
        if not isinstance(response, dict):
            return self._error_response(
                "Unexpected response format from Shodan",
                f"Expected JSON dict, got {type(response).__name__}",
            )

        # Check for error in response (per Shodan API docs)
        if "error" in response:
            error_msg = response.get("error", "Unknown error")
            
            # Common error messages
            if "invalid" in str(error_msg).lower():
                if query_type == "host":
                    return self._not_found_response(f"Invalid IP address: {query_value}")
                else:
                    return self._not_found_response(f"Invalid domain: {query_value}")
            elif "no information available" in str(error_msg).lower():
                return self._not_found_response(
                    f"No {query_type} information available for {query_value}"
                )
            else:
                return self._error_response(
                    f"Shodan API error: {error_msg}",
                    f"Failed to query {query_type} {query_value}",
                )

        # Empty response
        if not response:
            return self._not_found_response(
                f"No data found for {query_type} {query_value}"
            )

        # Normalize and return successful response
        if query_type == "host":
            normalized = self._normalize_host(response)
        else:
            normalized = self._normalize_domain(response)

        return self._success_response(normalized)

    def _normalize_host(self, data: dict) -> dict:
        """Extract key threat indicators from a Shodan host response.

        Per Shodan API documentation, host responses include:
        - IP information (ip_str, country, city, etc.)
        - Open ports and services
        - CVE vulnerabilities
        - Hostnames and domains
        - ISP and organization details
        - Banner data for each service

        Args:
            data: Raw Shodan host response.

        Returns:
            Normalized dict with threat-relevant fields.
        """
        # Extract banner data for key threat intel
        banners = data.get("data", [])
        services = []
        cves_from_banners = set()
        
        for banner in banners:
            if isinstance(banner, dict):
                port = banner.get("port")
                product = banner.get("product")
                version = banner.get("version")
                service = f"{product} {version}" if product else "Unknown"
                services.append({"port": port, "service": service})
                
                # Collect CVEs mentioned in banner
                if "cpe" in banner:
                    cves_from_banners.add(banner.get("cpe"))

        return {
            # IP and geolocation
            "ip_str": data.get("ip_str"),
            "country_name": data.get("country_name"),
            "country_code": data.get("country_code"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            
            # Network details
            "org": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            
            # Services and ports
            "ports": data.get("ports", []),
            "services": services,
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            
            # Security information
            "vulns": data.get("vulns", []),  # CVEs discovered
            "cves_from_banners": list(cves_from_banners),
            "tags": data.get("tags", []),
            
            # System information
            "os": data.get("os"),
            "uptime": data.get("uptime"),
            "last_update": data.get("last_update"),
            
            # Raw data for advanced analysis
            "raw_data": data,
        }

    def _normalize_domain(self, data: dict) -> dict:
        """Extract key information from a Shodan domain response.

        Per Shodan API documentation, domain responses include:
        - Subdomains
        - DNS records
        - Associated tags
        - All DNS entries

        Args:
            data: Raw Shodan domain response.

        Returns:
            Normalized dict with domain-relevant fields.
        """
        return {
            "domain": data.get("domain"),
            "subdomains": data.get("subdomain", []),
            "dns_records": data.get("all", []),
            "tags": data.get("tags", []),
            "last_update": data.get("last_update"),
            "tld": data.get("tld"),
            "raw_data": data,
        }

