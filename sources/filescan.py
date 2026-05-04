"""
FileScan.io threat intelligence source.

API Reference: https://www.filescan.io/api/docs

Provides threat intelligence APIs for:
- IOC prevalence lookup
- Similar samples by special hashes (fuzzyfsio, imphash, ssdeep, authentihash)

Supported IOC types:
  - hash_md5 / hash_sha1 / hash_sha256: Prevalence and similar samples lookup

Author: Agrashandhani
Version: 1.1
"""
import logging
from typing import Any, Dict

from sources.base import Source
from config import FILESCAN_API_KEY, FILESCAN_API_URL

logger = logging.getLogger(__name__)


class FileScanSource(Source):
    """FileScan.io source — queries IOC prevalence and similar samples.

    Provides prevalence information for IOCs and retrieves reports with
    similar special hashes (fuzzyfsio, imphash, ssdeep, authentihash).

    Supported IOC types:
      - hash_md5 / hash_sha1 / hash_sha256: Prevalence and similar samples lookup

    Attributes:
        api_url: Base URL for the FileScan.io API.
        api_key: FileScan.io API key loaded from config.

    Example:
        >>> source = FileScanSource()
        >>> result = source.query("hash_sha256", "...")
        >>> print(result["query_status"])
        'ok'
    """

    _SUPPORTED_IOCS = {
        "hash_md5",
        "hash_sha1",
        "hash_sha256",
    }

    def __init__(self) -> None:
        """Initialize FileScan.io source with API configuration."""
        super().__init__("filescan")
        self.api_url = FILESCAN_API_URL
        self.api_key = FILESCAN_API_KEY

    def query(self, ioc_type: str, value: str) -> dict:
        """Query the FileScan.io API for IOC prevalence and similar samples.

        This method queries two endpoints:
        1. /api/threatintel/get-prevalence - Get prevalence of IOCs
        2. /api/threatintel/get-similars - Get reports with similar hashes

        Args:
            ioc_type: IOC classification (hash_md5, hash_sha1, hash_sha256).
            value: Hash value to look up.

        Returns:
            Normalised response dict containing prevalence and similar samples.
        """
        if not self.api_key:
            return self._error_response(
                "FileScan.io API key missing",
                "Get it from https://www.filescan.io/api/docs",
            )

        if ioc_type not in self._SUPPORTED_IOCS:
            return self._error_response(
                f"Unsupported IOC type: {ioc_type}",
                f"FileScan.io supports: {', '.join(sorted(self._SUPPORTED_IOCS))}",
            )

        try:
            # Query prevalence and similar samples
            prevalence_data = self._get_prevalence(value)
            similars_data = self._get_similars(value)

            # Combine results
            combined_data = {
                "prevalence": prevalence_data if isinstance(prevalence_data, dict) else None,
                "similars": similars_data if isinstance(similars_data, list) else [],
            }

            return self._success_response(combined_data)

        except Exception as exc:
            logger.exception("[filescan] Unexpected error querying %s", value)
            return self._error_response(f"Unexpected error: {exc}", log=False)

    def _get_prevalence(self, value: str) -> Any:
        """Fetch prevalence information for an IOC.

        Calls POST /api/threatintel/get-prevalence endpoint.

        Args:
            value: Hash value to query.

        Returns:
            Parsed prevalence data from the API, or None on error.
        """
        try:
            url = f"{self.api_url}/threatintel/get-prevalence"
            headers = {"Authorization": f"Bearer {self.api_key}"}
            data = {"hash": value}

            response = self.client.request(
                "POST",
                url,
                json=data,
                headers=headers,
                timeout=self.timeout,
            )

            if isinstance(response, dict):
                return response.get("data") or response
            return response

        except Exception as exc:
            logger.warning("[filescan] Error fetching prevalence for %s: %s", value, exc)
            return None

    def _get_similars(self, value: str) -> list:
        """Fetch reports with similar special hashes.

        Calls GET /api/threatintel/get-similars endpoint to find reports
        with the same special hashes (fuzzyfsio, imphash, ssdeep, authentihash).

        Args:
            value: Hash value to query.

        Returns:
            List of similar samples, or empty list on error.
        """
        try:
            url = f"{self.api_url}/threatintel/get-similars"
            headers = {"Authorization": f"Bearer {self.api_key}"}
            params = {"hash": value}

            response = self.client.request(
                "GET",
                url,
                params=params,
                headers=headers,
                timeout=self.timeout,
            )

            if isinstance(response, dict):
                data = response.get("data")
                if isinstance(data, list):
                    return data
                return [response] if response else []
            elif isinstance(response, list):
                return response
            return []

        except Exception as exc:
            logger.warning("[filescan] Error fetching similars for %s: %s", value, exc)
            return []
