"""
MalShare Threat Intelligence Source.

Queries the MalShare API for malware samples and threat intelligence.
Reference: https://malshare.com/

Author: Agrashandhani
Version: 1.1
"""
import logging
from typing import Any

from sources.base import Source
from config import MALSHARE_API_KEY, MALSHARE_API_URL

logger = logging.getLogger(__name__)

_SUPPORTED_HASH_TYPES = {"hash_md5", "hash_sha1", "hash_sha256"}


class MalShareSource(Source):
    """MalShare API source for hash-based threat intelligence.

    Supported IOC types:
    - ``hash_md5`` / ``hash_sha1`` / ``hash_sha256``

    Rate limits vary by account tier; free accounts are limited.

    Attributes:
        api_key: MalShare API key loaded from config.
        api_url: MalShare API endpoint URL.
    """

    def __init__(self) -> None:
        super().__init__("malshare")
        self.api_key = MALSHARE_API_KEY
        self.api_url = MALSHARE_API_URL

    def query(self, ioc_type: str, value: str) -> dict:
        """Query MalShare API for a file hash.

        Args:
            ioc_type: IOC classification (``hash_md5``, ``hash_sha1``,
                ``hash_sha256``).
            value: Hash value to look up.

        Returns:
            Normalised response dict.
        """
        if not self.api_key:
            return self._error_response(
                "MalShare API key not configured",
                "Get it from https://malshare.com/register.php",
            )

        if ioc_type not in _SUPPORTED_HASH_TYPES:
            return self._error_response(
                f"Unsupported IOC type: {ioc_type}",
                f"MalShare supports: {', '.join(_SUPPORTED_HASH_TYPES)}",
            )

        return self._get_details(value.lower())

    def _get_details(self, hash_value: str) -> dict:
        """Fetch detailed information about a malware sample.

        Endpoint: ``GET /api.php?action=details&hash={hash}&api_key={key}``

        Args:
            hash_value: Lowercase hash to query.

        Returns:
            Normalised response dict.
        """
        try:
            params = {
                "api_key": self.api_key,
                "action": "details",
                "hash": hash_value,
            }
            headers = {"User-Agent": "Agrashandhani/1.0 (OSINT Tool)"}

            response = self.client.request(
                "GET",
                self.api_url,
                params=params,
                headers=headers,
            )

            if response is None or response == "":
                return self._not_found_response("Hash not found in MalShare")

            if not isinstance(response, dict):
                return self._not_found_response("Hash not found in MalShare")

            if "error" in response or response.get("status") == "error":
                error_msg = response.get("error", response.get("message", "Unknown error"))
                if "not found" in str(error_msg).lower() or "invalid hash" in str(error_msg).lower():
                    return self._not_found_response(str(error_msg))
                return self._error_response(f"MalShare API error: {error_msg}")

            return self._normalize_details(response)

        except Exception as exc:
            logger.exception("[malshare] Unexpected error querying %s", hash_value)
            return self._error_response(f"Unexpected error: {exc}")

    def _normalize_details(self, data: dict) -> dict:
        """Normalise a MalShare details response.

        Args:
            data: Raw API response dict.

        Returns:
            Normalised success response.
        """
        normalized = {
            "hash": data.get("hash"),
            "md5": data.get("md5"),
            "sha1": data.get("sha1"),
            "sha256": data.get("sha256"),
            "type": data.get("type"),
            "source": data.get("source"),
            "first_seen": data.get("first_seen"),
            "last_seen": data.get("last_seen"),
            "tags": data.get("tags", []),
            "analysis": data.get("analysis"),
            "raw_data": data,
        }
        # Remove keys whose value is None to keep the payload clean.
        normalized = {k: v for k, v in normalized.items() if v is not None}
        return self._success_response(normalized)
