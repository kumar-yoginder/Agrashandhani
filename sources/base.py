"""
Abstract base class for all threat intelligence sources.

Author: Agrashandhani
Version: 1.1
"""
import logging
from abc import ABC, abstractmethod
from typing import Any

from clients import RateLimitedClient

logger = logging.getLogger(__name__)


class Source(ABC):
    """Abstract base for every threat intelligence source.

    Each concrete subclass must implement :meth:`query`.  Common helpers for
    building standardised response dictionaries are provided here so they do
    not need to be duplicated across every source.

    Attributes:
        name: Human-readable source identifier (e.g. ``"virustotal"``).
        client: Shared :class:`~clients.RateLimitedClient` instance used for
            all HTTP calls made by this source.

    Example::

        class MySource(Source):
            def __init__(self):
                super().__init__("mysource")

            def query(self, ioc_type, value):
                response = self.client.request("GET", "https://...")
                return self._success_response(response)
    """

    def __init__(self, name: str) -> None:
        """Initialise the source with a name and a shared HTTP client.

        Args:
            name: Unique identifier for this source (lower-snake-case).
        """
        self.name = name
        self.client = RateLimitedClient()

    @abstractmethod
    def query(self, ioc_type: str, value: str) -> dict:
        """Query the source for the given IOC.

        Args:
            ioc_type: Classified IOC type string (e.g. ``"hash_sha256"``,
                ``"ip_v4"``, ``"domain"``).
            value: The actual IOC value to look up.

        Returns:
            A normalised response dictionary produced by
            :meth:`_success_response`, :meth:`_not_found_response`, or
            :meth:`_error_response`.
        """

    # ------------------------------------------------------------------
    # Shared response factory helpers
    # ------------------------------------------------------------------

    def _success_response(self, data: Any) -> dict:
        """Build a standardised success response.

        Args:
            data: Parsed payload returned by the API.

        Returns:
            Dict with ``query_status="ok"``, ``source``, and ``data`` keys.
        """
        return {
            "query_status": "ok",
            "source": self.name,
            "data": data,
        }

    def _not_found_response(self, message: str = "Not found") -> dict:
        """Build a standardised not-found response.

        Args:
            message: Human-readable explanation (e.g. ``"Hash not found"``).

        Returns:
            Dict with ``query_status="not_found"``, ``source``, and ``data``
            keys containing an empty list.
        """
        return {
            "query_status": "not_found",
            "source": self.name,
            "data": [],
            "message": message,
        }

    def _error_response(self, message: str, details: str = "") -> dict:
        """Build a standardised error response.

        Args:
            message: Short description of the error.
            details: Optional longer explanation or remediation hint.

        Returns:
            Dict with ``query_status="error"``, ``source``, and ``data``
            keys containing the error and details.
        """
        logger.error("[%s] %s — %s", self.name, message, details)
        return {
            "query_status": "error",
            "source": self.name,
            "data": {
                "error": message,
                "details": details,
            },
        }
