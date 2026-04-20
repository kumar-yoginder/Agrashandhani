"""
HTTP Client with rate limiting and retry logic.

Author: Agrashandhani
Version: 1.1
"""
import logging
import time
import random

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, HTTPError, Timeout
from urllib3.util.retry import Retry

from config import BACKOFF_FACTOR, HTTP_TIMEOUT, MAX_RETRIES

logger = logging.getLogger(__name__)


class RateLimitedClient:
    """HTTP client with automatic retries and exponential back-off for 429s.

    The underlying :class:`requests.adapters.HTTPAdapter` handles retries on
    connection-level errors and on 5xx / 429 responses.  An additional manual
    back-off layer is applied on top for ``429 Too Many Requests`` responses so
    that the caller respects the server's rate limit before the adapter gives
    up entirely.

    Attributes:
        max_retries: Maximum number of retry attempts per request.
        backoff_factor: Multiplier for exponential back-off sleep durations.
        session: The underlying :class:`requests.Session` instance.

    Example::

        client = RateLimitedClient()
        data = client.request("GET", "https://api.example.com/resource")
    """

    def __init__(
        self,
        max_retries: int = MAX_RETRIES,
        backoff_factor: float = BACKOFF_FACTOR,
    ) -> None:
        """Initialise the client and mount the retry adapter.

        Args:
            max_retries: Total retry attempts (connection + status errors).
            backoff_factor: Sleep multiplier between retries.
        """
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.session = requests.Session()

        # The adapter handles retries for connection errors and 5xx/429 codes.
        # We do NOT include 429 in status_forcelist here because we handle it
        # manually below to apply a proper exponential back-off; the adapter's
        # built-in backoff is typically too short for rate-limited APIs.
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def request(self, method: str, url: str, **kwargs) -> dict:
        """Make an HTTP request and return the parsed JSON response.

        Retries on ``429 Too Many Requests`` with exponential back-off.
        All other non-2xx responses raise :class:`requests.HTTPError` which is
        caught and returned as ``{"error": "<message>"}``.

        Args:
            method: HTTP verb (``"GET"``, ``"POST"``, …).
            url: Target URL.
            **kwargs: Forwarded to :meth:`requests.Session.request`.
                A ``timeout`` key defaults to :data:`config.HTTP_TIMEOUT`.

        Returns:
            Parsed JSON dictionary, or ``{"error": "<message>"}`` on failure.

        Raises:
            Nothing — all exceptions are caught and converted to error dicts.
        """
        kwargs.setdefault("timeout", HTTP_TIMEOUT)

        for attempt in range(1, self.max_retries + 2):
            try:
                response = self.session.request(method, url, **kwargs)

                if response.status_code == 429:
                    # Exponential back-off with jitter before retrying.
                    wait_time = (2 ** attempt) + random.uniform(0.5, 1.5)
                    logger.warning(
                        "Rate-limited by %s (attempt %d/%d); sleeping %.1fs",
                        url,
                        attempt,
                        self.max_retries + 1,
                        wait_time,
                    )
                    if attempt <= self.max_retries:
                        time.sleep(wait_time)
                        continue
                    return {"error": "Rate limit exceeded after max retries"}

                response.raise_for_status()
                return response.json()

            except (ConnectionError, Timeout) as exc:
                logger.warning(
                    "Network error on %s (attempt %d/%d): %s",
                    url,
                    attempt,
                    self.max_retries + 1,
                    exc,
                )
                if attempt <= self.max_retries:
                    time.sleep(2 ** attempt)
                    continue
                return {"error": str(exc)}

            except HTTPError as exc:
                logger.error("HTTP error from %s: %s", url, exc)
                return {"error": str(exc)}

            except ValueError as exc:
                # response.json() failed — response was not valid JSON.
                logger.error("Invalid JSON from %s: %s", url, exc)
                return {"error": f"Invalid JSON response: {exc}"}

        return {"error": "Max retries exceeded"}
