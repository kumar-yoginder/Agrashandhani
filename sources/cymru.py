"""
Team Cymru Hash/IP Reputation Source.

Queries the Team Cymru REST API for hash and IP reputation data.
Reference: https://hash.cymru.com/docs_rest

Author: Agrashandhani
Version: 1.3

API Details:
- GET Single Hash: GET https://hash.cymru.com/v2/{HASH}
- POST Bulk Hashes: POST https://hash.cymru.com/v2/submitHashes
  (up to 1000 hashes per request, newline/comma-separated)
- Authentication: HTTP Basic Auth (username:password)
- Response includes: md5, sha1, sha256, antivirus_detection_rate, last_run_date
"""
import logging
from typing import Any, Dict, List

from sources.base import Source
from config import CYMRU_API_PASSWORD, CYMRU_API_URL, CYMRU_API_USERNAME

logger = logging.getLogger(__name__)


class CymruSource(Source):
    """Team Cymru Malware Hash Registry (MHR) source for hash reputation.

    Supported IOC types:
    - ``hash_md5`` / ``hash_sha1`` / ``hash_sha256``: Antivirus detection rates, 
      related hash variants, last detection date

    Features:
    - Single hash lookup via GET /v2/{hash}
    - Bulk hash queries via POST /v2/submitHashes (up to 1000 per request)
    - Bulk import from CSV files (auto-chunks into 1000-hash batches)
    - HTTP Basic Auth (username:password)
    - Returns: AV detection rate (0-100%), last_run_date, related hash variants
    - Rate limiting: "too many requests" errors handled with backoff

    Response Structure (Single Hash):
    ```json
    {
      "query_status": "ok",
      "source": "cymru",
      "data": {
        "hash": "...",
        "md5": "...",
        "sha1": "...",
        "sha256": "...",
        "antivirus_detection_rate": 42,
        "last_run_date": "2018-01-04T04:18:39Z",
        "reputation_score": 42
      }
    }
    ```

    Response Structure (Bulk Hashes):
    ```json
    {
      "query_status": "ok",
      "source": "cymru",
      "data": [
        {...hash1 result...},
        {...hash2 result...},
        ...
      ]
    }
    ```

    Attributes:
        api_url: Team Cymru REST API base URL (https://hash.cymru.com/v2)
        username: Cymru API username (HTTP Basic Auth)
        password: Cymru API password (HTTP Basic Auth)
    """

    def __init__(self) -> None:
        super().__init__("cymru")
        self.api_url = CYMRU_API_URL
        self.username = CYMRU_API_USERNAME
        self.password = CYMRU_API_PASSWORD

    def query(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """Query Team Cymru for hash reputation.

        Args:
            ioc_type: IOC classification (``hash_md5``, ``hash_sha1``, ``hash_sha256``)
            value: The hash to look up.

        Returns:
            Normalised response dict with query_status, source, and data.
        """
        if not self.username or not self.password:
            return self._error_response(
                "Cymru credentials not configured",
                "Set CYMRU_API_USERNAME and CYMRU_API_PASSWORD. "
                "Register at https://hash.cymru.com/",
            )

        if ioc_type.startswith("hash_"):
            return self._query_hash(value)

        return self._error_response(
            f"Unsupported IOC type: {ioc_type}",
            "Cymru supports: hash_md5, hash_sha1, hash_sha256",
        )

    def _query_hash(self, hash_value: str) -> Dict[str, Any]:
        """Query Team Cymru for hash reputation.

        Endpoint: GET /v2/{hash}

        Args:
            hash_value: The hash (MD5, SHA1, or SHA256) to query.

        Returns:
            Normalized response with hash reputation data.
        """
        try:
            # Correct endpoint: /v2/{hash} (not /query/{hash})
            url = f"{self.api_url}/{hash_value}"

            headers = {
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Accept": "application/json",
            }

            response = self.client.request(
                "GET",
                url,
                headers=headers,
                auth=(self.username, self.password),
                timeout=self.timeout,
            )

            if response is None:
                return self._error_response(
                    "API request failed",
                    "Connection error or timeout querying Cymru",
                )

            if not isinstance(response, dict):
                return self._error_response(
                    "Unexpected response format",
                    "Cymru returned non-JSON response",
                )

            # Check for API errors
            if response.get("error"):
                error_msg = response.get("error", "Unknown error")
                msg = response.get("msg", "")

                # Handle rate limiting
                if "too many requests" in str(error_msg).lower():
                    return self._error_response(
                        f"Cymru API rate limit: {error_msg}",
                        "Please wait before retrying. " + msg,
                    )

                # Handle invalid hash
                if "invalid hash" in str(error_msg).lower():
                    return self._not_found_response(f"Invalid hash: {error_msg}")

                return self._error_response(
                    f"Cymru API error: {error_msg}",
                    msg,
                )

            # Check if hash was found
            if not self._is_hash_found(response):
                return self._not_found_response("Hash not found in Cymru MHR")

            # Normalize the response
            return self._normalize_response(response)

        except Exception as exc:
            logger.exception("[cymru] Error querying hash %s", hash_value)
            return self._error_response(f"Query failed: {str(exc)}", log=False)

    def query_bulk_from_file(self, csv_file_path: str) -> Dict[str, Any]:
        """Query multiple hashes from a CSV file using shared bulk handler.

        Delegates to sources.query_source_bulk() which handles CSV reading,
        batching, and multi-batch processing.

        CSV file formats supported:
        - Single column with hashes
        - Multi-column CSV with 'hash'/'h'/'value' column
        - First column if no hash column header found

        Args:
            csv_file_path: Path to CSV file containing hashes.

        Returns:
            Response with bulk query results (list of hash results).
        """
        if not self.username or not self.password:
            return self._error_response(
                "Cymru credentials not configured",
                "Set CYMRU_API_USERNAME and CYMRU_API_PASSWORD. "
                "Register at https://hash.cymru.com/",
            )

        # Import here to avoid circular imports
        from sources import query_source_bulk

        return query_source_bulk(
            source_name="cymru",
            csv_file_path=csv_file_path,
            query_func=self._query_bulk_hashes
        )

    def _query_bulk_hashes(self, hashes: List[str]) -> Dict[str, Any]:
        """Query a batch of hashes via POST /v2/submitHashes endpoint.

        Args:
            hashes: List of hashes (max 1000 per request).

        Returns:
            Response with results list.
        """
        try:
            # POST endpoint for bulk hashes
            url = f"{self.api_url}/submitHashes"

            # Prepare request - send hashes newline-separated in request body
            hashes_data = "\n".join(hashes)

            headers = {
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Accept": "application/json",
                "Content-Type": "text/plain",
            }

            response = self.client.request(
                "POST",
                url,
                data=hashes_data,
                headers=headers,
                auth=(self.username, self.password),
                timeout=self.timeout,
            )

            if response is None:
                return self._error_response(
                    "API request failed",
                    "Connection error or timeout querying Cymru bulk endpoint",
                )

            if not isinstance(response, dict):
                return self._error_response(
                    "Unexpected response format",
                    "Cymru bulk endpoint returned non-JSON response",
                )

            # Check for API errors
            if response.get("error"):
                error_msg = response.get("error", "Unknown error")
                msg = response.get("msg", "")

                # Handle rate limiting
                if "too many requests" in str(error_msg).lower():
                    return self._error_response(
                        f"Cymru API rate limit: {error_msg}",
                        "Please wait before retrying. " + msg,
                    )

                return self._error_response(
                    f"Cymru API error: {error_msg}",
                    msg,
                )

            # Response should be a list of hash results
            results = response.get("data", response) if "data" in response else response

            if not isinstance(results, list):
                # Wrap single result or raw response in list
                results = [results] if results else []

            # Normalize each result
            normalized_results = []
            for result in results:
                if isinstance(result, dict):
                    normalized_results.append(self._normalize_result(result))
                else:
                    normalized_results.append(result)

            return self._success_response(normalized_results)

        except Exception as exc:
            logger.exception("[cymru] Error querying bulk hashes")
            return self._error_response(f"Bulk query failed: {str(exc)}", log=False)

    def _normalize_result(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a single hash result (from single or bulk query).

        Args:
            data: Single hash result from Cymru API.

        Returns:
            Normalized data dict with key reputation metrics.
        """
        if not isinstance(data, dict):
            return data

        # Extract reputation data
        normalized = {
            "hash": data.get("hash"),
            "md5": data.get("md5"),
            "sha1": data.get("sha1"),
            "sha256": data.get("sha256"),
            "antivirus_detection_rate": data.get("antivirus_detection_rate"),
            "last_run_date": data.get("last_run_date"),
        }

        # Add reputation_score alias for antivirus_detection_rate (0-100 scale)
        if normalized.get("antivirus_detection_rate") is not None:
            normalized["reputation_score"] = normalized["antivirus_detection_rate"]

        # Filter out None values for cleaner output
        normalized = {k: v for k, v in normalized.items() if v is not None}

        return normalized

    def _is_hash_found(self, response: Dict[str, Any]) -> bool:
        """Determine if a hash was found in Cymru database.

        A hash is considered "found" if any of the hash variants (md5/sha1/sha256)
        are present, OR if antivirus_detection_rate is non-null.

        Args:
            response: API response dict from Cymru.

        Returns:
            True if hash exists in Cymru database, False otherwise.
        """
        # If no error, check for meaningful data
        has_hash_variants = any([
            response.get("md5"),
            response.get("sha1"),
            response.get("sha256"),
        ])

        has_av_detection = response.get("antivirus_detection_rate") is not None

        return has_hash_variants or has_av_detection

    def _normalize_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Cymru API response to standard format.

        Args:
            data: Raw API response from Cymru.

        Returns:
            Normalized response dict with key reputation metrics.
        """
        if not isinstance(data, dict):
            return self._success_response({"raw_data": data})

        # Use shared normalization logic
        normalized = self._normalize_result(data)
        normalized["raw_data"] = data

        return self._success_response(normalized)

    def _success_response(self, data: Any) -> Dict[str, Any]:
        """Create a success response in standard format."""
        return super()._success_response(data)

    def _error_response(self, message: str, details: str = "", *, log: bool = True) -> Dict[str, Any]:
        """Create an error response in standard format."""
        return super()._error_response(message, details, log=log)

    def _not_found_response(self, message: str = "Not found") -> Dict[str, Any]:
        """Create a not-found response in standard format."""
        return super()._not_found_response(message)
