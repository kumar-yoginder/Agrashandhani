"""
OSINT Search Engine.

Orchestrates IOC lookups across all configured threat intelligence sources,
manages the local result cache, and persists output to timestamped JSON files.

Author: Agrashandhani
Version: 1.1
"""
import json
import logging
import os
from datetime import datetime

from validators import IOCValidator
from sources import SOURCES, get_available_sources
from database import db_manager

logger = logging.getLogger(__name__)

OUTPUT_DIR = "outputs"


def _ensure_output_dir() -> None:
    """Create the outputs directory if it does not already exist."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def _sanitize_filename(query: str) -> str:
    """Convert an IOC string into a filesystem-safe filename component.

    Replaces any character that is not alphanumeric, a hyphen, underscore, or
    period with an underscore so the result can be safely embedded in a path.

    Args:
        query: Raw IOC string.

    Returns:
        Sanitised string suitable for use in filenames.
    """
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in query)


def _write_output(results: dict) -> str:
    """Persist a query result to a timestamped JSON file.

    Args:
        results: Structured result dict produced by :func:`run_osint_engine`.

    Returns:
        Absolute path of the written output file.
    """
    _ensure_output_dir()
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    safe_query = _sanitize_filename(results.get("query", "unknown"))
    filename = os.path.join(OUTPUT_DIR, f"result_{safe_query}_{timestamp}.json")
    try:
        with open(filename, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        logger.info("Results written to %s", filename)
    except OSError as exc:
        logger.error("Failed to write output file %s: %s", filename, exc)
    return filename


def _is_present(source_result: dict) -> bool:
    """Determine whether a source returned meaningful threat intelligence.

    A result is considered *present* (i.e. the IOC was found) only when the
    query status is ``"ok"`` and no top-level error key exists.  Statuses of
    ``"not_found"`` and ``"error"`` are both treated as absent.

    Args:
        source_result: The normalised response dict from a single source.

    Returns:
        ``True`` if the IOC was found in this source, ``False`` otherwise.
    """
    data = source_result.get("data", {})
    query_status = source_result.get("query_status", "")

    # Explicit error cases
    if query_status in ("error", "not_found"):
        return False
    if "error" in source_result:
        return False
    if isinstance(data, dict) and "error" in data:
        return False

    return query_status == "ok"


def run_osint_engine(query: str, sources: list = None, refresh: bool = False) -> dict:
    """Search for an IOC across configured threat intelligence sources.

    Checks the local cache first (unless *refresh* is ``True``), then queries
    each relevant source, persists the result to the cache and to a JSON output
    file, and returns the structured result.

    Args:
        query: Raw IOC string to look up (hash, IP, domain, URL, CVE, etc.).
        sources: Optional list of source names to restrict the search to.
            Defaults to all sources that support the detected IOC type.
        refresh: When ``True``, bypass the local cache and force fresh API
            queries.

    Returns:
        Dict with keys:
        - ``query`` (str): The original query string.
        - ``ioc_type`` (str): Detected IOC type.
        - ``timestamp`` (str): ISO-8601 timestamp of the search.
        - ``sources`` (dict): Per-source result dicts.
        - ``output_file`` (str, optional): Path to the written JSON file.
        - ``error`` (str, optional): Present only when the IOC type is unknown.
    """
    ioc = IOCValidator.classify(query)

    if ioc["type"] == "unknown":
        logger.warning("Unknown IOC type for query: %s", query)
        return {
            "query": query,
            "timestamp": datetime.now().isoformat(),
            "error": "IOC type not supported",
            "sources": {},
        }

    # Return cached result unless the caller asked for a forced refresh.
    if not refresh and db_manager.exists(query):
        cached_result = db_manager.get(query)
        logger.info(
            "Cache hit for '%s' (cached at %s). Use refresh=True to bypass.",
            query,
            cached_result.get("timestamp", "unknown"),
        )
        return cached_result

    # Resolve the list of sources to query.
    source_names = sources if sources else get_available_sources(ioc["type"])

    results: dict = {
        "query": query,
        "ioc_type": ioc["type"],
        "timestamp": datetime.now().isoformat(),
        "sources": {},
    }

    for source_name in source_names:
        if source_name not in SOURCES:
            results["sources"][source_name] = {
                "present": False,
                "error": f"Source '{source_name}' not found",
            }
            continue

        source = SOURCES[source_name]
        source_result = source.query(ioc["type"], ioc["value"])
        logger.debug("Source %s returned status=%s", source_name, source_result.get("query_status"))

        results["sources"][source_name] = {
            "present": _is_present(source_result),
            "data": source_result,
            "queried_at": datetime.now().isoformat(),
        }

    # Persist to cache and write output file.
    db_manager.set(query, results)
    results["output_file"] = _write_output(results)

    return results


# ---------------------------------------------------------------------------
# Backwards-compatible alias (used by legacy search.py callers)
# ---------------------------------------------------------------------------

def _run_osint_engine(query: str, sources: list = None, refresh: bool = False) -> dict:
    """Backwards-compatible alias for :func:`run_osint_engine`.

    Args:
        query: IOC string to search.
        sources: Optional source list.
        refresh: Bypass cache flag.

    Returns:
        Same as :func:`run_osint_engine`.
    """
    return run_osint_engine(query, sources=sources, refresh=refresh)


def run_osint_search(search_type: str, query: str) -> dict:
    """Backwards-compatible wrapper (``search_type`` is ignored).

    Args:
        search_type: Ignored — auto-detection is always used.
        query: IOC string to search.

    Returns:
        Same as :func:`run_osint_engine`.
    """
    return run_osint_engine(query)
