"""
Input Handler for CLI and CSV inputs.

Provides functions for reading IOC values from CSV files and validating
raw IOC input strings against known patterns.

Author: Agrashandhani
Version: 1.1
"""
import csv
import logging
from typing import List, Dict

from validators import classify

logger = logging.getLogger(__name__)

# =====================================================
# CSV Input Handler
# =====================================================


def read_csv(filepath: str) -> List[str]:
    """Read IOC values from a CSV file.

    The first column of each non-empty row is treated as the IOC. A header row
    is automatically skipped when the first line contains common header keywords
    (ioc, query, indicator, hash, ip, domain).

    Args:
        filepath: Path to the CSV file.

    Returns:
        List of raw IOC strings, or an empty list on error.
    """
    iocs = []
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            # Peek at the first line to detect a header row.
            sample = fh.readline()
            fh.seek(0)

            is_header = any(
                keyword in sample.lower()
                for keyword in ("ioc", "query", "indicator", "hash", "ip", "domain")
            )

            reader = csv.reader(fh)
            if is_header:
                next(reader)  # Skip header row

            for row in reader:
                if row and row[0].strip():
                    iocs.append(row[0].strip())

    except FileNotFoundError:
        logger.error("CSV file not found: %s", filepath)
    except PermissionError:
        logger.error("Permission denied reading CSV file: %s", filepath)
    except csv.Error as exc:
        logger.error("CSV parse error in %s: %s", filepath, exc)
    except OSError as exc:
        logger.error("I/O error reading CSV file %s: %s", filepath, exc)

    return iocs

# =====================================================
# Input Validation
# =====================================================


def validate_inputs(iocs: List[str]) -> Dict:
    """Validate and classify a list of raw IOC strings.

    Args:
        iocs: List of raw IOC strings (e.g., from :func:`read_csv`).

    Returns:
        Dict with keys:
        - ``valid`` (list): Classification dicts from :func:`~validators.classify`
          for each recognized IOC.
        - ``invalid`` (list): Dicts with ``value`` and ``reason`` for each
          unrecognized IOC.
        - ``summary`` (dict): Mapping of IOC type to count.

    Example:
        >>> result = validate_inputs(["192.168.1.1", "invalid"])
        >>> result["valid"]
        [{'type': 'ip_v4', 'value': '192.168.1.1', 'description': 'IPv4 Address'}]
        >>> result["summary"]
        {'ip_v4': 1}
    """
    results: Dict = {
        "valid": [],
        "invalid": [],
        "summary": {},
    }

    for ioc in iocs:
        if not ioc.strip():
            continue

        classification = classify(ioc)

        if classification["type"] != "unknown":
            results["valid"].append(classification)
            ioc_type = classification["type"]
            results["summary"][ioc_type] = results["summary"].get(ioc_type, 0) + 1
        else:
            results["invalid"].append(
                {"value": ioc, "reason": "Could not classify IOC type"}
            )

    return results
