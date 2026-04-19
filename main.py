"""
OSINT Search Tool - Main CLI Entry Point.

Provides a command-line interface for querying Indicators of Compromise (IOCs)
across multiple threat intelligence sources.

Author: Agrashandhani
Version: 1.1
"""
import json
import logging
import os
import sys
from datetime import datetime

import argparse

from engine import run_osint_engine
from input_handler import InputHandler
from validators import IOCValidator
from sources import SOURCES

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

_LOG_FILENAME = os.path.join(
    LOG_DIR, f"osint_{datetime.now().strftime('%Y-%m-%d')}.log"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(_LOG_FILENAME, encoding="utf-8"),
    ],
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Output directory
# ---------------------------------------------------------------------------

OUTPUT_DIR = "outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def _write_batch_results(results_list: list) -> str:
    """Persist a batch of IOC results to a timestamped JSON file.

    Args:
        results_list: List of result dicts from :func:`~engine.run_osint_engine`.

    Returns:
        Path of the written file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = os.path.join(OUTPUT_DIR, f"batch_results_{timestamp}.json")
    try:
        with open(filename, "w", encoding="utf-8") as fh:
            json.dump(results_list, fh, indent=2)
        logger.info("Batch results written to %s", filename)
    except OSError as exc:
        logger.error("Failed to write batch results: %s", exc)
    return filename


def main() -> None:
    """Parse CLI arguments and run the OSINT search tool."""
    parser = argparse.ArgumentParser(
        description="OSINT Search Tool — search IOCs across multiple threat intelligence sources"
    )
    parser.add_argument(
        "query",
        type=str,
        nargs="?",
        help="IOC to search (hash, IP, domain, URL, email, CVE, etc.)",
    )
    parser.add_argument(
        "-c", "--csv",
        type=str,
        help="Read IOCs from CSV file (one per line or as first column)",
    )
    parser.add_argument(
        "-t", "--type",
        choices=["hash", "ip", "auto"],
        default="auto",
        help="IOC type (default: auto-detect)",
    )
    parser.add_argument(
        "-s", "--sources",
        type=str,
        help="Comma-separated list of sources to query. Available: " + ", ".join(SOURCES.keys()),
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print detailed results in JSON format",
    )
    parser.add_argument(
        "-l", "--list-sources",
        action="store_true",
        help="List all available sources",
    )
    parser.add_argument(
        "-r", "--refresh",
        action="store_true",
        help="Force search even if found in local database (bypass cache)",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate and classify inputs without searching",
    )

    args = parser.parse_args()

    # --list-sources flag
    if args.list_sources:
        print("Available sources:")
        for name in SOURCES.keys():
            print(f"  - {name}")
        sys.exit(0)

    # Batch mode: read IOCs from CSV
    if args.csv:
        _handle_csv_mode(args)

    elif args.query:
        _handle_single_query_mode(args)

    else:
        parser.print_help()
        sys.exit(1)


def _handle_csv_mode(args: argparse.Namespace) -> None:
    """Process a CSV file containing multiple IOCs.

    Args:
        args: Parsed CLI arguments namespace.
    """
    logger.info("Reading IOCs from: %s", args.csv)
    iocs = InputHandler.read_csv(args.csv)

    if not iocs:
        logger.error("No IOCs found in CSV file: %s", args.csv)
        sys.exit(1)

    logger.info("Found %d IOC(s)", len(iocs))

    validation = InputHandler.validate_inputs(iocs)

    print(f"\n[+] Valid IOCs:   {len(validation['valid'])}")
    print(f"[-] Invalid IOCs: {len(validation['invalid'])}")

    if validation["summary"]:
        print("\n[*] IOC Type Summary:")
        for ioc_type, count in validation["summary"].items():
            print(f"  {ioc_type}: {count}")

    if args.validate_only:
        if validation["invalid"]:
            print("\n[!] Invalid IOCs:")
            for invalid in validation["invalid"]:
                print(f"  - {invalid['value']}: {invalid['reason']}")
        sys.exit(0)

    # Search valid IOCs
    print("\n[*] Starting searches…")
    results_list = []
    for ioc_data in validation["valid"]:
        logger.info("Searching: %s (%s)", ioc_data["value"], ioc_data["type"])
        result = run_osint_engine(ioc_data["value"], refresh=args.refresh)
        results_list.append(result)

    # Write batch output file
    output_file = _write_batch_results(results_list)
    print(f"\n[+] Results saved to: {output_file}")

    if args.verbose:
        print(json.dumps(results_list, indent=2))
    else:
        for result in results_list:
            print(f"\nIOC: {result['query']} ({result.get('ioc_type', 'unknown')})")
            for source_name, source_result in result.get("sources", {}).items():
                status = "✓" if source_result.get("present") else "✗"
                print(f"  {status} {source_name}")


def _handle_single_query_mode(args: argparse.Namespace) -> None:
    """Process a single IOC query from the CLI.

    Args:
        args: Parsed CLI arguments namespace.
    """
    logger.info("Validating input: %s", args.query)
    classification = IOCValidator.classify(args.query)

    if classification["type"] == "unknown":
        logger.error("Could not classify IOC type for input: %s", args.query)
        sys.exit(1)

    print(f"[+] Classification: {classification['description']} ({classification['type']})")

    if args.validate_only:
        sys.exit(0)

    # Resolve and validate requested sources
    source_names = None
    if args.sources:
        source_names = [s.strip() for s in args.sources.split(",")]
        for source in source_names:
            if source not in SOURCES:
                logger.error("Unknown source '%s'. Available: %s", source, ", ".join(SOURCES.keys()))
                sys.exit(1)

    output = run_osint_engine(args.query, sources=source_names, refresh=args.refresh)

    if args.verbose:
        print(json.dumps(output, indent=2))
    else:
        print(f"\nQuery:    {output['query']}")
        print(f"IOC Type: {output.get('ioc_type', 'unknown')}")
        if output.get("output_file"):
            print(f"Saved to: {output['output_file']}")
        print("\nResults:")
        for source_name, result in output.get("sources", {}).items():
            status = "✓ Present" if result.get("present") else "✗ Not found"
            print(f"  {source_name}: {status}")


if __name__ == "__main__":
    main()
