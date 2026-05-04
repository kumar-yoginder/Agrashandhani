"""
OSINT Search Tool - Main CLI Entry Point.

Provides a command-line interface for querying Indicators of Compromise (IOCs)
across multiple threat intelligence sources. Supports single queries, batch
processing from CSV files, and correlated indicator discovery via OTX.

Usage:
  python main.py <ioc>                 - Search for a single IOC
  python main.py -c file.csv           - Search for multiple IOCs from CSV
  python main.py <ioc> --related       - Find related indicators via OTX
  python main.py -c file.csv --cymru-bulk  - Bulk Cymru hash search
  python main.py <ioc> --sources       - Interactive source selection
  python main.py <ioc> --ioc-types hash_md5  - Filter by IOC type

Author: Agrashandhani
Version: 1.2
"""
import argparse
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional

from engine import run_osint_engine
from input_handler import read_csv, validate_inputs
from validators import classify
from sources import SOURCES
from utility.excel_exporter import export_to_excel
from config import IOC_TYPES

# =====================================================
# Configuration
# =====================================================

LOG_DIR = "logs"
OUTPUT_DIR = "outputs"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# =====================================================
# Logging Setup
# =====================================================

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

# =====================================================
# Banner and UI
# =====================================================


def print_banner() -> None:
    """Display a stylized banner for the OSINT Search Tool."""
    banner = r"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                   AGRASHANDHANI OSINT TOOL                   ║
    ║              Threat Intelligence Aggregator v1.2             ║
    ║                                                              ║
    ║  Query Multiple Threat Intelligence Sources for IOCs         ║
    ║  Supports: Hashes, IPs, Domains, URLs, CVEs, and more        ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_available_sources() -> None:
    """Display available threat intelligence sources."""
    if not SOURCES:
        print("[-] No sources configured. Please add API keys to .env")
        return
    
    print("\n[*] Available Threat Intelligence Sources:")
    print("    " + "-" * 56)
    for idx, source_name in enumerate(sorted(SOURCES.keys()), 1):
        print(f"    {idx:2d}. {source_name:<15} - {_get_source_description(source_name)}")
    print("    " + "-" * 56)


def _get_source_description(source_name: str) -> str:
    """Return a brief description of a threat intelligence source."""
    descriptions = {
        "virustotal": "Multi-hash/IP/Domain scanner (VirusTotal)",
        "malwarebazaar": "Malware sample repository (ABUSE.ch)",
        "hybrid_analysis": "Dynamic malware analysis platform",
        "malshare": "Malware sample sharing platform",
        "otx": "Pulses & threat intelligence correlation",
        "cymru": "IP-to-ASN mapping & hash reputation",
        "anyrun": "Interactive malware sandbox",
        "securitytrails": "Domain/IP/DNS intelligence",
        "shodan": "IoT device search engine",
        "greynoise": "Internet scan data & IP context",
        "xforce_ibm": "IBM X-Force threat intelligence",
        "filescan": "File analysis & hashing service",
        "threatfox": "Malware/phishing IOC sharing",
    }
    return descriptions.get(source_name, "Threat Intelligence Source")


def print_available_ioc_types() -> None:
    """Display available IOC types for filtering."""
    print("\n[*] Available IOC Types for Filtering:")
    print("    " + "-" * 50)
    for ioc_key, ioc_desc in IOC_TYPES.items():
        if ioc_key != "unknown":
            print(f"    • {ioc_key:<20} - {ioc_desc}")
    print("    " + "-" * 50)


def interactive_source_selection() -> List[str]:
    """Allow user to interactively select one or more sources.
    
    Returns:
        List of selected source names.
    """
    if not SOURCES:
        print("[-] No sources configured. Please add API keys to .env")
        sys.exit(1)
    
    print_available_sources()
    
    selected = []
    while True:
        try:
            user_input = input(
                "\n[?] Select source(s) by number (comma-separated) or 'a' for all, or 'q' to quit: "
            ).strip()
            
            if user_input.lower() == 'q':
                if not selected:
                    print("[-] No sources selected. Exiting.")
                    sys.exit(0)
                break
            
            if user_input.lower() == 'a':
                selected = list(SOURCES.keys())
                print(f"[+] Selected all {len(selected)} sources")
                break
            
            # Parse comma-separated indices
            indices = [int(x.strip()) for x in user_input.split(",")]
            source_list = sorted(SOURCES.keys())
            
            for idx in indices:
                if 1 <= idx <= len(source_list):
                    selected.append(source_list[idx - 1])
                else:
                    print(f"[-] Invalid selection: {idx}")
                    continue
            
            if selected:
                print(f"[+] Selected sources: {', '.join(selected)}")
                break
            
        except (ValueError, IndexError):
            print("[-] Invalid input. Please enter numbers separated by commas (e.g., 1,3,5)")
    
    return list(dict.fromkeys(selected))  # Remove duplicates while preserving order

# =====================================================
# Utility Functions
# =====================================================



def _sanitize_filename(query: str) -> str:
    """Convert an IOC string into a filesystem-safe filename component.

    Replaces any character that is not alphanumeric, hyphen, underscore, or
    period with an underscore.

    Args:
        query: Raw IOC string.

    Returns:
        Sanitized string suitable for use in filenames.
    """
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in query)


def _write_batch_results(results_list: List[Dict[str, Any]]) -> str:
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

# =====================================================
# CLI Command Handlers
# =====================================================


def main() -> None:
    """Parse CLI arguments and run the OSINT search tool."""
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="OSINT Search Tool - Query IOCs across multiple threat intelligence sources.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single IOC search:
    python main.py 8.8.8.8
    python main.py <hash>
    
  Select specific sources:
    python main.py 8.8.8.8 --sources virustotal,shodan
    python main.py 8.8.8.8 --sources  # Interactive selection
    
  Filter by IOC type:
    python main.py <value> --ioc-types hash_md5,hash_sha256
    python main.py <value> --ioc-types ip_v4
    
  Batch processing:
    python main.py -c file.csv
    python main.py -c file.csv --skip-validation  # Skip validation
    python main.py -c file.csv --ioc-types hash_md5  # Filter types
    
  Related indicators:
    python main.py <hash> --related
    
  List sources:
    python main.py --list-sources
        """
    )
    
    # Positional argument
    parser.add_argument(
        "query",
        type=str,
        nargs="?",
        help="IOC to search (hash, IP, domain, URL, email, CVE, etc.)",
    )
    
    # Input options
    parser.add_argument(
        "-c", "--csv",
        type=str,
        help="Read IOCs from CSV file (one per line or as first column)",
    )
    
    # IOC Type options
    parser.add_argument(
        "-t", "--ioc-types",
        type=str,
        help="Comma-separated IOC types to search for (e.g., hash_md5,ip_v4). "
             "Use --list-ioc-types to see all available types",
    )
    
    # Source options
    parser.add_argument(
        "-s", "--sources",
        type=str,
        nargs="?",
        const="",
        help="Comma-separated sources (e.g., virustotal,shodan) or leave blank for interactive selection. "
             "Use --list-sources to see all available sources",
    )
    
    # Output and format options
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print detailed results in JSON format",
    )
    
    parser.add_argument(
        "--output-excel",
        type=str,
        help="Save results to Excel file (e.g., results.xlsx)",
    )
    
    parser.add_argument(
        "--update-excel",
        action="store_true",
        help="Update an existing Excel file with new data (requires --output-excel)",
    )
    
    # Search options
    parser.add_argument(
        "--related",
        action="store_true",
        help="Find correlated/related indicators from OTX",
    )
    
    parser.add_argument(
        "-r", "--refresh",
        action="store_true",
        help="Force fresh search, bypass local database cache",
    )
    
    # Validation and special modes
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate and classify inputs without searching",
    )
    
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip IOC validation and type classification (use with caution)",
    )
    
    parser.add_argument(
        "--cymru-bulk",
        action="store_true",
        help="Use Cymru bulk hash search API (requires --csv with hash file)",
    )
    
    # Informational options
    parser.add_argument(
        "-l", "--list-sources",
        action="store_true",
        help="List all available threat intelligence sources",
    )
    
    parser.add_argument(
        "--list-ioc-types",
        action="store_true",
        help="List all available IOC types for filtering",
    )

    args = parser.parse_args()

    # Handle informational flags
    if args.list_sources:
        print_available_sources()
        sys.exit(0)
    
    if args.list_ioc_types:
        print_available_ioc_types()
        sys.exit(0)

    # Process --output-excel argument: add .xlsx extension if not present
    if args.output_excel and not args.output_excel.lower().endswith(".xlsx"):
        args.output_excel += ".xlsx"

    # Bulk mode: Cymru bulk hash search from CSV
    if args.csv and args.cymru_bulk:
        _handle_cymru_bulk_mode(args)

    # Batch mode: read IOCs from CSV
    elif args.csv:
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
    iocs = read_csv(args.csv)

    if not iocs:
        logger.error("No IOCs found in CSV file: %s", args.csv)
        sys.exit(1)

    logger.info("Found %d IOC(s)", len(iocs))

    # Handle validation
    if args.skip_validation:
        print("\n[!] Validation skipped (--skip-validation enabled)")
        validation = {"valid": [{"value": ioc, "type": "unknown"} for ioc in iocs], "invalid": [], "summary": {}}
    else:
        validation = validate_inputs(iocs)

        print(f"\n[+] Valid IOCs:   {len(validation['valid'])}")
        print(f"[-] Invalid IOCs: {len(validation['invalid'])}")

        if validation["summary"]:
            print("\n[*] IOC Type Summary:")
            for ioc_type, count in validation["summary"].items():
                print(f"  {ioc_type}: {count}")

    if args.validate_only:
        if not args.skip_validation and validation["invalid"]:
            print("\n[!] Invalid IOCs:")
            for invalid in validation["invalid"]:
                print(f"  - {invalid['value']}: {invalid['reason']}")
        sys.exit(0)

    # Filter IOCs by type if specified
    filtered_iocs = validation["valid"]
    if args.ioc_types:
        ioc_type_list = [t.strip() for t in args.ioc_types.split(",")]
        print(f"\n[*] Filtering by IOC types: {', '.join(ioc_type_list)}")
        filtered_iocs = [ioc for ioc in validation["valid"] if ioc.get("type") in ioc_type_list]
        print(f"[+] IOCs after filtering: {len(filtered_iocs)}")

    if not filtered_iocs:
        print("[-] No IOCs match the specified criteria")
        sys.exit(0)

    # Search valid IOCs in parallel (batch mode enabled)
    print("\n[*] Starting parallel searches…")
    results_list = []
    for ioc_data in filtered_iocs:
        logger.info("Searching: %s (%s)", ioc_data["value"], ioc_data.get("type", "unknown"))
        result = run_osint_engine(ioc_data["value"], refresh=args.refresh, batch_mode=True)
        results_list.append(result)

    # Write batch output file (single consolidated file for all IOCs)
    output_file = _write_batch_results(results_list)
    print(f"\n[+] Results saved to: {output_file}")

    if args.output_excel:
        excel_output_path = export_to_excel(results_list, args.output_excel, args.update_excel)
        if excel_output_path:
            print(f"[+] Excel results saved to: {excel_output_path}")

    if args.verbose:
        print(json.dumps(results_list, indent=2))
    else:
        for result in results_list:
            print(f"\nIOC: {result['query']} ({result.get('ioc_type', 'unknown')})")
            for source_name, source_result in result.get("sources", {}).items():
                status = "✓" if source_result.get("present") else "✗"
                print(f"  {status} {source_name}")



def _handle_cymru_bulk_mode(args: argparse.Namespace) -> None:
    """Process CSV file with Cymru bulk hash search API.

    Uses Cymru's optimized bulk endpoint (POST /v2/submitHashes) for efficient
    hash reputation lookups when processing multiple hashes from a CSV file.

    Args:
        args: Parsed CLI arguments namespace (must have args.csv set).
    """
    if "cymru" not in SOURCES:
        print("[-] Cymru source not available. Ensure CYMRU_API_USERNAME and CYMRU_API_PASSWORD are configured.")
        sys.exit(1)

    logger.info("Using Cymru bulk API for hash reputation lookup: %s", args.csv)
    print(f"[*] Using Cymru bulk hash search API...")
    print(f"[*] CSV file: {args.csv}")

    cymru_source = SOURCES["cymru"]

    # Call Cymru's bulk query directly from CSV file
    # This handles CSV parsing, batching (1000 hashes per batch), and API calls
    result = cymru_source.query_bulk_from_file(args.csv)

    # Check result status
    if result.get("query_status") != "ok":
        error = result.get("error", "Unknown error")
        details = result.get("details", "")
        print(f"[-] Cymru bulk query failed: {error}")
        if details:
            print(f"    {details}")
        sys.exit(1)

    # Extract results
    results_data = result.get("data", [])
    print(f"\n[+] Query completed. Retrieved {len(results_data)} hash results.")

    # Write results to file
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = os.path.join(OUTPUT_DIR, f"cymru_bulk_{timestamp}.json")
    try:
        with open(filename, "w", encoding="utf-8") as fh:
            json.dump({
                "source": "cymru",
                "method": "bulk_hash_api",
                "timestamp": timestamp,
                "total_results": len(results_data),
                "results": results_data
            }, fh, indent=2)
        logger.info("Cymru bulk results written to %s", filename)
        print(f"[+] Results saved to: {filename}")
    except OSError as exc:
        logger.error("Failed to write results: %s", exc)
        sys.exit(1)

    # Display results
    if args.verbose:
        print(json.dumps(results_data, indent=2))
    else:
        # Summary view
        print("\n[*] Hash Results Summary:")
        detected = 0
        for hash_result in results_data:
            if isinstance(hash_result, dict):
                av_rate = hash_result.get("antivirus_detection_rate")
                hash_val = hash_result.get("hash") or hash_result.get("md5") or hash_result.get("sha1") or hash_result.get("sha256") or "unknown"
                if av_rate is not None:
                    detected += 1
                    print(f"  ✓ {hash_val[:16]}... | AV Detection: {av_rate}%")
                else:
                    print(f"  ✗ {hash_val[:16]}... | Not found in Cymru")
        print(f"\n[*] Detected in AV engines: {detected}/{len(results_data)}")


def _handle_related_search(query: str, ioc_type: str, refresh: bool = False, verbose: bool = False) -> None:
    """Search for correlated/related indicators from OTX.

    Args:
        query: The original IOC to find correlations for.
        ioc_type: Type of the original IOC.
        refresh: Bypass cache flag.
        verbose: Print full JSON output.
    """
    logger.info("Searching for correlated indicators for: %s (%s)", query, ioc_type)
    
    # Query OTX specifically to get related data
    if "otx" not in SOURCES:
        print("[-] OTX source not available. Cannot search for correlated indicators.")
        sys.exit(1)
    
    otx_source = SOURCES["otx"]
    
    # Map IOC type for OTX
    otx_type_map = {
        "hash_md5": "hash_md5",
        "hash_sha1": "hash_sha1",
        "hash_sha256": "hash_sha256",
        "ip_v4": "ip_v4",
        "ip_v6": "ip_v6",
        "domain": "domain",
        "url": "url",
    }
    
    otx_ioc_type = otx_type_map.get(ioc_type)
    if not otx_ioc_type:
        print(f"[-] Correlated search not supported for IOC type: {ioc_type}")
        sys.exit(1)
    
    # Query OTX to get related indicators
    otx_response = otx_source.query(otx_ioc_type, query)
    
    if otx_response.get("query_status") != "ok":
        print(f"[-] OTX query failed: {otx_response.get('data', {}).get('error', 'Unknown error')}")
        logger.error("OTX query failed: %s", otx_response)
        sys.exit(1)
    
    otx_data = otx_response.get("data", {})
    correlated_hashes = otx_data.get("correlated_hashes", {}).get("related_files", [])
    
    if not correlated_hashes:
        print(f"[*] No correlated indicators found for: {query}")
        return
    
    print(f"\n[+] Found {len(correlated_hashes)} correlated indicator(s) for: {query}")
    print(f"[*] Malware Family: {otx_data.get('malware_family', {}).get('names', [])}")
    print(f"[*] APT Groups: {otx_data.get('apt_groups', {}).get('attributed', [])}\n")
    
    # Search for each correlated hash
    print("[*] Searching for correlated indicators across sources...\n")
    related_results = []
    
    for idx, related_ioc in enumerate(correlated_hashes[:10], 1):  # Limit to first 10
        print(f"[{idx}/{min(10, len(correlated_hashes))}] Searching: {related_ioc[:16]}...")
        related_output = run_osint_engine(related_ioc, refresh=refresh, batch_mode=True)
        related_results.append(related_output)
    
    # Display results
    if verbose:
        print("\n=== DETAILED RESULTS ===\n")
        print(json.dumps({
            "original_query": query,
            "original_type": ioc_type,
            "correlated_count": len(correlated_hashes),
            "search_results": related_results
        }, indent=2))
    else:
        print("\n=== CORRELATED INDICATORS SUMMARY ===\n")
        print(f"Original: {query}")
        print(f"Type:     {ioc_type}")
        print(f"Found:    {len(correlated_hashes)} related indicator(s)\n")
        
        for result in related_results:
            query_short = result['query'][:20] + "..." if len(result['query']) > 20 else result['query']
            print(f"  ├─ {query_short}")
            for source_name, source_result in result.get("sources", {}).items():
                status = "✓" if source_result.get("present") else "✗"
                print(f"  │  {status} {source_name}")
    
    # Save results to file
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file = os.path.join(OUTPUT_DIR, f"correlated_{_sanitize_filename(query)}_{timestamp}.json")
    try:
        with open(output_file, "w", encoding="utf-8") as fh:
            json.dump({
                "original_query": query,
                "original_type": ioc_type,
                "correlated_count": len(correlated_hashes),
                "correlated_indicators": correlated_hashes[:10],
                "search_results": related_results
            }, fh, indent=2)
        print(f"\n[+] Correlated search results saved to: {output_file}")
    except OSError as exc:
        logger.error("Failed to write correlated results: %s", exc)


def _handle_single_query_mode(args: argparse.Namespace) -> None:
    """Process a single IOC query from the CLI.

    Args:
        args: Parsed CLI arguments namespace.
    """
    if not args.skip_validation:
        logger.info("Validating input: %s", args.query)
        classification = classify(args.query)

        if classification["type"] == "unknown":
            logger.error("Could not classify IOC type for input: %s", args.query)
            sys.exit(1)

        print(f"\n[+] Classification: {classification['description']} ({classification['type']})")
    else:
        print(f"\n[!] Validation skipped (--skip-validation enabled)")
        classification = {"type": "unknown", "description": "Unknown (validation disabled)"}

    if args.validate_only:
        sys.exit(0)

    # Handle related/correlated search
    if args.related:
        _handle_related_search(
            args.query,
            classification["type"],
            refresh=args.refresh,
            verbose=args.verbose
        )
        return

    # Check if IOC type matches requested types
    if args.ioc_types and classification["type"] != "unknown":
        ioc_type_list = [t.strip() for t in args.ioc_types.split(",")]
        if classification["type"] not in ioc_type_list:
            print(f"\n[-] IOC type '{classification['type']}' does not match requested types: {', '.join(ioc_type_list)}")
            sys.exit(1)

    # Resolve and validate requested sources
    source_names = None
    
    if args.sources is not None:
        if args.sources == "":
            # Interactive mode
            print("\n[*] Starting interactive source selection...")
            source_names = interactive_source_selection()
        else:
            # Parse comma-separated sources
            source_names = [s.strip() for s in args.sources.split(",")]
            for source in source_names:
                if source not in SOURCES:
                    logger.error("Unknown source '%s'. Available: %s", source, ", ".join(SOURCES.keys()))
                    print(f"[-] Unknown source: {source}")
                    print(f"[*] Use --list-sources to see available sources")
                    sys.exit(1)

    output = run_osint_engine(args.query, sources=source_names, refresh=args.refresh)

    if args.verbose:
        print(json.dumps(output, indent=2))
    else:
        print(f"\nQuery:    {output['query']}")
        print(f"IOC Type: {output.get('ioc_type', 'unknown')}")
        if output.get("output_file"):
            print(f"Saved to: {output['output_file']}")
        print("\n[*] Results:")
        for source_name, result in output.get("sources", {}).items():
            status = "✓ Present" if result.get("present") else "✗ Not found"
            print(f"  {source_name}: {status}")

    if args.output_excel:
        excel_output_path = export_to_excel([output], args.output_excel, args.update_excel)
        if excel_output_path:
            print(f"[+] Excel results saved to: {excel_output_path}")


if __name__ == "__main__":
    main()
