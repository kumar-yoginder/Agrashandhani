"""
OSINT Search Tool - Main CLI Entry Point
"""
import json
import argparse
from engine import _run_osint_engine
from input_handler import InputHandler
from validators import IOCValidator
from sources import SOURCES


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="OSINT Search Tool - Search IOCs across multiple threat intelligence sources"
    )
    parser.add_argument(
        "query",
        type=str,
        nargs="?",
        help="IOC to search (hash, IP, domain, URL, email, CVE, etc.)"
    )
    parser.add_argument(
        "-c", "--csv",
        type=str,
        help="Read IOCs from CSV file (one per line or as first column)"
    )
    parser.add_argument(
        "-t", "--type",
        choices=["hash", "ip", "auto"],
        default="auto",
        help="IOC type (default: auto-detect)"
    )
    parser.add_argument(
        "-s", "--sources",
        type=str,
        help="Comma-separated list of sources to query. Available: " + ", ".join(SOURCES.keys())
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print detailed results in JSON format"
    )
    parser.add_argument(
        "-l", "--list-sources",
        action="store_true",
        help="List all available sources"
    )
    parser.add_argument(
        "-r", "--refresh",
        action="store_true",
        help="Force search even if found in local database (bypass cache)"
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate and classify inputs without searching"
    )
    
    args = parser.parse_args()
    
    # Handle --list-sources flag
    if args.list_sources:
        print("Available sources:")
        for name in SOURCES.keys():
            print(f"  - {name}")
        exit(0)
    
    # Process inputs (CSV or CLI)
    if args.csv:
        print(f"[*] Reading IOCs from: {args.csv}")
        iocs = InputHandler.read_csv(args.csv)
        
        if not iocs:
            print("Error: No IOCs found in CSV file")
            exit(1)
        
        print(f"[*] Found {len(iocs)} IOC(s)")
        
        # Validate inputs
        validation = InputHandler.validate_inputs(iocs)
        
        print(f"\n[+] Valid IOCs: {len(validation['valid'])}")
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
            exit(0)
        
        # Search valid IOCs
        print("\n[*] Starting searches...")
        results_list = []
        for ioc_data in validation["valid"]:
            print(f"[>] Searching: {ioc_data['value']} ({ioc_data['type']})")
            result = _run_osint_engine(ioc_data["value"], refresh=args.refresh)
            results_list.append(result)
        
        # Output results
        if args.verbose:
            print(json.dumps(results_list, indent=2))
        else:
            for result in results_list:
                print(f"\nIOC: {result['query']} ({result.get('ioc_type', 'unknown')})")
                for source_name, source_result in result.get("sources", {}).items():
                    status = "✓" if source_result.get("present") else "✗"
                    print(f"  {status} {source_name}")
    
    elif args.query:
        # Single query mode
        print(f"[*] Validating input: {args.query}")
        classification = IOCValidator.classify(args.query)
        
        if classification["type"] == "unknown":
            print(f"[!] Error: Could not classify IOC type")
            print(f"    Input: {args.query}")
            exit(1)
        
        print(f"[+] Classification: {classification['description']} ({classification['type']})")
        
        if args.validate_only:
            exit(0)
        
        # Parse source list
        sources = None
        if args.sources:
            sources = [s.strip() for s in args.sources.split(",")]
            # Validate sources
            for source in sources:
                if source not in SOURCES:
                    print(f"Error: Unknown source '{source}'")
                    print(f"Available sources: {', '.join(SOURCES.keys())}")
                    exit(1)
        
        # Run search
        output = _run_osint_engine(args.query, sources=sources, refresh=args.refresh)
        
        if args.verbose:
            print(json.dumps(output, indent=2))
        else:
            print(f"\nQuery: {output['query']}")
            print(f"IOC Type: {output.get('ioc_type', 'unknown')}")
            print("\nResults:")
            for source_name, result in output.get("sources", {}).items():
                status = "✓ Present" if result.get("present") else "✗ Not found"
                print(f"  {source_name}: {status}")
    
    else:
        parser.print_help()
        exit(1)


if __name__ == "__main__":
    main()
