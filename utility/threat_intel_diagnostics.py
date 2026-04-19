#!/usr/bin/env python3
"""
Threat Intelligence Diagnostics Tool

Analyzes threat_intel_db.json to identify:
- Authentication/authorization failures (401, 403)
- Missing API credentials
- Network/timeout issues
- Data not found errors (expected)
- Rate limiting issues

Provides recommendations for disabling sources with missing credentials.
"""

import json
import sys
from typing import Dict, List, Tuple, Any
from collections import defaultdict
from datetime import datetime


# Error categories
ERROR_CATEGORIES = {
    "401": "Unauthorized - Missing or Invalid API Key/Credentials",
    "403": "Forbidden - Invalid API Key or Insufficient Permissions",
    "404": "Not Found - Data Not Available or Wrong Endpoint",
    "429": "Rate Limited - Too Many Requests",
    "timeout": "Timeout - API Unresponsive or Network Issue",
    "connection": "Connection Error - Network or Infrastructure Issue"
}

# Priority for disabling (which sources should be disabled)
SHOULD_DISABLE_CODES = ["401", "403"]  # Authentication failures
INVESTIGATE_CODES = ["timeout", "connection"]  # Might need retry logic
EXPECTED_CODES = ["404", "429"]  # Normal/expected errors


def load_threat_db(filename: str = "data/threat_intel_db.json") -> Dict[str, Any]:
    """Load threat intelligence database"""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ File not found: {filename}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON: {e}")
        sys.exit(1)


def categorize_error(error_msg: str) -> str:
    """Categorize error message to error code"""
    error_lower = error_msg.lower()
    
    if "401" in error_msg:
        return "401"
    elif "403" in error_msg:
        return "403"
    elif "404" in error_msg:
        return "404"
    elif "429" in error_msg or "too many" in error_lower:
        return "429"
    elif "timeout" in error_lower or "timed out" in error_lower:
        return "timeout"
    elif "connection" in error_lower or "pool" in error_lower:
        return "connection"
    else:
        return "unknown"


def analyze_threat_db(threat_db: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze threat database for error patterns"""
    
    analysis = {
        "total_queries": len(threat_db),
        "sources_queried": set(),
        "error_summary": defaultdict(lambda: defaultdict(int)),  # source -> error_code -> count
        "source_failures": defaultdict(list),  # source -> list of error details
        "sources_to_disable": [],
        "sources_to_investigate": [],
        "healthy_sources": []
    }
    
    # Analyze each query result
    for ioc, query_data in threat_db.items():
        for source_name, source_result in query_data.get("sources", {}).items():
            analysis["sources_queried"].add(source_name)
            
            # Check for errors in data field (nested structure)
            data_field = source_result.get("data", {})
            
            # First check if there's a direct error field
            if "error" in data_field:
                error_msg = data_field["error"]
                error_code = categorize_error(error_msg)
                
                analysis["error_summary"][source_name][error_code] += 1
                analysis["source_failures"][source_name].append({
                    "ioc": ioc,
                    "error": error_msg,
                    "code": error_code,
                    "timestamp": source_result.get("queried_at", "unknown")
                })
            
            # Also check for nested data structure with error field
            elif isinstance(data_field, dict) and "data" in data_field:
                nested_data = data_field["data"]
                if "error" in nested_data:
                    error_msg = nested_data["error"]
                    error_code = categorize_error(error_msg)
                    
                    analysis["error_summary"][source_name][error_code] += 1
                    analysis["source_failures"][source_name].append({
                        "ioc": ioc,
                        "error": error_msg,
                        "code": error_code,
                        "timestamp": source_result.get("queried_at", "unknown")
                    })
    
    return analysis


def generate_diagnostics_report(threat_db: Dict[str, Any]) -> None:
    """Generate comprehensive diagnostics report"""
    
    analysis = analyze_threat_db(threat_db)
    
    print("\n" + "="*80)
    print("THREAT INTELLIGENCE DIAGNOSTICS REPORT")
    print("="*80)
    
    print(f"\n📊 SUMMARY")
    print(f"{'─'*80}")
    print(f"Total IOCs Queried: {analysis['total_queries']}")
    print(f"Unique Sources Queried: {len(analysis['sources_queried'])}")
    print(f"Sources: {', '.join(sorted(analysis['sources_queried']))}")
    
    # Group sources by issue
    sources_by_action = {
        "DISABLE": [],
        "INVESTIGATE": [],
        "MONITOR": [],
        "OK": []
    }
    
    print(f"\n🔍 ERROR ANALYSIS BY SOURCE")
    print(f"{'─'*80}")
    
    for source_name in sorted(analysis["sources_queried"]):
        errors = analysis["error_summary"][source_name]
        failures = analysis["source_failures"][source_name]
        
        if not failures:
            sources_by_action["OK"].append(source_name)
            print(f"\n✅ {source_name.upper()}")
            print(f"   Status: No errors detected")
            continue
        
        # Determine action based on error codes
        error_codes = set(errors.keys())
        action = "MONITOR"  # Default
        
        if error_codes & set(SHOULD_DISABLE_CODES):
            action = "DISABLE"
        elif error_codes & set(INVESTIGATE_CODES):
            action = "INVESTIGATE"
        elif error_codes == {"unknown"}:
            action = "INVESTIGATE"
        elif error_codes <= set(EXPECTED_CODES):
            action = "MONITOR"  # Expected errors only
        
        sources_by_action[action].append(source_name)
        
        # Print source status
        status_icon = "🔴" if action == "DISABLE" else "🟡" if action == "INVESTIGATE" else "🟠" if action == "MONITOR" else "✅"
        print(f"\n{status_icon} {source_name.upper()}")
        print(f"   Action: {action}")
        print(f"   Total Failures: {len(failures)}")
        print(f"   Error Breakdown:")
        
        for error_code, count in sorted(errors.items(), key=lambda x: -x[1]):
            description = ERROR_CATEGORIES.get(error_code, "Unknown Error")
            print(f"      • {error_code} ({description}): {count} occurrences")
        
        # Show example errors
        if failures:
            print(f"   Sample Errors:")
            for i, failure in enumerate(failures[:2]):  # Show first 2
                print(f"      • IOC: {failure['ioc']}")
                print(f"        Msg: {failure['error'][:70]}...")
    
    # Summary by action
    print(f"\n{'='*80}")
    print(f"ACTION SUMMARY")
    print(f"{'='*80}")
    
    print(f"\n🔴 DISABLE SOURCES ({len(sources_by_action['DISABLE'])})")
    print(f"   Reason: Missing or invalid API credentials")
    if sources_by_action['DISABLE']:
        for source in sources_by_action['DISABLE']:
            print(f"   • {source}")
    else:
        print(f"   None")
    
    print(f"\n🟡 INVESTIGATE SOURCES ({len(sources_by_action['INVESTIGATE'])})")
    print(f"   Reason: Network issues or unexpected errors")
    if sources_by_action['INVESTIGATE']:
        for source in sources_by_action['INVESTIGATE']:
            print(f"   • {source}")
    else:
        print(f"   None")
    
    print(f"\n🟠 MONITOR SOURCES ({len(sources_by_action['MONITOR'])})")
    print(f"   Reason: Data not found or rate limited (normal)")
    if sources_by_action['MONITOR']:
        for source in sources_by_action['MONITOR']:
            print(f"   • {source}")
    else:
        print(f"   None")
    
    print(f"\n✅ HEALTHY SOURCES ({len(sources_by_action['OK'])})")
    if sources_by_action['OK']:
        for source in sources_by_action['OK']:
            print(f"   • {source}")
    else:
        print(f"   None")
    
    # Recommendations
    print(f"\n{'='*80}")
    print(f"RECOMMENDATIONS")
    print(f"{'='*80}")
    
    if sources_by_action['DISABLE']:
        print(f"\n1️⃣  DISABLE SOURCES (Priority HIGH)")
        print(f"   Sources to disable due to missing/invalid credentials:")
        for source in sources_by_action['DISABLE']:
            print(f"   • {source} - 401/403 Authentication Error")
        print(f"\n   Action: Update .env file with valid API credentials, or disable in config")
    
    if sources_by_action['INVESTIGATE']:
        print(f"\n2️⃣  INVESTIGATE SOURCES (Priority MEDIUM)")
        print(f"   Sources with network/timeout issues:")
        for source in sources_by_action['INVESTIGATE']:
            print(f"   • {source}")
        print(f"\n   Action: Check API status, network connectivity, and timeout settings")
    
    print(f"\n3️⃣  NEXT STEPS")
    print(f"   • Create DISABLED_SOURCES.json with sources that should be disabled")
    print(f"   • Update sources/__init__.py to skip disabled sources during initialization")
    print(f"   • Use config.py to mark sources as enabled/disabled")
    print(f"   • Retry queries with updated credentials for DISABLE category")
    
    print(f"\n{'='*80}\n")
    
    return sources_by_action


def create_disabled_sources_config(sources_to_disable: List[str]) -> None:
    """Create disabled sources configuration"""
    
    if not sources_to_disable:
        print("✅ No sources need to be disabled")
        return
    
    config = {
        "disabled_sources": sources_to_disable,
        "reason": "Missing or invalid API credentials (401/403 errors)",
        "created_at": datetime.now().isoformat(),
        "details": {
            "401": "Unauthorized - Missing or invalid API key",
            "403": "Forbidden - Invalid credentials or insufficient permissions"
        }
    }
    
    output_file = "disabled_sources_config.json"
    with open(output_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"✅ Created disabled sources config: {output_file}")


def generate_remediation_steps(sources_to_disable: List[str]) -> None:
    """Generate remediation steps for each disabled source"""
    
    remediation_map = {
        "virustotal": [
            "1. Go to https://www.virustotal.com/",
            "2. Sign up for a free account",
            "3. Navigate to Settings > API",
            "4. Copy your API key",
            "5. Add to .env: VT_API_KEY=<your_key>"
        ],
        "hybrid_analysis": [
            "1. Go to https://www.hybrid-analysis.com/",
            "2. Sign up for a free account",
            "3. Navigate to Settings > API",
            "4. Copy your API key",
            "5. Add to .env: HA_API_KEY=<your_key>"
        ],
        "securitytrails": [
            "1. Go to https://securitytrails.com/",
            "2. Sign up for an account",
            "3. Navigate to Settings > API",
            "4. Copy your API key",
            "5. Add to .env: SECURITYTRAILS_API_KEY=<your_key>"
        ],
        "shodan": [
            "1. Go to https://www.shodan.io/",
            "2. Sign up for a free account",
            "3. Navigate to Account > API",
            "4. Copy your API key",
            "5. Add to .env: SHODAN_API_KEY=<your_key>"
        ],
        "xforce_ibm": [
            "1. Go to https://exchange.xforce.ibmcloud.com/",
            "2. Sign up for an account",
            "3. Navigate to Settings > API",
            "4. Copy your API credentials",
            "5. Add to .env: XFORCE_API_KEY=<key> and XFORCE_API_PASSWORD=<password>"
        ]
    }
    
    print(f"\n{'='*80}")
    print(f"REMEDIATION STEPS")
    print(f"{'='*80}")
    
    for source in sources_to_disable:
        print(f"\n🔧 {source.upper()}")
        steps = remediation_map.get(source.lower(), [
            "1. Check the API provider's documentation",
            "2. Sign up/login to your account",
            "3. Generate API key/credentials",
            "4. Add credentials to .env file"
        ])
        for step in steps:
            print(f"   {step}")
    
    print(f"\n💡 ALTERNATIVE: Disable Sources")
    print(f"   If you don't need these sources, you can disable them by:")
    print(f"   • Setting source flags in config.py")
    print(f"   • Modifying sources/__init__.py to skip initialization")
    print(f"   • Using the disabled_sources_config.json")


def main():
    """Main diagnostics function"""
    
    # Load database
    threat_db = load_threat_db()
    
    # Generate report and get source actions
    sources_by_action = generate_diagnostics_report(threat_db)
    
    # Sources that should be disabled
    sources_to_disable = sources_by_action["DISABLE"]
    
    if sources_to_disable:
        print(f"\n⚠️  SOURCES REQUIRING ACTION:")
        print(f"{'─'*80}")
        
        # Create disabled sources config
        create_disabled_sources_config(sources_to_disable)
        
        # Show remediation steps
        generate_remediation_steps(sources_to_disable)
    
    # Save analysis summary
    summary = {
        "timestamp": datetime.now().isoformat(),
        "total_queries": threat_db.__len__(),
        "sources": {
            "total": len(sources_by_action["DISABLE"] + sources_by_action["INVESTIGATE"] + sources_by_action["MONITOR"] + sources_by_action["OK"]),
            "disable": sources_by_action["DISABLE"],
            "investigate": sources_by_action["INVESTIGATE"],
            "monitor": sources_by_action["MONITOR"],
            "ok": sources_by_action["OK"]
        }
    }
    
    with open("diagnostics_summary.json", 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\n✅ Diagnostics complete. Summary saved to diagnostics_summary.json")
    print(f"✅ Detailed recommendations saved to disabled_sources_config.json")


if __name__ == "__main__":
    main()
