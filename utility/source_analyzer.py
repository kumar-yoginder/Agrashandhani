#!/usr/bin/env python3
"""
Source Capability Analyzer - Interactive tool for exploring threat intelligence sources

Provides CLI interface to explore capabilities, rate limits, and enhancement opportunities
for all integrated sources in Agrashandhani framework.
"""

import json
from typing import List, Dict, Tuple, Any


# Source capabilities database
SOURCES_DB = {
    "virustotal": {
        "name": "VirusTotal",
        "tier": "⭐⭐⭐",
        "supported_iocs": ["hash_md5", "hash_sha1", "hash_sha256", "hash_ssdeep", "hash_tlsh", "ip_v4", "ip_v6", "domain", "url"],
        "malware_family": True,
        "correlated_hashes": True,
        "apt_info": True,
        "rate_limit": "4 req/min",
        "rate_limit_value": 0.067,
        "file": "sources/virustotal.py",
        "enhancement_status": "Not Enhanced (High Priority)",
        "enhancement_priority": 1,
        "enhancement_effort": "Medium",
        "enhancement_impact": "Major",
        "features": [
            "70+ antivirus engines",
            "Community/expert intelligence",
            "Behavioral analysis",
            "YARA rules detection",
            "Similar samples detection",
            "Related samples via filename patterns",
            "Sandbox analysis integration"
        ]
    },
    "otx": {
        "name": "OTX",
        "tier": "⭐⭐⭐",
        "supported_iocs": ["hash_md5", "hash_sha1", "hash_sha256", "ip_v4", "ip_v6", "domain", "url"],
        "malware_family": True,
        "correlated_hashes": True,
        "apt_info": True,
        "rate_limit": "Unlimited",
        "rate_limit_value": float('inf'),
        "file": "sources/otx.py",
        "enhancement_status": "ENHANCED ✅",
        "enhancement_priority": 0,
        "enhancement_effort": "Complete",
        "enhancement_impact": "Complete",
        "features": [
            "Multi-section sequential querying",
            "Malware family extraction",
            "APT group identification (14+ keywords)",
            "Correlated hash discovery",
            "Community threat feeds",
            "70+ integrated threat feeds",
            "Pulse-based intelligence"
        ]
    },
    "malwarebazaar": {
        "name": "MalwareBazaar",
        "tier": "⭐",
        "supported_iocs": ["hash_md5", "hash_sha1", "hash_sha256", "hash_imphash", "hash_tlsh", "hash_telfhash", "hash_gimphash"],
        "malware_family": True,
        "correlated_hashes": False,
        "apt_info": False,
        "rate_limit": "2 req/sec",
        "rate_limit_value": 2.0,
        "file": "sources/malwarebazaar.py",
        "enhancement_status": "Limited Enrichment",
        "enhancement_priority": 4,
        "enhancement_effort": "Low",
        "enhancement_impact": "Low",
        "features": [
            "Free malware sample database",
            "Collaborative submissions",
            "Recent malware samples",
            "POST-based API",
            "Malware family tags"
        ]
    },
    "hybrid_analysis": {
        "name": "Hybrid Analysis",
        "tier": "⭐⭐",
        "supported_iocs": ["hash_md5", "hash_sha1", "hash_sha256", "ip_v4", "ip_v6", "domain", "url"],
        "malware_family": True,
        "correlated_hashes": True,
        "apt_info": True,
        "rate_limit": "50 req/day",
        "rate_limit_value": 0.0006,
        "file": "sources/hybrid_analysis.py",
        "enhancement_status": "Enhancement Candidate",
        "enhancement_priority": 3,
        "enhancement_effort": "Medium",
        "enhancement_impact": "Good",
        "features": [
            "Falcon Sandbox integration",
            "Advanced search with operators",
            "Behavioral analysis results",
            "Sandbox screenshots/process trees",
            "MITRE ATT&CK mapping",
            "Verdict tags",
            "Environment type detection"
        ]
    },
    "anyrun": {
        "name": "Any.run",
        "tier": "⭐⭐",
        "supported_iocs": ["hash_md5", "hash_sha1", "hash_sha256", "ip_v4", "ip_v6", "domain", "url"],
        "malware_family": True,
        "correlated_hashes": False,
        "apt_info": False,
        "rate_limit": "100 req/day",
        "rate_limit_value": 0.0012,
        "file": "sources/anyrun.py",
        "enhancement_status": "Enhancement Candidate",
        "enhancement_priority": 4,
        "enhancement_effort": "Low-Medium",
        "enhancement_impact": "Good",
        "features": [
            "Interactive sandbox analysis",
            "TI Lookup service",
            "Behavioral analysis",
            "Network activity capture",
            "Batch indicator support",
            "Malware family detection"
        ]
    },
    "shodan": {
        "name": "Shodan",
        "tier": "Standard",
        "supported_iocs": ["ip_v4", "domain"],
        "malware_family": False,
        "correlated_hashes": False,
        "apt_info": False,
        "rate_limit": "1 req/sec",
        "rate_limit_value": 1.0,
        "file": "sources/shodan.py",
        "enhancement_status": "Not Applicable (Infrastructure)",
        "enhancement_priority": 99,
        "enhancement_effort": "N/A",
        "enhancement_impact": "N/A",
        "features": [
            "Internet-wide scanning data",
            "Open ports and services",
            "Banner/fingerprint data",
            "CVE associations",
            "Geolocation and ASN data",
            "Domain to IP resolution"
        ]
    },
    "greynoise": {
        "name": "GreyNoise",
        "tier": "Standard",
        "supported_iocs": ["ip_v4"],
        "malware_family": False,
        "correlated_hashes": False,
        "apt_info": False,
        "rate_limit": "Unlimited",
        "rate_limit_value": float('inf'),
        "file": "sources/greynoise.py",
        "enhancement_status": "Not Applicable (Noise Classification)",
        "enhancement_priority": 99,
        "enhancement_effort": "N/A",
        "enhancement_impact": "N/A",
        "features": [
            "Background noise classification",
            "Malicious vs. benign distinction",
            "Scanner/researcher identification",
            "Organization attribution",
            "Actor classification",
            "Last activity timestamps"
        ]
    },
    "securitytrails": {
        "name": "SecurityTrails",
        "tier": "Standard",
        "supported_iocs": ["domain", "ip_v4", "ip_v6"],
        "malware_family": False,
        "correlated_hashes": False,
        "apt_info": False,
        "rate_limit": "50 req/day",
        "rate_limit_value": 0.0006,
        "file": "sources/securitytrails.py",
        "enhancement_status": "Not Applicable (DNS/Infrastructure)",
        "enhancement_priority": 99,
        "enhancement_effort": "N/A",
        "enhancement_impact": "N/A",
        "features": [
            "Current and historical DNS records",
            "IP to hostname mapping",
            "Domain reputation",
            "WHOIS data",
            "Subdomain enumeration",
            "Associated infrastructure discovery"
        ]
    },
    "cymru": {
        "name": "Cymru",
        "tier": "Standard",
        "supported_iocs": ["hash_md5", "hash_sha1", "hash_sha256", "ip_v4"],
        "malware_family": False,
        "correlated_hashes": False,
        "apt_info": False,
        "rate_limit": "Unlimited",
        "rate_limit_value": float('inf'),
        "file": "sources/cymru.py",
        "enhancement_status": "Limited Data",
        "enhancement_priority": 99,
        "enhancement_effort": "Low",
        "enhancement_impact": "Very Low",
        "features": [
            "Hash reputation lookup",
            "Antivirus detection rate",
            "Last seen date",
            "IP to ASN mapping",
            "BGP prefix mapping"
        ]
    },
    "malshare": {
        "name": "MalShare",
        "tier": "⭐",
        "supported_iocs": ["hash_md5", "hash_sha1", "hash_sha256"],
        "malware_family": True,
        "correlated_hashes": False,
        "apt_info": False,
        "rate_limit": "Varies",
        "rate_limit_value": 0.5,
        "file": "sources/malshare.py",
        "enhancement_status": "Limited Data",
        "enhancement_priority": 5,
        "enhancement_effort": "Low",
        "enhancement_impact": "Low",
        "features": [
            "Malware sample sharing platform",
            "Detailed file analysis results",
            "Malware classification and metadata",
            "Community submissions",
            "Sample details endpoint"
        ]
    },
    "xforce_ibm": {
        "name": "X-Force IBM",
        "tier": "⭐⭐",
        "supported_iocs": ["hash_md5", "hash_sha1", "hash_sha256", "ip_v4", "ip_v6", "domain", "url"],
        "malware_family": True,
        "correlated_hashes": False,
        "apt_info": True,
        "rate_limit": "5 req/sec",
        "rate_limit_value": 5.0,
        "file": "sources/xforce_ibm.py",
        "enhancement_status": "Enhancement Candidate",
        "enhancement_priority": 2,
        "enhancement_effort": "Medium",
        "enhancement_impact": "Major",
        "features": [
            "IP reputation and geolocation",
            "Domain/URL threat scoring",
            "Malware hash analysis",
            "Passive DNS data",
            "Vulnerability intelligence",
            "Threat actor correlation",
            "Campaign correlation",
            "Enterprise-grade TI"
        ]
    }
}

# IOC type compatibility matrix
IOC_TYPES = ["hash", "ip", "domain", "url"]

# Commands
COMMANDS = {
    "list": "List all sources",
    "details": "Show details for a specific source",
    "matrix": "Show capability matrix",
    "hash": "Show sources supporting hash IOCs",
    "ip": "Show sources supporting IP IOCs",
    "domain": "Show sources supporting domain IOCs",
    "url": "Show sources supporting URL IOCs",
    "malware": "Show sources providing malware family info",
    "correlated": "Show sources providing correlated hashes",
    "apt": "Show sources providing APT/threat actor info",
    "enhanced": "Show enhancement status of all sources",
    "priority": "Show enhancement priority ranking",
    "compare": "Compare two sources",
    "stats": "Show statistics about sources",
    "help": "Show this help message"
}


def print_header(text: str):
    """Print a formatted header"""
    print(f"\n{'='*80}")
    print(f"  {text}")
    print(f"{'='*80}\n")


def cmd_list():
    """List all sources"""
    print_header("AVAILABLE SOURCES")
    
    for key, source in SOURCES_DB.items():
        status_emoji = "✅" if "ENHANCED" in source["enhancement_status"] else "❌"
        print(f"{status_emoji} {source['tier']} {source['name']:20} | {source['enhancement_status']:40} | {source['rate_limit']}")
    
    print(f"\nTotal: {len(SOURCES_DB)} sources")


def cmd_details(source_name: str):
    """Show details for a specific source"""
    source_key = source_name.lower()
    
    if source_key not in SOURCES_DB:
        print(f"❌ Source '{source_name}' not found")
        return
    
    src = SOURCES_DB[source_key]
    print_header(f"SOURCE: {src['name']} {src['tier']}")
    
    print(f"📁 File: {src['file']}")
    print(f"🔄 Rate Limit: {src['rate_limit']}")
    print(f"📊 Enhancement Status: {src['enhancement_status']}")
    
    print(f"\n✅ Supported IOC Types:")
    for ioc in src['supported_iocs']:
        print(f"   - {ioc}")
    
    print(f"\n📈 Enrichment Capabilities:")
    print(f"   - Malware Family:     {'✅ Yes' if src['malware_family'] else '❌ No'}")
    print(f"   - Correlated Hashes:  {'✅ Yes' if src['correlated_hashes'] else '❌ No'}")
    print(f"   - APT/Threat Actor:   {'✅ Yes' if src['apt_info'] else '❌ No'}")
    
    print(f"\n🎯 Features:")
    for feature in src['features']:
        print(f"   • {feature}")
    
    if src['enhancement_priority'] < 10:
        print(f"\n🚀 Enhancement Opportunity:")
        print(f"   Priority:  {src['enhancement_priority']}")
        print(f"   Effort:    {src['enhancement_effort']}")
        print(f"   Impact:    {src['enhancement_impact']}")


def cmd_matrix():
    """Show capability matrix"""
    print_header("SOURCE CAPABILITY MATRIX")
    
    # Print header
    print(f"{'Source':<20} {'Tier':<8} {'Malware':<8} {'Corr':<6} {'APT':<6} {'Rate Limit':<15} {'Status':<25}")
    print("-" * 100)
    
    for key, src in SOURCES_DB.items():
        malware = "✅" if src['malware_family'] else "❌"
        corr = "✅" if src['correlated_hashes'] else "❌"
        apt = "✅" if src['apt_info'] else "❌"
        print(f"{src['name']:<20} {src['tier']:<8} {malware:<8} {corr:<6} {apt:<6} {src['rate_limit']:<15} {src['enhancement_status'][:23]:<25}")


def cmd_filter_by_capability(capability: str):
    """Filter sources by capability"""
    capability_map = {
        "hash": "hash",
        "ip": "ip",
        "domain": "domain",
        "url": "url",
        "malware": "malware_family",
        "correlated": "correlated_hashes",
        "apt": "apt_info"
    }
    
    if capability not in capability_map:
        print(f"❌ Unknown capability: {capability}")
        return
    
    field = capability_map[capability]
    print_header(f"SOURCES SUPPORTING: {field.upper()}")
    
    matching = []
    for key, src in SOURCES_DB.items():
        if field == "hash":
            has_capability = any(ioc.startswith("hash_") for ioc in src['supported_iocs'])
        elif field in ["ip", "domain", "url"]:
            has_capability = any(ioc.startswith(f"{field}_") for ioc in src['supported_iocs'])
        else:
            has_capability = src.get(field, False)
        
        if has_capability:
            matching.append(src['name'])
    
    if not matching:
        print(f"❌ No sources found supporting {field}")
        return
    
    for i, name in enumerate(matching, 1):
        print(f"{i}. {name}")
    
    print(f"\nTotal: {len(matching)} sources")


def cmd_enhanced():
    """Show enhancement status"""
    print_header("ENHANCEMENT STATUS OVERVIEW")
    
    enhanced = [s for s in SOURCES_DB.values() if "ENHANCED" in s["enhancement_status"]]
    candidates = [s for s in SOURCES_DB.values() if s["enhancement_priority"] < 10 and "ENHANCED" not in s["enhancement_status"]]
    not_applicable = [s for s in SOURCES_DB.values() if s["enhancement_priority"] >= 10]
    
    print(f"✅ ENHANCED ({len(enhanced)}):")
    for src in enhanced:
        print(f"   • {src['name']}")
    
    print(f"\n🔧 ENHANCEMENT CANDIDATES ({len(candidates)}):")
    for src in sorted(candidates, key=lambda x: x["enhancement_priority"]):
        print(f"   {src['enhancement_priority']}. {src['name']:20} | Effort: {src['enhancement_effort']:12} | Impact: {src['enhancement_impact']}")
    
    print(f"\n⚠️  NOT APPLICABLE ({len(not_applicable)}):")
    for src in not_applicable:
        print(f"   • {src['name']:20} ({src['enhancement_status']})")


def cmd_priority():
    """Show enhancement priority ranking"""
    print_header("ENHANCEMENT PRIORITY RANKING")
    
    ranked = sorted([s for s in SOURCES_DB.values() if s['enhancement_priority'] < 10], 
                   key=lambda x: x['enhancement_priority'])
    
    for i, src in enumerate(ranked, 1):
        print(f"{i}. {src['name']:20} | Priority: {src['enhancement_priority']} | Effort: {src['enhancement_effort']:12} | Impact: {src['enhancement_impact']}")


def cmd_compare(source1: str, source2: str):
    """Compare two sources"""
    s1_key = source1.lower()
    s2_key = source2.lower()
    
    if s1_key not in SOURCES_DB or s2_key not in SOURCES_DB:
        print(f"❌ One or both sources not found")
        return
    
    s1 = SOURCES_DB[s1_key]
    s2 = SOURCES_DB[s2_key]
    
    print_header(f"COMPARISON: {s1['name']} vs {s2['name']}")
    
    comparisons = [
        ("Tier", s1['tier'], s2['tier']),
        ("Rate Limit", s1['rate_limit'], s2['rate_limit']),
        ("Malware Family", "✅" if s1['malware_family'] else "❌", "✅" if s2['malware_family'] else "❌"),
        ("Correlated Hashes", "✅" if s1['correlated_hashes'] else "❌", "✅" if s2['correlated_hashes'] else "❌"),
        ("APT Info", "✅" if s1['apt_info'] else "❌", "✅" if s2['apt_info'] else "❌"),
        ("Enhancement Status", s1['enhancement_status'], s2['enhancement_status']),
        ("# of IOC Types", str(len(s1['supported_iocs'])), str(len(s2['supported_iocs'])))
    ]
    
    print(f"{'Attribute':<25} {s1['name']:<25} {s2['name']:<25}")
    print("-" * 75)
    for attr, val1, val2 in comparisons:
        print(f"{attr:<25} {val1:<25} {val2:<25}")


def cmd_stats():
    """Show statistics"""
    print_header("SOURCE STATISTICS")
    
    # Count capabilities
    with_malware = sum(1 for s in SOURCES_DB.values() if s['malware_family'])
    with_correlated = sum(1 for s in SOURCES_DB.values() if s['correlated_hashes'])
    with_apt = sum(1 for s in SOURCES_DB.values() if s['apt_info'])
    enhanced = sum(1 for s in SOURCES_DB.values() if "ENHANCED" in s['enhancement_status'])
    
    # IOC coverage
    hash_support = sum(1 for s in SOURCES_DB.values() if any(ioc.startswith("hash_") for ioc in s['supported_iocs']))
    ip_support = sum(1 for s in SOURCES_DB.values() if any(ioc.startswith("ip_") for ioc in s['supported_iocs']))
    domain_support = sum(1 for s in SOURCES_DB.values() if "domain" in s['supported_iocs'])
    url_support = sum(1 for s in SOURCES_DB.values() if "url" in s['supported_iocs'])
    
    print("CAPABILITY COVERAGE:")
    print(f"  Malware Family:      {with_malware}/{len(SOURCES_DB)} sources")
    print(f"  Correlated Hashes:   {with_correlated}/{len(SOURCES_DB)} sources")
    print(f"  APT/Threat Actor:    {with_apt}/{len(SOURCES_DB)} sources")
    print(f"  Enhanced:            {enhanced}/{len(SOURCES_DB)} sources")
    
    print("\nIOC TYPE SUPPORT:")
    print(f"  Hash IOCs:     {hash_support}/{len(SOURCES_DB)} sources")
    print(f"  IP IOCs:       {ip_support}/{len(SOURCES_DB)} sources")
    print(f"  Domain IOCs:   {domain_support}/{len(SOURCES_DB)} sources")
    print(f"  URL IOCs:      {url_support}/{len(SOURCES_DB)} sources")
    
    # Rate limit analysis
    unlimited = sum(1 for s in SOURCES_DB.values() if "Unlimited" in s['rate_limit'])
    print(f"\nRATE LIMITS:")
    print(f"  Unlimited:     {unlimited}/{len(SOURCES_DB)} sources")
    print(f"  Rate Limited:  {len(SOURCES_DB) - unlimited}/{len(SOURCES_DB)} sources")


def cmd_help():
    """Show help"""
    print_header("AVAILABLE COMMANDS")
    for cmd, description in COMMANDS.items():
        print(f"  {cmd:20} - {description}")


def interactive_mode():
    """Interactive command mode"""
    print_header("AGRASHANDHANI SOURCE CAPABILITY ANALYZER")
    print("Type 'help' for available commands. Type 'exit' to quit.\n")
    
    while True:
        try:
            user_input = input(">>> ").strip().lower()
            
            if user_input == "exit":
                print("Goodbye!")
                break
            
            if user_input == "help":
                cmd_help()
            elif user_input == "list":
                cmd_list()
            elif user_input.startswith("details "):
                cmd_details(user_input.replace("details ", ""))
            elif user_input == "matrix":
                cmd_matrix()
            elif user_input == "hash":
                cmd_filter_by_capability("hash")
            elif user_input == "ip":
                cmd_filter_by_capability("ip")
            elif user_input == "domain":
                cmd_filter_by_capability("domain")
            elif user_input == "url":
                cmd_filter_by_capability("url")
            elif user_input == "malware":
                cmd_filter_by_capability("malware")
            elif user_input == "correlated":
                cmd_filter_by_capability("correlated")
            elif user_input == "apt":
                cmd_filter_by_capability("apt")
            elif user_input == "enhanced":
                cmd_enhanced()
            elif user_input == "priority":
                cmd_priority()
            elif user_input.startswith("compare "):
                parts = user_input.replace("compare ", "").split()
                if len(parts) == 2:
                    cmd_compare(parts[0], parts[1])
                else:
                    print("❌ Usage: compare source1 source2")
            elif user_input == "stats":
                cmd_stats()
            elif user_input:
                print(f"❌ Unknown command: {user_input}. Type 'help' for available commands.")
        
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # Command-line mode
        cmd = sys.argv[1].lower()
        
        if cmd == "list":
            cmd_list()
        elif cmd == "details" and len(sys.argv) > 2:
            cmd_details(sys.argv[2])
        elif cmd == "matrix":
            cmd_matrix()
        elif cmd == "hash":
            cmd_filter_by_capability("hash")
        elif cmd == "ip":
            cmd_filter_by_capability("ip")
        elif cmd == "domain":
            cmd_filter_by_capability("domain")
        elif cmd == "url":
            cmd_filter_by_capability("url")
        elif cmd == "malware":
            cmd_filter_by_capability("malware")
        elif cmd == "correlated":
            cmd_filter_by_capability("correlated")
        elif cmd == "apt":
            cmd_filter_by_capability("apt")
        elif cmd == "enhanced":
            cmd_enhanced()
        elif cmd == "priority":
            cmd_priority()
        elif cmd == "compare" and len(sys.argv) > 3:
            cmd_compare(sys.argv[2], sys.argv[3])
        elif cmd == "stats":
            cmd_stats()
        else:
            print("Usage: python source_analyzer.py <command> [args]")
            print("Commands: list, details, matrix, hash, ip, domain, url, malware, correlated, apt, enhanced, priority, compare, stats")
    else:
        # Interactive mode
        interactive_mode()
