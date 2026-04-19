#!/usr/bin/env python3
"""
Source Manager - Handles source initialization with disabled sources support

This module:
1. Loads the disabled_sources_config.json to identify disabled sources
2. Validates API credentials in .env before initializing sources
3. Automatically disables sources with missing credentials
4. Provides diagnostic information about disabled sources
5. Allows re-enabling sources when credentials are added
"""

import json
import os
from typing import Dict, List, Set, Any
from dotenv import load_dotenv

load_dotenv()


class SourceManager:
    """Manages source initialization and disabling"""
    
    # Source API key mappings
    SOURCE_CREDENTIALS = {
        "virustotal": {"env_vars": ["VT_API_KEY"], "name": "VirusTotal"},
        "hybrid_analysis": {"env_vars": ["HA_API_KEY"], "name": "Hybrid Analysis"},
        "otx": {"env_vars": ["OTX_API_KEY"], "name": "OTX"},
        "malwarebazaar": {"env_vars": ["MB_API_KEY"], "name": "MalwareBazaar"},
        "malshare": {"env_vars": ["MALSHARE_API_KEY"], "name": "MalShare"},
        "cymru": {"env_vars": ["CYMRU_API_USERNAME", "CYMRU_API_PASSWORD"], "name": "Cymru"},
        "anyrun": {"env_vars": ["ANYRUN_API_KEY"], "name": "Any.run"},
        "securitytrails": {"env_vars": ["SECURITYTRAILS_API_KEY"], "name": "SecurityTrails"},
        "shodan": {"env_vars": ["SHODAN_API_KEY"], "name": "Shodan"},
        "greynoise": {"env_vars": ["GREYNOISE_API_KEY"], "name": "GreyNoise"},
        "xforce_ibm": {"env_vars": ["XFORCE_API_KEY", "XFORCE_API_PASSWORD"], "name": "X-Force IBM"}
    }
    
    def __init__(self, config_file: str = "disabled_sources_config.json", strict: bool = False):
        """Initialize source manager
        
        Args:
            config_file: Path to disabled sources configuration
            strict: If True, validate all credentials on init
        """
        self.config_file = config_file
        self.strict = strict
        self.disabled_sources: Set[str] = set()
        self.missing_credentials: Dict[str, List[str]] = {}
        self.enabled_sources: Set[str] = set()
        self.disabled_sources_info: Dict[str, Any] = {}
        
        # Load config
        self._load_disabled_sources_config()
        
        # Validate credentials
        self._validate_credentials()
    
    def _load_disabled_sources_config(self) -> None:
        """Load disabled sources from config file"""
        if not os.path.exists(self.config_file):
            return
        
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                self.disabled_sources = set(config.get("disabled_sources", []))
                self.disabled_sources_info = config
        except Exception as e:
            print(f"⚠️  Warning: Could not load disabled sources config: {e}")
            self.disabled_sources = set()
    
    def _validate_credentials(self) -> None:
        """Validate that each source has required credentials"""
        # Reset enabled sources
        self.enabled_sources = set()
        
        # Check each source
        for source, cred_info in self.SOURCE_CREDENTIALS.items():
            # If already in disabled config, keep it disabled
            if source in self.disabled_sources:
                continue
            
            # Check credentials
            env_vars = cred_info["env_vars"]
            missing = []
            for var in env_vars:
                if not os.getenv(var):
                    missing.append(var)
            
            # Disable if missing credentials
            if missing:
                self.missing_credentials[source] = missing
                self.disabled_sources.add(source)
            else:
                # Credentials present, enable this source
                self.enabled_sources.add(source)
    
    def is_source_enabled(self, source_name: str) -> bool:
        """Check if source is enabled"""
        return source_name not in self.disabled_sources
    
    def get_disabled_sources(self) -> Set[str]:
        """Get all disabled sources"""
        return self.disabled_sources.copy()
    
    def get_enabled_sources(self) -> Set[str]:
        """Get all enabled sources"""
        return self.enabled_sources.copy()
    
    def get_missing_credentials(self, source_name: str = None) -> Dict[str, List[str]]:
        """Get missing credentials for a source or all sources"""
        if source_name:
            return {source_name: self.missing_credentials.get(source_name, [])}
        return self.missing_credentials
    
    def print_status(self) -> None:
        """Print status of all sources"""
        print("\n" + "="*80)
        print("SOURCE STATUS REPORT")
        print("="*80)
        
        print(f"\n✅ ENABLED SOURCES ({len(self.enabled_sources)}):")
        for source in sorted(self.enabled_sources):
            print(f"   • {source}")
        
        print(f"\n❌ DISABLED SOURCES ({len(self.disabled_sources)}):")
        for source in sorted(self.disabled_sources):
            reason = "Config" if source in self.disabled_sources_info.get("disabled_sources", []) else "Missing Credentials"
            missing = self.missing_credentials.get(source, [])
            print(f"   • {source} ({reason})")
            if missing:
                print(f"     Missing: {', '.join(missing)}")
        
        print(f"\n📊 SUMMARY:")
        print(f"   Total Sources: {len(self.SOURCE_CREDENTIALS)}")
        print(f"   Enabled: {len(self.enabled_sources)}")
        print(f"   Disabled: {len(self.disabled_sources)}")
        print(f"\n{'='*80}\n")


def filter_sources(sources_dict: Dict[str, Any], manager: SourceManager) -> Dict[str, Any]:
    """Filter sources dictionary to only include enabled sources
    
    Args:
        sources_dict: Dictionary of source classes/instances
        manager: SourceManager instance
    
    Returns:
        Filtered dictionary with only enabled sources
    """
    enabled_sources = manager.get_enabled_sources()
    filtered = {
        key: value for key, value in sources_dict.items()
        if key in enabled_sources
    }
    
    disabled = set(sources_dict.keys()) - enabled_sources
    if disabled:
        print(f"⚠️  Disabled {len(disabled)} sources due to missing credentials:")
        for source in sorted(disabled):
            missing = manager.get_missing_credentials(source)[source]
            print(f"   • {source}: missing {', '.join(missing)}")
    
    return filtered


# Global source manager instance
_source_manager = None


def get_source_manager() -> SourceManager:
    """Get or create global source manager instance"""
    global _source_manager
    if _source_manager is None:
        _source_manager = SourceManager()
    return _source_manager


def is_source_enabled(source_name: str) -> bool:
    """Check if a source is enabled"""
    return get_source_manager().is_source_enabled(source_name)


def get_enabled_sources() -> Set[str]:
    """Get all enabled sources"""
    return get_source_manager().get_enabled_sources()


def print_source_status() -> None:
    """Print source status report"""
    get_source_manager().print_status()


if __name__ == "__main__":
    # Run diagnostics
    manager = SourceManager()
    manager.print_status()
