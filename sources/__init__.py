"""
Threat Intelligence Sources Package
"""
import csv
import logging
from pathlib import Path
from typing import List, Callable, Any, Dict

from sources.virustotal import VirusTotalSource
from sources.malwarebazaar import MalwareBazaarSource
from sources.hybrid_analysis import HybridAnalysisSource
from sources.malshare import MalShareSource
from sources.otx import OTXSource
from sources.cymru import CymruSource
from sources.anyrun import AnyRunSource  
from sources.securitytrails import SecurityTrailsSource
from sources.shodan import ShodanSource
from sources.greynoise import GreyNoiseSource
from sources.xforce_ibm import XForceIBMSource

from config import (
    VT_KEY, MB_API_KEY, HA_KEY, MALSHARE_API_KEY, OTX_API_KEY,
    CYMRU_API_USERNAME, CYMRU_API_PASSWORD, ANYRUN_API_KEY,
    SECURITYTRAILS_API_KEY, SHODAN_API_KEY, GREYNOISE_API_KEY,
    XFORCE_API_KEY, XFORCE_API_PASSWORD
)

logger = logging.getLogger(__name__)

# =====================================================
# Source Credentials Check (enable/disable at runtime)
# =====================================================
# Sources are automatically enabled if credentials are provided, disabled if empty.
# To enable a disabled source, provide valid credentials in .env.
# 

_SOURCE_CREDENTIALS = {
    "virustotal": VT_KEY,
    "malwarebazaar": MB_API_KEY,
    "hybrid_analysis": HA_KEY,
    "malshare": MALSHARE_API_KEY,
    "otx": OTX_API_KEY,
    "cymru": (CYMRU_API_USERNAME and CYMRU_API_PASSWORD),
    "anyrun": ANYRUN_API_KEY,
    "securitytrails": SECURITYTRAILS_API_KEY,
    "shodan": SHODAN_API_KEY,
    "greynoise": GREYNOISE_API_KEY,
    "xforce_ibm": (XFORCE_API_KEY and XFORCE_API_PASSWORD),
}

def _has_credentials(source_name: str) -> bool:
    """Check if a source has valid credentials configured."""
    creds = _SOURCE_CREDENTIALS.get(source_name)
    if isinstance(creds, bool):
        return creds
    return bool(creds and str(creds).strip() and str(creds).lower() != "none")


# Source registry - only include sources with valid credentials
SOURCES = {}

_source_instances = {
    "virustotal": VirusTotalSource(),
    "malwarebazaar": MalwareBazaarSource(),
    "hybrid_analysis": HybridAnalysisSource(),
    "malshare": MalShareSource(),
    "otx": OTXSource(),
    "cymru": CymruSource(),
    "anyrun": AnyRunSource(),
    "securitytrails": SecurityTrailsSource(),
    "shodan": ShodanSource(),
    "greynoise": GreyNoiseSource(),
    "xforce_ibm": XForceIBMSource(),
}

# Populate SOURCES only with configured sources
_disabled_sources = []
for source_name, source_instance in _source_instances.items():
    if _has_credentials(source_name):
        SOURCES[source_name] = source_instance
    else:
        _disabled_sources.append(source_name)
        logger.info(f"Source '{source_name}' disabled: credentials not configured or empty")

if _disabled_sources:
    logger.info(f"Disabled sources: {', '.join(_disabled_sources)}")
if SOURCES:
    logger.info(f"Active sources: {', '.join(SOURCES.keys())}")

# Maps each source to the IOC types it supports
_SOURCE_SUPPORTED_TYPES = {
    "virustotal": {"hash_md5", "hash_sha1", "hash_sha256", "ip_v4", "ip_v6", "domain", "url"},
    "malwarebazaar": {"hash_md5", "hash_sha1", "hash_sha256"},
    "hybrid_analysis": {"hash_md5", "hash_sha1", "hash_sha256", "ip_v4", "domain", "url"},
    "malshare": {"hash_md5", "hash_sha1", "hash_sha256"},
    "otx": {"hash_md5", "hash_sha1", "hash_sha256", "ip_v4", "ip_v6", "domain", "url"},
    "cymru": {"hash_md5", "hash_sha1", "hash_sha256", "ip_v4"},
    "anyrun": {"hash_md5", "hash_sha1", "hash_sha256", "ip_v4", "domain", "url"},  # DISABLED: No proven API access for IOC searches
    "securitytrails": {"ip_v4", "domain"},
    "shodan": {"ip_v4", "domain"},
    "greynoise": {"ip_v4"},
    "xforce_ibm": {"hash_md5", "hash_sha1", "hash_sha256", "ip_v4", "ip_v6", "domain", "url"}  # DISABLED: Valid XFORCE_API_KEY not available
}


def get_available_sources(ioc_type: str) -> list:
    """Get sources that support this IOC type"""
    available = []

    for name in SOURCES:
        supported = _SOURCE_SUPPORTED_TYPES.get(name, set())
        if ioc_type in supported:
            available.append(name)

    return available


# =====================================================
# Bulk Query Utilities (shared across all sources)
# =====================================================

def read_hashes_from_csv(csv_file_path: str) -> List[str]:
    """Read hashes from a CSV file.
    
    Supports multiple formats:
    - Single column with hashes (one per line)
    - Multi-column CSV with 'hash'/'h'/'value' column headers
    - Multi-column CSV using first column if no hash column found
    
    Args:
        csv_file_path: Path to CSV file containing hashes.
        
    Returns:
        List of hashes (whitespace-trimmed, comments filtered).
        
    Raises:
        FileNotFoundError: If CSV file does not exist.
        ValueError: If no hashes found or cannot determine hash column.
    """
    csv_path = Path(csv_file_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_file_path}")
    
    hashes = []
    
    with open(csv_path, "r", encoding="utf-8") as f:
        # Detect if file has CSV formatting
        first_line = f.readline()
        has_csv = "," in first_line
        f.seek(0)
        
        if not has_csv:
            # Single column or newline-separated hashes
            for line in f:
                hash_val = line.strip()
                if hash_val and not hash_val.startswith("#"):
                    hashes.append(hash_val)
        else:
            # Multi-column CSV - find hash column
            f.seek(0)
            reader = csv.DictReader(f)
            header = reader.fieldnames or []
            hash_col = None
            
            # Look for 'hash' column (case-insensitive)
            for col in header:
                if col.lower() in ["hash", "h", "value"]:
                    hash_col = col
                    break
            
            if hash_col is None:
                # Use first column if no hash column found
                hash_col = header[0] if header else None
            
            if hash_col is None:
                raise ValueError(
                    f"Cannot determine hash column from CSV. "
                    f"Columns found: {header}. Expected 'hash', 'h', or 'value'."
                )
            
            for row in reader:
                hash_val = row.get(hash_col, "").strip()
                if hash_val and not hash_val.startswith("#"):
                    hashes.append(hash_val)
    
    if not hashes:
        raise ValueError(f"No hashes found in CSV file: {csv_file_path}")
    
    logger.info(f"[bulk] Loaded {len(hashes)} hashes from CSV file")
    return hashes


def batch_items(items: List[str], batch_size: int = 1000) -> List[List[str]]:
    """Batch items into chunks of specified size.
    
    Args:
        items: List of items to batch.
        batch_size: Maximum size of each batch (default: 1000).
        
    Returns:
        List of batches (each batch is a list of items).
    """
    batches = []
    for i in range(0, len(items), batch_size):
        batches.append(items[i : i + batch_size])
    return batches


def query_source_bulk(
    source_name: str,
    csv_file_path: str,
    query_func: Callable[[List[str]], Dict[str, Any]]
) -> Dict[str, Any]:
    """Generic bulk query handler for any source supporting bulk operations.
    
    Reads hashes from CSV, batches them, and calls the source's bulk query function.
    
    Args:
        source_name: Name of the source (for logging).
        csv_file_path: Path to CSV file with hashes.
        query_func: Callable that takes List[str] of hashes and returns Dict with results.
                   This should be the source's _query_bulk_hashes() method.
    
    Returns:
        Response dict with combined results from all batches.
        Format: {"query_status": "ok", "source": source_name, "data": [results...]}
    """
    try:
        # Read hashes from CSV
        hashes = read_hashes_from_csv(csv_file_path)
        
        # Batch hashes (1000 per batch)
        batches = batch_items(hashes, batch_size=1000)
        
        logger.info(
            f"[bulk] {source_name} will query {len(hashes)} hashes in {len(batches)} batch(es)"
        )
        
        all_results = []
        
        # Execute each batch
        for batch_idx, batch in enumerate(batches):
            batch_num = batch_idx + 1
            logger.info(
                f"[bulk] {source_name} batch {batch_num}/{len(batches)} ({len(batch)} hashes)"
            )
            
            response = query_func(batch)
            
            if response.get("query_status") != "ok":
                logger.warning(
                    f"[bulk] {source_name} batch {batch_num} failed: {response.get('error')}"
                )
                continue
            
            batch_results = response.get("data", [])
            if isinstance(batch_results, list):
                all_results.extend(batch_results)
            else:
                logger.warning(
                    f"[bulk] {source_name} batch {batch_num} returned unexpected format (expected list)"
                )
        
        if not all_results:
            return {
                "query_status": "error",
                "source": source_name,
                "error": "Bulk query failed - no results returned",
                "details": f"Queried {len(hashes)} hashes from {len(batches)} batch(es)",
            }
        
        return {
            "query_status": "ok",
            "source": source_name,
            "data": all_results
        }
        
    except FileNotFoundError as e:
        return {
            "query_status": "error",
            "source": source_name,
            "error": str(e),
            "details": "Ensure the CSV file path is correct and file exists",
        }
    except ValueError as e:
        return {
            "query_status": "error",
            "source": source_name,
            "error": str(e),
        }
    except Exception as e:
        logger.exception(f"[bulk] {source_name} bulk query failed")
        return {
            "query_status": "error",
            "source": source_name,
            "error": f"Bulk query failed: {str(e)}",
        }
