"""
OSINT Search Engine
"""
from datetime import datetime
from validators import IOCValidator
from sources import SOURCES, get_available_sources
from database import db_manager


def _run_osint_engine(query: str, sources: list = None, refresh: bool = False) -> dict:
    """
    Search for IOC across threat intelligence sources.
    Returns structured data with source mappings and timestamps.
    
    Args:
        query: IOC to search
        sources: List of specific sources to query
        refresh: If True, ignore local DB and force API search
    
    Returns:
        Dictionary with query results, timestamps, and source data
    """
    ioc = IOCValidator.classify(query)
    
    # Return error for unknown IOC types
    if ioc["type"] == "unknown":
        return {
            "query": query,
            "timestamp": datetime.now().isoformat(),
            "error": "IOC type not supported",
            "sources": {}
        }
    
    # Check local database first (unless refresh is True)
    if not refresh and db_manager.exists(query):
        cached_result = db_manager.get(query)
        print(f"[*] Found in local database: {query}")
        print(f"    Cached: {cached_result.get('timestamp', 'unknown')}")
        print(f"    Use --refresh to search external sources again")
        return cached_result
    
    # Determine which sources to query
    if sources is None or len(sources) == 0:
        sources = get_available_sources(ioc["type"])
    
    # Query each source
    results = {
        "query": query,
        "ioc_type": ioc["type"],
        "timestamp": datetime.now().isoformat(),
        "sources": {}
    }
    
    for source_name in sources:
        if source_name not in SOURCES:
            results["sources"][source_name] = {
                "present": False,
                "error": f"Source '{source_name}' not found"
            }
            continue
        
        source = SOURCES[source_name]
        data = source.query(ioc["type"], ioc["value"])
        
        # Check if query was successful
        has_error = "error" in data
        
        results["sources"][source_name] = {
            "present": not has_error,
            "data": data,
            "queried_at": datetime.now().isoformat()
        }
    
    # Save to database
    db_manager.set(query, results)
    
    return results


def run_osint_search(search_type: str, query: str) -> dict:
    """
    Backward-compatible wrapper for search.py
    search_type is ignored (auto-detection used).
    """
    return _run_osint_engine(query)
