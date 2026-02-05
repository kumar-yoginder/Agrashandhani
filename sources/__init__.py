"""
Threat Intelligence Sources Package
"""
from sources.virustotal import VirusTotalSource
from sources.malwarebazaar import MalwareBazaarSource
from sources.hybrid_analysis import HybridAnalysisSource
from sources.malshare import MalShareSource
from sources.otx import OTXSource

# Source registry
SOURCES = {
    "virustotal": VirusTotalSource(),
    "malwarebazaar": MalwareBazaarSource(),
    "hybrid_analysis": HybridAnalysisSource(),
    "malshare": MalShareSource(),
    "otx": OTXSource()
}


def get_available_sources(ioc_type: str) -> list:
    """Get sources that support this IOC type"""
    available = []
    
    # Check if it's a hash type (md5, sha1, sha256)
    is_hash = ioc_type.startswith("hash_")
    is_ip = ioc_type.startswith("ip_")
    
    for name, source in SOURCES.items():
        try:
            # Hash sources: all support hashes
            if is_hash:
                available.append(name)
            # IP sources: only virustotal supports IPs
            elif is_ip and name == "virustotal":
                available.append(name)
        except:
            pass
    
    return available
