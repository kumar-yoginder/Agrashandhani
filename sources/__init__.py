"""
Threat Intelligence Sources Package
"""
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

# Source registry
SOURCES = {
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
    "xforce_ibm": XForceIBMSource()
}

# Maps each source to the IOC types it supports
_SOURCE_SUPPORTED_TYPES = {
    "virustotal": {"hash_md5", "hash_sha1", "hash_sha256", "ip_v4", "ip_v6", "domain", "url"},
    "malwarebazaar": {"hash_md5", "hash_sha1", "hash_sha256"},
    "hybrid_analysis": {"hash_md5", "hash_sha1", "hash_sha256", "ip_v4", "domain", "url"},
    "malshare": {"hash_md5", "hash_sha1", "hash_sha256"},
    "otx": {"hash_md5", "hash_sha1", "hash_sha256", "ip_v4", "ip_v6", "domain", "url"},
    "cymru": {"hash_md5", "hash_sha1", "hash_sha256", "ip_v4"},
    "anyrun": {"hash_md5", "hash_sha1", "hash_sha256", "ip_v4", "domain", "url"},
    "securitytrails": {"ip_v4", "domain"},
    "shodan": {"ip_v4", "domain"},
    "greynoise": {"ip_v4"},
    "xforce_ibm": {"hash_md5", "hash_sha1", "hash_sha256", "ip_v4", "ip_v6", "domain", "url"}
}


def get_available_sources(ioc_type: str) -> list:
    """Get sources that support this IOC type"""
    available = []

    for name in SOURCES:
        supported = _SOURCE_SUPPORTED_TYPES.get(name, set())
        if ioc_type in supported:
            available.append(name)

    return available
