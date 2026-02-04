"""
Hybrid Analysis threat intelligence source
"""
from sources.base import Source
from clients import RateLimitedClient
from config import HA_KEY


ha_client = RateLimitedClient(max_retries=3)


class HybridAnalysisSource(Source):
    """Hybrid Analysis source handler"""
    
    def __init__(self):
        super().__init__("hybrid_analysis")
    
    def query(self, ioc_type: str, value: str) -> dict:
        """Query Hybrid Analysis API"""
        if not HA_KEY:
            return {"error": "Hybrid Analysis API key missing"}
        
        if not ioc_type.startswith("hash_"):
            return {"error": "Hybrid Analysis only supports hashes"}
        
        headers = {
            "api-key": HA_KEY,
            "User-Agent": "Falcon Sandbox"
        }
        
        return ha_client.request(
            "GET",
            f"https://www.hybrid-analysis.com/api/v2/overview/{value}",
            headers=headers
        )
