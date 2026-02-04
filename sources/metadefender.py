"""
MetaDefender threat intelligence source
"""
from sources.base import Source
from clients import RateLimitedClient
from config import OPSWAT_KEY


opswat_client = RateLimitedClient(max_retries=3)


class MetaDefenderSource(Source):
    """MetaDefender source handler"""
    
    def __init__(self):
        super().__init__("metadefender")
    
    def query(self, ioc_type: str, value: str) -> dict:
        """Query MetaDefender API"""
        if not OPSWAT_KEY:
            return {"error": "MetaDefender API key missing"}
        
        if not ioc_type.startswith("hash_"):
            return {"error": "MetaDefender only supports hashes"}
        
        return opswat_client.request(
            "GET",
            f"https://api.metadefender.com/v4/hash/{value}",
            headers={"apikey": OPSWAT_KEY}
        )
