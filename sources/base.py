"""
Base Source class for threat intelligence sources
"""


class Source:
    """Base class for threat intelligence sources"""
    
    def __init__(self, name: str):
        self.name = name
    
    def query(self, ioc_type: str, value: str) -> dict:
        """Query source for IOC information"""
        raise NotImplementedError(f"query() not implemented for {self.name}")
