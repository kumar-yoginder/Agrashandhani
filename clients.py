"""
HTTP Client with rate limiting and retry logic
"""
import time
import random
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from config import MAX_RETRIES, BACKOFF_FACTOR, HTTP_TIMEOUT


class RateLimitedClient:
    """HTTP client with rate limiting and automatic retries"""
    
    def __init__(self, max_retries=MAX_RETRIES, backoff_factor=BACKOFF_FACTOR):
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.session = requests.Session()
        
        # Configure retry strategy for connection errors
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def request(self, method, url, **kwargs):
        """Make HTTP request with retry logic"""
        timeout = kwargs.pop("timeout", HTTP_TIMEOUT)
        kwargs.setdefault("timeout", timeout)
        
        for attempt in range(1, self.max_retries + 1):
            try:
                response = self.session.request(method, url, **kwargs)
                
                if response.status_code == 429:
                    wait_time = (2 ** attempt) + random.uniform(0.5, 1.5)
                    time.sleep(wait_time)
                    continue
                
                response.raise_for_status()
                return response.json()
            
            except Exception as e:
                if attempt == self.max_retries:
                    return {"error": str(e)}
                time.sleep(2 ** attempt)
        
        return {"error": "Max retries exceeded"}
