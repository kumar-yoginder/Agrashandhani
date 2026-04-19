"""
AlienVault OTX (Open Threat Exchange) Source

Queries the AlienVault OTX API for threat intelligence indicators.
Reference: https://otx.alienvault.com/
"""

from typing import Dict, Any
from sources.base import Source
from clients import RateLimitedClient
from config import OTX_API_KEY, OTX_API_URL


class OTXSource(Source):
    """
    AlienVault OTX (Open Threat Exchange) API source for threat intelligence.
    
    Supported IOC types:
    - hash_md5: MD5 file hash
    - hash_sha1: SHA1 file hash
    - hash_sha256: SHA256 file hash
    - ip_v4: IPv4 address
    - ip_v6: IPv6 address
    - domain: Domain name
    - url: URL
    
    Features:
    - Multi-type indicator lookups (hashes, IPs, domains, URLs)
    - Detailed threat analysis and passive DNS data
    - Community threat intelligence (pulses)
    - CVE correlation
    - Reputation scoring
    - ENHANCED - Multi-section hash querying:
      * Malware family identification and detection counts
      * APT group attribution derived from pulse metadata
      * Correlated/related file hash extraction
    
    Enhanced Hash Analysis:
    - Queries 4 API sections per hash (general, malware, analysis, related)
    - Extracts malware family names and detection frequencies
    - Identifies associated APT groups from pulse names and tags
    - Compiles list of correlated/related file hashes (limited to top 20)
    
    Rate Limits:
    - Free tier: 600 requests/hour (~150 hashes with multi-section queries)
    - Premium tiers: Higher limits based on subscription
    - Implements exponential backoff for rate limiting
    - Uses sequential requests to ensure stability
    
    Response Structure:
    ```json
    {
      "query_status": "ok",
      "source": "otx",
      "data": {
        "indicator": "...",
        "type": "file",
        "malware_family": {
          "names": ["Trojan.Generic", "Win32.Backdoor"],
          "detection_count": 45,
          "sample_count": 12
        },
        "apt_groups": {
          "attributed": ["APT28", "Lazarus"],
          "sources": ["pulse: APT28 Activity", "tag: lazarus"]
        },
        "correlated_hashes": {
          "related_files": ["hash1", "hash2", ...],
          "total_count": 5
        },
        "pulse_info": {...},
        "reputation": {...},
        ...
      }
    }
    ```
    
    Reference:
    - https://otx.alienvault.com/ (OTX platform)
    - https://otx.alienvault.com/api (API documentation)
    - Get API key: https://otx.alienvault.com/account/profile
    """
    
    def __init__(self):
        """Initialize OTX source with API key from config."""
        super().__init__("otx")
        self.api_key = OTX_API_KEY
        self.api_url = OTX_API_URL
    
    def query(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """
        Query OTX API for threat intelligence.
        
        Args:
            ioc_type: Type of IOC (hash_md5, hash_sha1, hash_sha256, ip_v4, ip_v6, domain, url)
            value: The IOC value to search for
            
        Returns:
            Normalized response dictionary with query_status, source, and data
        """
        if not self.api_key:
            return self._error_response(
                "API key not configured",
                "OTX API key not set. Get key from https://otx.alienvault.com/account/profile"
            )
        
        # Map IOC type to OTX endpoint
        ioc_map = {
            "hash_md5": "file",
            "hash_sha1": "file",
            "hash_sha256": "file",
            "ip_v4": "IPv4",
            "ip_v6": "IPv6",
            "domain": "domain",
            "url": "url"
        }
        
        if ioc_type not in ioc_map:
            return self._error_response(
                f"Unsupported IOC type: {ioc_type}",
                f"OTX supports: {', '.join(ioc_map.keys())}"
            )
        
        endpoint_type = ioc_map[ioc_type]
        
        # Query based on IOC type
        if ioc_type.startswith("hash_"):
            return self._query_hash(value, endpoint_type)
        elif ioc_type.startswith("ip_"):
            return self._query_indicator(endpoint_type, value, "reputation")
        elif ioc_type == "domain":
            return self._query_indicator(endpoint_type, value, "general")
        elif ioc_type == "url":
            return self._query_indicator(endpoint_type, value, "general")
        
        return self._error_response(
            "Query routing failed",
            f"Unable to route query for IOC type: {ioc_type}"
        )
    
    def _query_hash(self, hash_value: str, endpoint_type: str) -> Dict[str, Any]:
        """
        Query OTX for comprehensive file hash information.
        
        Queries multiple sections sequentially:
        - /general: General file information
        - /malware: Malware family and AV detections
        - /analysis: Detailed analysis and related indicators
        - /related: Correlated/related files
        
        Args:
            hash_value: The hash to query
            endpoint_type: Type of endpoint (file, IPv4, domain, url)
            
        Returns:
            Normalized response with enriched file analysis data including:
            - Malware families
            - APT group attribution
            - Correlated hashes
        """
        try:
            headers = {
                "X-OTX-API-KEY": self.api_key,
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Content-Type": "application/json"
            }
            
            otx_client = RateLimitedClient(max_retries=3)
            
            # Query general section (base information)
            general_response = otx_client.request(
                "GET",
                f"{self.api_url}/indicators/{endpoint_type}/{hash_value}/general",
                headers=headers,
                timeout=10
            )
            
            if general_response is None:
                return self._error_response(
                    "API request failed",
                    "Connection error or timeout querying OTX general section"
                )
            
            # Check for error responses
            if isinstance(general_response, dict):
                if general_response.get("error") or general_response.get("status") == "error":
                    error_msg = general_response.get("error", general_response.get("message", "Unknown error"))
                    
                    if "not found" in str(error_msg).lower():
                        return self._success_response({"found": False, "message": error_msg})
                    
                    return self._error_response(
                        f"OTX API error: {error_msg}",
                        "Hash not found or API limit exceeded"
                    )
            
            # Initialize enriched data with general response
            enriched_data = general_response if isinstance(general_response, dict) else {}
            
            # Query malware section sequentially (malware family info)
            malware_data = otx_client.request(
                "GET",
                f"{self.api_url}/indicators/{endpoint_type}/{hash_value}/malware",
                headers=headers,
                timeout=10
            )
            
            # Query analysis section (correlated indicators)
            analysis_data = otx_client.request(
                "GET",
                f"{self.api_url}/indicators/{endpoint_type}/{hash_value}/analysis",
                headers=headers,
                timeout=10
            )
            
            # Query related section (related files)
            related_data = otx_client.request(
                "GET",
                f"{self.api_url}/indicators/{endpoint_type}/{hash_value}/related",
                headers=headers,
                timeout=10
            )
            
            # Extract enriched information from sections
            enriched_data["malware_family"] = self._extract_malware_family(malware_data)
            enriched_data["correlated_hashes"] = self._get_correlated_hashes(related_data, analysis_data)
            enriched_data["apt_groups"] = self._extract_apt_groups(enriched_data.get("pulse_info", {}))
            
            return self._normalize_response(enriched_data)
        
        except Exception as e:
            return self._error_response(
                f"Query failed: {str(e)}",
                "Error querying OTX API"
            )
    
    def _query_indicator(self, indicator_type: str, value: str, section: str = "general") -> Dict[str, Any]:
        """
        Query OTX for indicator information (IP, domain, URL, etc.).
        
        Endpoint: GET /indicators/{type}/{value}/{section}
        
        Args:
            indicator_type: Type of indicator (IPv4, IPv6, domain, url)
            value: The indicator value
            section: API section (general, reputation, geo, malware, etc.)
            
        Returns:
            Normalized response with indicator details
        """
        try:
            url = f"{self.api_url}/indicators/{indicator_type}/{value}/{section}"
            
            headers = {
                "X-OTX-API-KEY": self.api_key,
                "User-Agent": "Agrashandhani/1.0 (OSINT Tool)",
                "Content-Type": "application/json"
            }
            
            otx_client = RateLimitedClient(max_retries=3)
            response = otx_client.request(
                "GET",
                url,
                headers=headers,
                timeout=10
            )
            
            if response is None:
                return self._error_response(
                    "API request failed",
                    "Connection error or timeout querying OTX"
                )
            
            # Check for error responses
            if isinstance(response, dict):
                if response.get("error") or response.get("status") == "error":
                    error_msg = response.get("error", response.get("message", "Unknown error"))
                    
                    if "not found" in str(error_msg).lower():
                        return self._success_response({"found": False, "message": error_msg})
                    
                    return self._error_response(
                        f"OTX API error: {error_msg}",
                        "Indicator not found or invalid"
                    )
                
                return self._normalize_response(response)
            
            return self._error_response(
                "Unexpected response format",
                "OTX returned non-JSON response"
            )
        
        except Exception as e:
            return self._error_response(
                f"Query failed: {str(e)}",
                "Error querying OTX API"
            )
    
    def _extract_malware_family(self, malware_data: Any) -> Dict[str, Any]:
        """
        Extract malware family information from OTX malware section.
        
        Args:
            malware_data: Response from /malware endpoint
            
        Returns:
            Dictionary containing malware family names and detection count
        """
        if not malware_data or not isinstance(malware_data, dict):
            return {}
        
        # Check for errors in malware data
        if malware_data.get("error") or "not found" in str(malware_data.get("message", "")).lower():
            return {}
        
        malware_info = {}
        
        # Extract malware names/families
        if "names" in malware_data and isinstance(malware_data["names"], list):
            malware_info["names"] = malware_data["names"][:10]  # Limit to top 10
        
        # Extract detection count
        if "count" in malware_data:
            malware_info["detection_count"] = malware_data["count"]
        
        # Extract sample information if available
        if "samples" in malware_data and isinstance(malware_data["samples"], list):
            malware_info["sample_count"] = len(malware_data["samples"])
        
        # Add data from data field (OTX response structure)
        if "data" in malware_data and isinstance(malware_data["data"], (list, dict)):
            if isinstance(malware_data["data"], list):
                # Extract unique family names from data array
                families = set()
                for item in malware_data["data"][:20]:  # Limit to 20 items
                    if isinstance(item, dict) and "name" in item:
                        families.add(item["name"])
                if families and not malware_info.get("names"):
                    malware_info["names"] = list(families)
        
        return malware_info
    
    def _extract_apt_groups(self, pulse_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract APT group attribution from OTX pulse information.
        
        Args:
            pulse_info: Pulse information dictionary from OTX response
            
        Returns:
            Dictionary containing attributed APT groups and their sources
        """
        if not pulse_info or not isinstance(pulse_info, dict):
            return {}
        
        apt_groups = set()
        sources = []
        
        # Common APT group name fragments and mappings
        apt_mappings = {
            "apt": "APT",
            "lazarus": "Lazarus",
            "fancy bear": "Fancy Bear (APT28)",
            "apt28": "APT28",
            "cozy bear": "Cozy Bear (APT29)",
            "apt29": "APT29",
            "thrip": "THRIP",
            "fin": "FIN",
            "group": "Group",
            "apt-c": "APT-C",
            "hurricane": "Hurricane Panda",
            "panda": "Panda",
            "hydra": "Hydra",
            "sidewinder": "SideWinder",
        }
        
        # Extract from pulses array
        if "pulses" in pulse_info and isinstance(pulse_info["pulses"], list):
            for pulse in pulse_info["pulses"]:
                if isinstance(pulse, dict):
                    # Check pulse name for APT indicators
                    pulse_name = pulse.get("name", "").lower()
                    for keyword, normalized in apt_mappings.items():
                        if keyword in pulse_name:
                            apt_groups.add(normalized)
                            sources.append(f"pulse: {pulse.get('name', 'Unknown')}")
                            break
                    
                    # Check tags for APT group references
                    if "tags" in pulse and isinstance(pulse["tags"], list):
                        for tag in pulse["tags"]:
                            tag_lower = str(tag).lower()
                            for keyword, normalized in apt_mappings.items():
                                if keyword in tag_lower:
                                    apt_groups.add(normalized)
                                    sources.append(f"tag: {tag}")
                                    break
                    
                    # Check for adversary field
                    if "adversary" in pulse and pulse["adversary"]:
                        apt_groups.add(pulse["adversary"])
                        sources.append(f"adversary: {pulse['adversary']}")
        
        # Check for malware tag (common pattern)
        if "tags" in pulse_info and isinstance(pulse_info["tags"], list):
            for tag in pulse_info["tags"]:
                tag_lower = str(tag).lower()
                if any(keyword in tag_lower for keyword in apt_mappings.keys()):
                    for keyword, normalized in apt_mappings.items():
                        if keyword in tag_lower:
                            apt_groups.add(normalized)
                            sources.append(f"global_tag: {tag}")
        
        result = {}
        if apt_groups:
            result["attributed"] = sorted(list(apt_groups))
        if sources:
            result["sources"] = list(set(sources))[:10]  # Limit to 10 unique sources
        
        return result
    
    def _get_correlated_hashes(self, related_data: Any, analysis_data: Any) -> Dict[str, Any]:
        """
        Extract correlated/related file hashes from OTX.
        
        Args:
            related_data: Response from /related endpoint
            analysis_data: Response from /analysis endpoint
            
        Returns:
            Dictionary containing correlated hash IDs and count
        """
        correlated_hashes = set()
        
        # Extract from related section
        if related_data and isinstance(related_data, dict):
            if "related" in related_data and isinstance(related_data["related"], list):
                for item in related_data["related"]:
                    if isinstance(item, dict):
                        # Try to extract hash from various possible fields
                        for field in ["hash", "indicator", "sha256", "md5", "sha1", "id"]:
                            if field in item:
                                correlated_hashes.add(str(item[field]))
                                break
            
            # Try data field structure
            if "data" in related_data and isinstance(related_data["data"], list):
                for item in related_data["data"][:30]:  # Limit to 30 items
                    if isinstance(item, dict):
                        for field in ["hash", "indicator", "sha256", "md5", "sha1"]:
                            if field in item:
                                correlated_hashes.add(str(item[field]))
                                break
        
        # Extract from analysis section if available
        if analysis_data and isinstance(analysis_data, dict):
            if "results" in analysis_data and isinstance(analysis_data["results"], list):
                for result in analysis_data["results"][:20]:
                    if isinstance(result, dict) and "hash" in result:
                        correlated_hashes.add(str(result["hash"]))
            
            if "data" in analysis_data and isinstance(analysis_data["data"], list):
                for item in analysis_data["data"][:20]:
                    if isinstance(item, dict) and "hash" in item:
                        correlated_hashes.add(str(item["hash"]))
        
        result = {}
        if correlated_hashes:
            result["related_files"] = sorted(list(correlated_hashes))[:20]  # Limit to 20
            result["total_count"] = len(correlated_hashes)
        
        return result
    
    def _normalize_response(self, data: Any) -> Dict[str, Any]:
        """
        Normalize OTX API response to standard format.
        
        Args:
            data: Raw API response data
            
        Returns:
            Normalized response dictionary
        """
        if isinstance(data, dict):
            # Extract key threat indicators from OTX response
            normalized_data = {
                "indicator": data.get("indicator"),
                "type": data.get("type"),
                "pulse_info": data.get("pulse_info"),
                "reputation": data.get("reputation"),
                "ali_as": data.get("ali_as"),
                "country_code": data.get("country_code"),
                "country_name": data.get("country_name"),
                "validation": data.get("validation"),
                "asn": data.get("asn"),
                "whois": data.get("whois"),
                "sections": data.get("sections", []),
                "malware_family": data.get("malware_family"),
                "correlated_hashes": data.get("correlated_hashes"),
                "apt_groups": data.get("apt_groups"),
                "raw_data": data
            }
            
            # Filter out None values
            normalized_data = {k: v for k, v in normalized_data.items() if v is not None}
            
            return self._success_response(normalized_data)
        
        return self._success_response({"raw_data": data})
    
    def _success_response(self, data: Any) -> Dict[str, Any]:
        """Create a success response in standard format."""
        return {
            "query_status": "ok",
            "source": "otx",
            "data": data
        }
    
    def _error_response(self, message: str, details: str = "") -> Dict[str, Any]:
        """Create an error response in standard format."""
        return {
            "query_status": "error",
            "source": "otx",
            "data": {
                "error": message,
                "details": details
            }
        }
