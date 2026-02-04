"""
IOC Validator and Classifier
"""
import re
from config import IOC_TYPES


class IOCValidator:
    """Comprehensive IOC validation and classification"""
    
    # Common malware families and APT groups
    MALWARE_FAMILIES = [
        "wannacry", "emotet", "trickbot", "mirai", "locky", "petya", "notpetya",
        "ransomware", "trojan", "botnet", "worm", "virus"
    ]
    
    KNOWN_APTS = [
        "apt1", "apt28", "apt29", "apt34", "apt41", "lazarus", "carbanak",
        "turla", "APT", "FIN", "UNC", "WIZARD SPIDER", "WIZARD", "SPIDER"
    ]
    
    OPERATING_SYSTEMS = [
        "windows", "linux", "macos", "ios", "android", "unix", "freebsd",
        "ubuntu", "debian", "centos", "fedora", "rhel"
    ]
    
    COUNTRIES = [
        "united states", "china", "russia", "uk", "united kingdom", "iran",
        "north korea", "india", "japan", "germany", "france", "brazil"
    ]
    
    @staticmethod
    def validate_md5(value: str) -> bool:
        """Validate MD5 hash (32 hex chars)"""
        return bool(re.fullmatch(r"[a-fA-F0-9]{32}", value.strip()))
    
    @staticmethod
    def validate_sha1(value: str) -> bool:
        """Validate SHA1 hash (40 hex chars)"""
        return bool(re.fullmatch(r"[a-fA-F0-9]{40}", value.strip()))
    
    @staticmethod
    def validate_sha256(value: str) -> bool:
        """Validate SHA256 hash (64 hex chars)"""
        return bool(re.fullmatch(r"[a-fA-F0-9]{64}", value.strip()))
    
    @staticmethod
    def validate_ipv4(value: str) -> bool:
        """Validate IPv4 address"""
        pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if not re.match(pattern, value.strip()):
            return False
        parts = value.strip().split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    
    @staticmethod
    def validate_ipv6(value: str) -> bool:
        """Validate IPv6 address"""
        pattern = r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
        return bool(re.match(pattern, value.strip()))
    
    @staticmethod
    def validate_domain(value: str) -> bool:
        """Validate domain name"""
        pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        return bool(re.match(pattern, value.strip()))
    
    @staticmethod
    def validate_url(value: str) -> bool:
        """Validate URL"""
        pattern = r"^https?://[^\s/$.?#].[^\s]*$"
        return bool(re.match(pattern, value.strip(), re.IGNORECASE))
    
    @staticmethod
    def validate_email(value: str) -> bool:
        """Validate email address"""
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, value.strip()))
    
    @staticmethod
    def validate_cve(value: str) -> bool:
        """Validate CVE identifier"""
        pattern = r"^CVE-\d{4}-\d{4,}$"
        return bool(re.match(pattern, value.strip(), re.IGNORECASE))
    
    @classmethod
    def validate_malware_family(cls, value: str) -> bool:
        """Check if value is a known malware family"""
        value_lower = value.strip().lower()
        return any(family in value_lower for family in cls.MALWARE_FAMILIES)
    
    @classmethod
    def validate_apt(cls, value: str) -> bool:
        """Check if value is a known APT group"""
        value_lower = value.strip().lower()
        return any(apt in value_lower for apt in cls.KNOWN_APTS)
    
    @classmethod
    def validate_os(cls, value: str) -> bool:
        """Check if value is an operating system"""
        value_lower = value.strip().lower()
        return any(os_name in value_lower for os_name in cls.OPERATING_SYSTEMS)
    
    @classmethod
    def validate_country(cls, value: str) -> bool:
        """Check if value is a country name"""
        value_lower = value.strip().lower()
        return any(country in value_lower for country in cls.COUNTRIES)
    
    @classmethod
    def classify(cls, value: str) -> dict:
        """Classify and validate IOC"""
        value = value.strip()
        
        if cls.validate_sha256(value):
            return {"type": "hash_sha256", "value": value, "description": IOC_TYPES["hash_sha256"]}
        
        if cls.validate_sha1(value):
            return {"type": "hash_sha1", "value": value, "description": IOC_TYPES["hash_sha1"]}
        
        if cls.validate_md5(value):
            return {"type": "hash_md5", "value": value, "description": IOC_TYPES["hash_md5"]}
        
        if cls.validate_ipv6(value):
            return {"type": "ip_v6", "value": value, "description": IOC_TYPES["ip_v6"]}
        
        if cls.validate_ipv4(value):
            return {"type": "ip_v4", "value": value, "description": IOC_TYPES["ip_v4"]}
        
        if cls.validate_url(value):
            return {"type": "url", "value": value, "description": IOC_TYPES["url"]}
        
        if cls.validate_domain(value):
            return {"type": "domain", "value": value, "description": IOC_TYPES["domain"]}
        
        if cls.validate_email(value):
            return {"type": "email", "value": value, "description": IOC_TYPES["email"]}
        
        if cls.validate_cve(value):
            return {"type": "cve", "value": value, "description": IOC_TYPES["cve"]}
        
        if cls.validate_apt(value):
            return {"type": "apt", "value": value, "description": IOC_TYPES["apt"]}
        
        if cls.validate_malware_family(value):
            return {"type": "malware_family", "value": value, "description": IOC_TYPES["malware_family"]}
        
        if cls.validate_os(value):
            return {"type": "os", "value": value, "description": IOC_TYPES["os"]}
        
        if cls.validate_country(value):
            return {"type": "country", "value": value, "description": IOC_TYPES["country"]}
        
        return {"type": "unknown", "value": value, "description": IOC_TYPES["unknown"]}
