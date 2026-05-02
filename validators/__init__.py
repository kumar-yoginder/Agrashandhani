"""
IOC Validator and Classifier.

Provides functions for validating and classifying Indicators of Compromise (IOCs)
into specific types such as hashes, IP addresses, domains, URLs, CVEs, APT groups,
and other threat intelligence categories.

Author: Agrashandhani
Version: 1.1
"""
import re
from config import IOC_TYPES

# =====================================================
# IOC Type Reference Data
# =====================================================

_MALWARE_FAMILIES = [
    "wannacry", "emotet", "trickbot", "mirai", "locky", "petya", "notpetya",
    "ransomware", "trojan", "botnet", "worm", "virus",
]

_KNOWN_APTS = [
    "apt1", "apt28", "apt29", "apt34", "apt41", "lazarus", "carbanak",
    "turla", "APT", "FIN", "UNC", "WIZARD SPIDER", "WIZARD", "SPIDER",
]

_OPERATING_SYSTEMS = [
    "windows", "linux", "macos", "ios", "android", "unix", "freebsd",
    "ubuntu", "debian", "centos", "fedora", "rhel",
]

_COUNTRIES = [
    "united states", "china", "russia", "uk", "united kingdom", "iran",
    "north korea", "india", "japan", "germany", "france", "brazil",
]

# =====================================================
# Hash Validators
# =====================================================


def validate_md5(value: str) -> bool:
    """Validate MD5 hash (32 hexadecimal characters).

    Args:
        value: String to validate.

    Returns:
        True if value is a valid MD5 hash, False otherwise.
    """
    return bool(re.fullmatch(r"[a-fA-F0-9]{32}", value.strip()))


def validate_sha1(value: str) -> bool:
    """Validate SHA1 hash (40 hexadecimal characters).

    Args:
        value: String to validate.

    Returns:
        True if value is a valid SHA1 hash, False otherwise.
    """
    return bool(re.fullmatch(r"[a-fA-F0-9]{40}", value.strip()))


def validate_sha256(value: str) -> bool:
    """Validate SHA256 hash (64 hexadecimal characters).

    Args:
        value: String to validate.

    Returns:
        True if value is a valid SHA256 hash, False otherwise.
    """
    return bool(re.fullmatch(r"[a-fA-F0-9]{64}", value.strip()))

# =====================================================
# Network Validators
# =====================================================


def validate_ipv4(value: str) -> bool:
    """Validate IPv4 address.

    Verifies that the value matches the IPv4 dotted-decimal notation and
    that each octet is within the valid range (0-255).

    Args:
        value: String to validate.

    Returns:
        True if value is a valid IPv4 address, False otherwise.
    """
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, value.strip()):
        return False
    parts = value.strip().split(".")
    return all(0 <= int(p) <= 255 for p in parts)


def validate_ipv6(value: str) -> bool:
    """Validate IPv6 address.

    Args:
        value: String to validate.

    Returns:
        True if value is a valid IPv6 address, False otherwise.
    """
    pattern = r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
    return bool(re.match(pattern, value.strip()))


def validate_domain(value: str) -> bool:
    """Validate domain name.

    Args:
        value: String to validate.

    Returns:
        True if value is a valid domain name, False otherwise.
    """
    pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value.strip()))


def validate_url(value: str) -> bool:
    """Validate URL.

    Args:
        value: String to validate.

    Returns:
        True if value is a valid URL, False otherwise.
    """
    pattern = r"^https?://[^\s/$.?#].[^\s]*$"
    return bool(re.match(pattern, value.strip(), re.IGNORECASE))

# =====================================================
# Contact and Identifier Validators
# =====================================================


def validate_email(value: str) -> bool:
    """Validate email address.

    Args:
        value: String to validate.

    Returns:
        True if value is a valid email address, False otherwise.
    """
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value.strip()))


def validate_cve(value: str) -> bool:
    """Validate CVE identifier (e.g., CVE-2021-1234).

    Args:
        value: String to validate.

    Returns:
        True if value is a valid CVE identifier, False otherwise.
    """
    pattern = r"^CVE-\d{4}-\d{4,}$"
    return bool(re.match(pattern, value.strip(), re.IGNORECASE))

# =====================================================
# Threat Intelligence Validators
# =====================================================


def validate_malware_family(value: str) -> bool:
    """Check if value matches a known malware family.

    Args:
        value: String to validate.

    Returns:
        True if value is a known malware family, False otherwise.
    """
    value_lower = value.strip().lower()
    return any(family in value_lower for family in _MALWARE_FAMILIES)


def validate_apt(value: str) -> bool:
    """Check if value matches a known APT group.

    Args:
        value: String to validate.

    Returns:
        True if value is a known APT group, False otherwise.
    """
    value_lower = value.strip().lower()
    return any(apt in value_lower for apt in _KNOWN_APTS)


def validate_os(value: str) -> bool:
    """Check if value is an operating system.

    Args:
        value: String to validate.

    Returns:
        True if value is a known operating system, False otherwise.
    """
    value_lower = value.strip().lower()
    return any(os_name in value_lower for os_name in _OPERATING_SYSTEMS)


def validate_country(value: str) -> bool:
    """Check if value is a country name.

    Args:
        value: String to validate.

    Returns:
        True if value is a known country, False otherwise.
    """
    value_lower = value.strip().lower()
    return any(country in value_lower for country in _COUNTRIES)

# =====================================================
# IOC Classification
# =====================================================


def classify(value: str) -> dict:
    """Classify and validate an Indicator of Compromise (IOC).

    Attempts to match the value against known IOC patterns in order of
    specificity (hashes first, then network indicators, etc.).

    Args:
        value: Raw IOC string to classify.

    Returns:
        Dict with keys:
        - ``type`` (str): IOC type (hash_sha256, ip_v4, domain, etc., or unknown).
        - ``value`` (str): The trimmed IOC value.
        - ``description`` (str): Human-readable type description.

    Example:
        >>> result = classify("192.168.1.1")
        >>> result["type"]
        'ip_v4'
    """
    value = value.strip()

    if validate_sha256(value):
        return {
            "type": "hash_sha256",
            "value": value,
            "description": IOC_TYPES["hash_sha256"],
        }

    if validate_sha1(value):
        return {
            "type": "hash_sha1",
            "value": value,
            "description": IOC_TYPES["hash_sha1"],
        }

    if validate_md5(value):
        return {
            "type": "hash_md5",
            "value": value,
            "description": IOC_TYPES["hash_md5"],
        }

    if validate_ipv6(value):
        return {
            "type": "ip_v6",
            "value": value,
            "description": IOC_TYPES["ip_v6"],
        }

    if validate_ipv4(value):
        return {
            "type": "ip_v4",
            "value": value,
            "description": IOC_TYPES["ip_v4"],
        }

    if validate_url(value):
        return {
            "type": "url",
            "value": value,
            "description": IOC_TYPES["url"],
        }

    if validate_domain(value):
        return {
            "type": "domain",
            "value": value,
            "description": IOC_TYPES["domain"],
        }

    if validate_email(value):
        return {
            "type": "email",
            "value": value,
            "description": IOC_TYPES["email"],
        }

    if validate_cve(value):
        return {
            "type": "cve",
            "value": value,
            "description": IOC_TYPES["cve"],
        }

    if validate_apt(value):
        return {
            "type": "apt",
            "value": value,
            "description": IOC_TYPES["apt"],
        }

    if validate_malware_family(value):
        return {
            "type": "malware_family",
            "value": value,
            "description": IOC_TYPES["malware_family"],
        }

    if validate_os(value):
        return {
            "type": "os",
            "value": value,
            "description": IOC_TYPES["os"],
        }

    if validate_country(value):
        return {
            "type": "country",
            "value": value,
            "description": IOC_TYPES["country"],
        }

    return {
        "type": "unknown",
        "value": value,
        "description": IOC_TYPES["unknown"],
    }

