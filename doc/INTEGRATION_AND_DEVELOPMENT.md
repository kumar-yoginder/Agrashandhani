# Agrashandhani Integration and Contribution Guide

This document provides detailed instructions on how to integrate with the Agrashandhani codebase and how to extend its capabilities by adding new threat intelligence sources.

---

## Table of Contents

1. [Overview](#overview)
2. [Getting Started](#getting-started)
   - [Prerequisites](#prerequisites)
   - [Configuration](#configuration)
3. [Integration](#integration)
   - [CLI Usage](#cli-usage)
   - [Programmatic Integration](#programmatic-integration)
4. [Architecture Overview](#architecture-overview)
5. [Adding New Sources](#adding-new-sources)
   - [Step 1: Create the Source Class](#step-1-create-the-source-class)
   - [Step 2: Define API Configuration](#step-2-define-api-configuration)
   - [Step 3: Register the Source](#step-3-register-the-source)
   - [Step 4: Update Source Manager](#step-4-update-source-manager)
6. [Best Practices](#best-practices)

---

## Overview

Agrashandhani is a modular OSINT search tool designed to query Indicators of Compromise (IOCs) across multiple threat intelligence platforms. It features an extensible architecture, parallelized scanning, and a standardized response format.

## Getting Started

### Prerequisites

- Python 3.8+
- Required packages (install via `pip install -r requirements.txt`)

### Configuration

The tool uses environment variables for configuration. Create a `.env` file in the root directory based on `.env.example`:

```bash
cp .env.example .env
```

Edit the `.env` file to include your API keys:
- `VT_API_KEY`: VirusTotal API Key
- `OTX_API_KEY`: AlienVault OTX API Key
- ... and others as needed.

---

## Integration

### CLI Usage

The primary entry point for the tool is `main.py`. The tool displays a banner at startup and supports multiple modes of operation.

#### Basic Usage

**Single IOC Search**:
```bash
python main.py 8.8.8.8
python main.py <hash>
python main.py example.com
```

**Batch Processing from CSV**:
```bash
python main.py -c samples/iocs.csv
```

**Find Related/Correlated Indicators (OTX)**:
```bash
python main.py <hash> --related
```

#### Advanced Options

**Source Selection**:
```bash
# Specify sources explicitly (comma-separated)
python main.py 8.8.8.8 --sources virustotal,shodan

# Interactive source selection (prompts user to choose)
python main.py 8.8.8.8 --sources

# List available sources
python main.py --list-sources
```

**IOC Type Filtering**:
```bash
# Search only for specific IOC types
python main.py <value> --ioc-types hash_md5,hash_sha256
python main.py 8.8.8.8 --ioc-types ip_v4

# List all available IOC types
python main.py --list-ioc-types
```

**Validation Control**:
```bash
# Skip IOC validation (use with caution)
python main.py <value> --skip-validation

# Only validate without searching
python main.py <value> --validate-only

# Skip validation in batch mode
python main.py -c file.csv --skip-validation
```

**Bulk Processing**:
```bash
# Cymru bulk hash search for multiple hashes
python main.py -c hashes.csv --cymru-bulk

# Filter batch by IOC type
python main.py -c file.csv --ioc-types hash_md5

# Bypass cache (force fresh search)
python main.py 8.8.8.8 --refresh
python main.py -c file.csv --refresh
```

**Output Options**:
```bash
# Save to Excel
python main.py <value> --output-excel results.xlsx

# Append to existing Excel file
python main.py <value> --output-excel results.xlsx --update-excel

# Verbose JSON output
python main.py <value> --verbose
```

#### Available IOC Types
- `hash_md5` - MD5 Hash (32 hex characters)
- `hash_sha1` - SHA1 Hash (40 hex characters)
- `hash_sha256` - SHA256 Hash (64 hex characters)
- `ip_v4` - IPv4 Address
- `ip_v6` - IPv6 Address
- `domain` - Domain Name
- `url` - Full URL
- `email` - Email Address
- `cve` - CVE Identifier (CVE-YYYY-####)
- `apt` - APT Group Name
- `malware_family` - Malware Family Name
- `country` - Country Name
- `os` - Operating System
- `unknown` - Unknown/Unclassified

#### Available Threat Intelligence Sources
The tool supports queries to multiple sources. Available sources are shown with:
```bash
python main.py --list-sources
```

Current sources include:
- **VirusTotal** - Multi-hash/IP/Domain scanner
- **MalwareBazaar** - Malware sample repository
- **Hybrid Analysis** - Dynamic malware analysis
- **MalShare** - Malware sample sharing
- **OTX (AlienVault)** - Threat intelligence pulses
- **Cymru** - IP-to-ASN mapping & hash reputation
- **AnyRun** - Interactive malware sandbox
- **SecurityTrails** - Domain/IP/DNS intelligence
- **Shodan** - IoT device search engine
- **GreyNoise** - Internet scan data & IP context
- **X-Force (IBM)** - IBM X-Force threat intelligence
- **FileScan** - File analysis & hashing service
- **ThreatFox** - Malware/phishing IOC sharing

#### Example Workflows

**Search multiple sources for a file hash**:
```bash
python main.py abc123def456... --sources virustotal,malwarebazaar,hybrid_analysis
```

**Interactive source selection**:
```bash
python main.py 8.8.8.8 --sources
# Tool prompts: "Select source(s) by number (comma-separated) or 'a' for all, or 'q' to quit:"
```

**Process only MD5 and SHA256 hashes from batch**:
```bash
python main.py -c indicators.csv --ioc-types hash_md5,hash_sha256
```

**Validate CSV without searching (no validation)**:
```bash
python main.py -c indicators.csv --validate-only --skip-validation
```

**Find related malware samples**:
```bash
python main.py <file_hash> --related
```

**Export batch results to Excel**:
```bash
python main.py -c indicators.csv --output-excel threat_report.xlsx
```

### Programmatic Integration

To use the OSINT engine within your own Python projects, you can import and call `run_osint_engine`.

```python
from engine import run_osint_engine

# Query a single IOC
result = run_osint_engine("8.8.8.8")

# Accessing results
if result.get("sources"):
    for source, data in result["sources"].items():
        if data.get("present"):
            print(f"Found in {source}: {data['data']}")

# Query specific sources only
result = run_osint_engine("8.8.8.8", sources=["virustotal", "shodan"])

# Bypass cache
result = run_osint_engine("8.8.8.8", refresh=True)

# Batch mode
result = run_osint_engine("8.8.8.8", batch_mode=True)
```

---

## Architecture Overview

- `main.py`: CLI entry point.
- `engine/`: Contains the orchestration logic and parallel execution engine.
- `sources/`: Individual source implementations (e.g., VirusTotal, OTX).
- `validators/`: IOC classification and validation logic.
- `database/`: Local cache management (JSON/MongoDB/Postgres).
- `utility/`: Support tools for source management and diagnostics.

---

## Adding New Sources

Follow these steps to add a new threat intelligence source:

### Step 1: Create the Source Class

Create a new file in `sources/your_source.py`. Inherit from the `Source` base class in `sources/base.py`.

```python
import logging
from typing import Dict, Any
from sources.base import Source
from config import YOUR_SOURCE_URL, YOUR_SOURCE_KEY

logger = logging.getLogger(__name__)

class YourSource(Source):
    def __init__(self) -> None:
        # Initialize with a unique name
        super().__init__("your_source")
        self.api_url = YOUR_SOURCE_URL
        self.api_key = YOUR_SOURCE_KEY

    def query(self, ioc_type: str, value: str) -> Dict[str, Any]:
        if not self.api_key:
            return self._error_response("API key missing")

        # Implement your API logic here
        try:
            # Example request using the built-in rate-limited client
            endpoint = f"{self.api_url}/search/{value}"
            headers = {"Authorization": f"Bearer {self.api_key}"}
            
            response = self.client.request("GET", endpoint, headers=headers)
            
            # Standardize the response
            if response.get("status") == "success":
                return self._success_response(response["data"])
            else:
                return self._not_found_response()
                
        except Exception as exc:
            return self._error_response(f"Unexpected error: {exc}")
```

### Step 2: Define API Configuration

Add the new API endpoint and key environment variable to `config.py`:

```python
# API KEYS
YOUR_SOURCE_KEY = os.getenv("YOUR_SOURCE_API_KEY", "")

# API ENDPOINTS
YOUR_SOURCE_URL = "https://api.your-source.com/v1"
```

### Step 3: Register the Source

1. **Import and instantiate** in `sources/__init__.py`:

```python
from sources.your_source import YourSource

# Add to _SOURCE_CREDENTIALS for auto-enabling
_SOURCE_CREDENTIALS["your_source"] = YOUR_SOURCE_KEY

# Add to _source_instances
_source_instances["your_source"] = YourSource()

# Define supported IOC types
_SOURCE_SUPPORTED_TYPES["your_source"] = {"ip_v4", "domain", "hash_sha256"}
```

### Step 4: Update Source Manager (Optional)

Add your source to `utility/sources_manager.py` to support credential diagnostics:

```python
SOURCE_CREDENTIALS = {
    # ...
    "your_source": {"env_vars": ["YOUR_SOURCE_API_KEY"], "name": "Your Source Name"},
}
```

---

## Best Practices

1. **Standardized Responses**: Always use the helper methods `self._success_response()`, `self._not_found_response()`, and `self._error_response()` provided by the base `Source` class.
2. **Rate Limiting**: Use `self.client.request()` which uses a shared `RateLimitedClient` to respect API limits.
3. **IOC Classification**: The engine automatically classifies IOCs. Ensure your source only processes supported types as defined in `_SOURCE_SUPPORTED_TYPES`.
4. **Error Handling**: Log exceptions gracefully within your source's `query` method but always return a standardized error dictionary.
