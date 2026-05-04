# Agrashandhani CLI Guide

Complete reference for command-line usage of the Agrashandhani OSINT Search Tool.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Basic Commands](#basic-commands)
3. [Source Selection](#source-selection)
4. [IOC Type Filtering](#ioc-type-filtering)
5. [Validation Control](#validation-control)
6. [Batch Processing](#batch-processing)
7. [Output Options](#output-output-options)
8. [Advanced Examples](#advanced-examples)
9. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Installation and Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Configure API keys
cp .env.example .env
# Edit .env with your API keys
```

### First Search

```bash
# Search for a single IOC
python main.py 8.8.8.8

# The tool will:
# 1. Display a banner
# 2. Classify the IOC type
# 3. Search across all configured sources
# 4. Display results
```

---

## Basic Commands

### Single IOC Search

Search for any Indicator of Compromise with automatic type detection:

```bash
# Search for an IP address
python main.py 8.8.8.8

# Search for a domain
python main.py example.com

# Search for a file hash
python main.py abc123def456789...

# Search for a URL
python main.py https://malicious.example.com

# Search for an email
python main.py attacker@example.com

# Search for a CVE
python main.py CVE-2021-1234
```

### Validation Only

Validate and classify an IOC without searching:

```bash
python main.py 8.8.8.8 --validate-only
```

---

## Source Selection

### List Available Sources

Display all configured threat intelligence sources:

```bash
python main.py --list-sources
```

Output:
```
[*] Available Threat Intelligence Sources:
    ────────────────────────────────────────────────────
     1. anyrun               - Interactive malware sandbox
     2. cymru               - IP-to-ASN mapping & hash reputation
     3. filescan            - File analysis & hashing service
     4. greynoise           - Internet scan data & IP context
     5. hybrid_analysis     - Dynamic malware analysis platform
     6. malshare            - Malware sample sharing platform
     7. malwarebazaar       - Malware sample repository (ABUSE.ch)
     8. otx                 - Pulses & threat intelligence correlation
     9. securitytrails      - Domain/IP/DNS intelligence
    10. shodan              - IoT device search engine
    11. threatfox           - Malware/phishing IOC sharing
    12. virustotal          - Multi-hash/IP/Domain scanner (VirusTotal)
    13. xforce_ibm          - IBM X-Force threat intelligence
    ────────────────────────────────────────────────────
```

### Explicit Source Selection

Query only specific sources:

```bash
# Single source
python main.py 8.8.8.8 --sources virustotal

# Multiple sources (comma-separated, no spaces)
python main.py 8.8.8.8 --sources virustotal,shodan,greynoise

# With full query
python main.py 8.8.8.8 --sources virustotal,cymru --verbose
```

### Interactive Source Selection

Let the tool prompt you to choose sources:

```bash
python main.py 8.8.8.8 --sources
```

The tool will display available sources and ask:
```
[?] Select source(s) by number (comma-separated) or 'a' for all, or 'q' to quit: 
```

Examples:
- `1` - Select source #1
- `1,3,5` - Select sources 1, 3, and 5
- `a` - Select all available sources
- `q` - Quit without selecting

---

## IOC Type Filtering

### List Available IOC Types

See all supported IOC types:

```bash
python main.py --list-ioc-types
```

Output:
```
[*] Available IOC Types for Filtering:
    ──────────────────────────────────────────────
    • hash_md5               - MD5 Hash
    • hash_sha1              - SHA1 Hash
    • hash_sha256            - SHA256 Hash
    • ip_v4                  - IPv4 Address
    • ip_v6                  - IPv6 Address
    • domain                 - Domain Name
    • url                    - URL
    • email                  - Email Address
    • cve                    - CVE Identifier
    • apt                    - APT Group
    • malware_family         - Malware Family
    • os                     - Operating System
    • country                - Country Name
    ──────────────────────────────────────────────
```

### Filter by Single Type

Search only for a specific IOC type:

```bash
# Only search if input is IPv4
python main.py 8.8.8.8 --ioc-types ip_v4

# Only search if input is MD5 hash
python main.py abc123def456... --ioc-types hash_md5
```

### Filter by Multiple Types

Allow multiple types:

```bash
# Accept any hash type
python main.py abc123def456... --ioc-types hash_md5,hash_sha1,hash_sha256

# Accept IP addresses
python main.py <value> --ioc-types ip_v4,ip_v6

# Mixed types
python main.py <value> --ioc-types ip_v4,domain,url
```

---

## Validation Control

### Skip Validation

Process indicators without validation (use with caution):

```bash
# Single query without validation
python main.py <value> --skip-validation

# Batch processing without validation
python main.py -c indicators.csv --skip-validation

# Skip validation + filter by type
python main.py <value> --skip-validation --ioc-types ip_v4
```

### Validation Only (No Search)

Validate inputs without querying sources:

```bash
python main.py <value> --validate-only
python main.py -c file.csv --validate-only
```

---

## Batch Processing

### Process CSV File

Search multiple IOCs from a CSV file:

```bash
python main.py -c indicators.csv
```

CSV format (first column is read):
```
8.8.8.8
example.com
abc123def456...
```

### Filter Batch by IOC Type

Process only IOCs of specific types:

```bash
# Only hash indicators
python main.py -c indicators.csv --ioc-types hash_md5,hash_sha1,hash_sha256

# Only IP addresses
python main.py -c indicators.csv --ioc-types ip_v4,ip_v6

# Only domains and URLs
python main.py -c indicators.csv --ioc-types domain,url
```

### Skip Validation in Batch Mode

```bash
python main.py -c indicators.csv --skip-validation

# Combined with type filtering
python main.py -c indicators.csv --skip-validation --ioc-types hash_md5
```

### Cymru Bulk Hash Search

Optimized batch hash lookup using Cymru's bulk API:

```bash
python main.py -c hashes.csv --cymru-bulk
```

This method:
- Batches requests (1000 hashes per batch)
- Uses Cymru's optimized bulk endpoint
- Better performance for large hash files

---

## Output Options

### Verbose JSON Output

Print full JSON details:

```bash
python main.py 8.8.8.8 --verbose
python main.py -c indicators.csv --verbose
```

### Export to Excel

Save results to Excel spreadsheet:

```bash
# Create new Excel file
python main.py 8.8.8.8 --output-excel results.xlsx

# Batch mode to Excel
python main.py -c indicators.csv --output-excel report.xlsx

# Update existing Excel file
python main.py 8.8.8.8 --output-excel report.xlsx --update-excel
```

### Refresh Cache

Force fresh searches (bypass local database):

```bash
python main.py 8.8.8.8 --refresh
python main.py -c indicators.csv --refresh
```

---

## Advanced Examples

### Scenario 1: Complete IP Reconnaissance

```bash
# Interactive source selection for IP
python main.py 8.8.8.8 --sources

# This prompts:
# [?] Select source(s) by number (comma-separated) or 'a' for all, or 'q' to quit:
```

### Scenario 2: Find Related Malware Samples

```bash
python main.py <file_hash> --related
```

This searches OTX for correlated indicators and queries them across sources.

### Scenario 3: Process Hash List with Specific Sources

```bash
python main.py -c hashes.csv --ioc-types hash_md5,hash_sha256 --sources virustotal,malwarebazaar
```

### Scenario 4: Validate and Export to Excel

```bash
python main.py -c indicators.csv \
  --validate-only \
  --output-excel validation_report.xlsx
```

### Scenario 5: Full Reconnaissance with Report

```bash
python main.py -c targets.csv \
  --sources virustotal,shodan,cymru \
  --refresh \
  --output-excel full_report.xlsx
```

### Scenario 6: Process Untrusted Data Safely

```bash
# Skip validation for non-standard indicators
python main.py -c custom_iocs.csv \
  --skip-validation \
  --ioc-types hash_md5 \
  --output-excel results.xlsx
```

### Scenario 7: Find All IPv4s in Mixed Indicators

```bash
python main.py -c mixed_indicators.csv \
  --ioc-types ip_v4 \
  --sources greynoise,shodan
```

---

## Troubleshooting

### No Sources Available

**Issue**: Tool says "No sources configured"

**Solution**: 
```bash
# Check your .env file
cat .env

# Ensure API keys are set
# Edit .env and add missing credentials

# Restart the tool
python main.py --list-sources
```

### Unknown Source Error

**Issue**: "Unknown source 'name'"

**Solution**:
```bash
# List available sources
python main.py --list-sources

# Use correct source name (case-sensitive)
python main.py 8.8.8.8 --sources virustotal  # Correct
# Not: python main.py 8.8.8.8 --sources VirusTotal
```

### IOC Type Mismatch

**Issue**: "IOC type does not match requested types"

**Solution**:
```bash
# Check what type was detected
python main.py <value> --validate-only

# Use correct type or remove filter
python main.py <value> --ioc-types <detected_type>
```

### CSV File Not Found

**Issue**: "No IOCs found in CSV file"

**Solution**:
```bash
# Verify file exists
ls -la indicators.csv

# Check file format (first column should have IOCs)
head indicators.csv

# Ensure file path is correct
python main.py -c ./path/to/indicators.csv
```

### Invalid CSV Format

**Issue**: "IOCs are being skipped"

**Solution**:
```bash
# CSV should have IOCs in first column
# Correct format:
# 8.8.8.8
# example.com
# abc123...

# Or CSV with headers:
# indicator
# 8.8.8.8
# example.com

# Check for encoding issues (use UTF-8)
file indicators.csv
```

---

## Command Reference

| Command | Description |
|---------|-------------|
| `python main.py <ioc>` | Single IOC search |
| `python main.py -c file.csv` | Batch processing |
| `python main.py <ioc> --sources <names>` | Select sources |
| `python main.py <ioc> --sources` | Interactive source selection |
| `python main.py <ioc> --ioc-types <types>` | Filter by IOC type |
| `python main.py <ioc> --skip-validation` | Skip validation |
| `python main.py <ioc> --validate-only` | Validation only |
| `python main.py <ioc> --related` | Find correlated indicators |
| `python main.py <ioc> --refresh` | Bypass cache |
| `python main.py <ioc> --output-excel file.xlsx` | Export to Excel |
| `python main.py <ioc> --verbose` | JSON output |
| `python main.py --list-sources` | List all sources |
| `python main.py --list-ioc-types` | List IOC types |
| `python main.py -h` | Show help message |

---

## Notes

- **Source Availability**: Only sources with configured API keys are available
- **Cache**: Results are cached in local database unless `--refresh` is used
- **Rate Limiting**: Some sources have rate limits; check their documentation
- **CSV Format**: Tool reads first column; extra columns are ignored
- **Interactive Mode**: Leave `--sources` blank to enable interactive selection

---

For more information, see [INTEGRATION_AND_DEVELOPMENT.md](INTEGRATION_AND_DEVELOPMENT.md)
