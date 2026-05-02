# Agrashandhani: The OSINT Tool

**अग्रशंधनी** (leading inquiry) - A comprehensive OSINT aggregation platform for threat intelligence research

Agrashandhani searches IOCs (hashes, IPs, domains, URLs, CVEs, emails, etc.) across multiple threat-intel sources, caches results locally with timestamps, and supports batch processing from CSV files. Built for security professionals who need fast, reliable threat intelligence at scale.

## Quickstart

1. Create and activate a Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run a single query:

```bash
python main.py "44d88612fea8a8f36de82e1278abb02f"
```

4. Run a CSV batch (first column or one IOC per line, optional header):

```bash
python main.py -c sample_iocs.csv
```

## CLI Options

- `query` — Single IOC to search
- `-c, --csv` — Read IOCs from CSV file
- `-t, --type` — Force IOC type (`hash`, `ip`, `auto`)
- `-s, --sources` — Comma-separated source list (e.g. `virustotal,malwarebazaar`)
- `-v, --verbose` — Output JSON-formatted results
- `-r, --refresh` — Force search and bypass cache
- `-l, --list-sources` — List available sources
- `--validate-only` — Validate inputs without searching
- `--related` — Search for correlated/related indicators from OTX (find related hashes/IPs)
- `--cymru-bulk` — Use Cymru bulk hash search API with CSV file

## Documentation

For detailed information on how to integrate this tool into your own projects or how to contribute by adding new threat intelligence sources, please refer to:

- [Integration and Development Guide](doc/INTEGRATION_AND_DEVELOPMENT.md)

## Key Features

✅ **Multi-Source Threat Intelligence** - Query 11 active sources (VirusTotal, MalwareBazaar, Hybrid Analysis, MalShare, AlienVault OTX, SecurityTrails, Shodan, GreyNoise, Team Cymru, Any.run, IBM X-Force) simultaneously  
✅ **Intelligent Source Management** - Sources are automatically enabled/disabled based on credential availability in `.env`  
✅ **Correlated Indicator Search** - Use `--related` flag to find related/correlated hashes and APT groups from OTX  
✅ **Intelligent Caching** - Timestamped local JSON database prevents redundant API calls  
✅ **14+ IOC Types** - MD5/SHA1/SHA256 hashes, IPv4/IPv6, domains, URLs, emails, CVEs, APTs, malware families, OS, countries  
✅ **Batch Processing** - Process CSV files with automatic header detection and type validation  
✅ **Bulk Hash Search** - Use Cymru's optimized bulk API for efficient hash reputation lookups (1000 hashes per batch)
✅ **Modular Architecture** - Clean, extensible design for adding new sources  
✅ **Smart Rate Limiting** - Built-in exponential backoff and retry logic  
✅ **Multiple Output Formats** - Human-readable or verbose JSON for integration  
✅ **Validation Mode** - Test IOC format without making API calls

## Supported Sources

Agrashandhani integrates **11 threat intelligence sources**. Each source is queried only for IOC types it supports.

**Sources are automatically enabled/disabled at runtime based on credential availability in .env** — if credentials are missing or empty, the source is skipped.

| Source | Key Name | Hashes (MD5/SHA1/SHA256) | IPv4 | IPv6 | Domain | URL | Notes |
|---|---|:---:|:---:|:---:|:---:|:---:|---|
| **VirusTotal** | `virustotal` | ✅ | ✅ | ✅ | ✅ | ✅ | 70+ AV engines, file/network reputation |
| **MalwareBazaar** | `malwarebazaar` | ✅ | | | | | Malware samples, YARA rules, malware families |
| **Hybrid Analysis** | `hybrid_analysis` | ✅ | ✅ | | ✅ | ✅ | Sandbox analysis, file behavior, network indicators |
| **MalShare** | `malshare` | ✅ | | | | | Malware sample database, analysis results |
| **AlienVault OTX** | `otx` | ✅ | ✅ | ✅ | ✅ | ✅ | Threat pulses, passive DNS, CVE correlation, **correlated indicators** |
| **SecurityTrails** | `securitytrails` | | ✅ | | ✅ | | DNS records, WHOIS, subdomains, IP-to-hostname |
| **Shodan** | `shodan` | | ✅ | | ✅ | | Open ports, services, banners, CVEs, DNS records |
| **GreyNoise** | `greynoise` | | ✅ | | | | IP classification: benign / malicious / noise |
| **Team Cymru** | `cymru` | ✅ | ✅ | | | | Malware hash reputation, bulk hash search API |
| **Any.run** | `anyrun` | ✅ | ✅ | | ✅ | ✅ | Interactive malware analysis, detonation results |
| **IBM X-Force Exchange** | `xforce_ibm` | ✅ | ✅ | | | | Threat intelligence, vulnerabilities, ransomware |

### What each source searches for

#### File Hash Searches (MD5 · SHA1 · SHA256)
| Source | What you get |
|---|---|
| VirusTotal | Antivirus detections from 70+ engines, file metadata, signatures |
| MalwareBazaar | Malware sample details, YARA rule matches, malware family attribution |
| Hybrid Analysis | Sandbox execution report, behavior analysis, file relationships |
| MalShare | Sample details from community-uploaded malware corpus |
| AlienVault OTX | File reputation, related threat pulses, correlated hashes, and adversary groups |



#### IP Address Searches (IPv4 · IPv6)
| Source | What you get |
|---|---|
| VirusTotal | IP reputation, WHOIS data, passive DNS, ASN information |
| AlienVault OTX | IP reputation, geolocation, passive DNS, related pulses |
| Hybrid Analysis | Network indicators associated with the IP |
| SecurityTrails | Reverse DNS, hostname associations, historical DNS records |
| Shodan | Open ports, running services, banners, CVEs, geolocation |
| GreyNoise | IP classification (benign / malicious / background noise), tags |

#### Domain Searches
| Source | What you get |
|---|---|
| VirusTotal | Domain reputation, DNS records, WHOIS, related URLs |
| AlienVault OTX | Domain reputation, passive DNS, associated malware pulses |
| Hybrid Analysis | Domain network indicators from sandbox submissions |
| SecurityTrails | Current/historical DNS records, WHOIS, subdomain enumeration |
| Shodan | DNS records, subdomains, associated IP addresses |

#### URL Searches
| Source | What you get |
|---|---|
| VirusTotal | URL reputation, file downloads, redirects, AV detections |
| AlienVault OTX | URL threat analysis, related threat pulses |
| Hybrid Analysis | URL behavior, network activity from sandbox |

## Adding a New Threat Intelligence Source

Agrashandhani's modular architecture makes it easy to integrate additional threat intelligence providers:

1. Create `sources/newsource.py` with a class inheriting from `base.Source`:
```python
from sources.base import Source
from clients import RateLimitedClient
from config import YOUR_API_KEY

class NewSource(Source):
    def __init__(self):
        super().__init__("newsource")
        self.client = RateLimitedClient()
    
    def query(self, ioc_type, value):
        # Your query implementation
        pass
```

2. Register in `sources/__init__.py`:
```python
from sources.newsource import NewSource
SOURCES["newsource"] = NewSource()
```

## Project Layout

```
Agrashandhani/
├── main.py                      # CLI entry point
├── requirements.txt             # Python dependencies
├── .env                         # API keys (not in repo)
├── .env.example                 # Configuration template
├── data/
│   ├── threat_intel_db.json     # Local cache with timestamps
│   └── malware_families_mapping.json
├── sample_iocs.csv              # Example batch file
│
├── config.py                    # Configuration & constants
├── clients.py                   # RateLimitedClient with retry logic
│
├── sources/                     # Threat intelligence source implementations
│   ├── __init__.py              # Source registry & factory
│   ├── base.py                  # Abstract Source class
│   ├── virustotal.py            # VirusTotal
│   ├── malwarebazaar.py         # MalwareBazaar
│   ├── hybrid_analysis.py       # Hybrid Analysis
│   ├── malshare.py              # MalShare
│   ├── otx.py                   # AlienVault OTX
│   ├── cymru.py                 # Team Cymru
│   ├── securitytrails.py        # SecurityTrails
│   ├── shodan.py                # Shodan
│   └── greynoise.py             # GreyNoise
│
├── validators/                  # IOC validation & classification
│   └── __init__.py              # IOCValidator class (14+ types)
│
├── database/                    # Local cache management
│   └── __init__.py              # ThreatIntelDB with timestamps
│
├── engine/                      # Search orchestration core
│   └── __init__.py              # _run_osint_engine() function
│
└── input_handler/               # Batch processing
    └── __init__.py              # InputHandler for CSV files
```

## Configuration

Create a `.env` file in the project root with your API keys (copy `.env.example` as a starting point). **Leave credentials empty or commented to disable a source at runtime.**

```env
# VirusTotal — https://www.virustotal.com/gui/my-apikey
VT_API_KEY=your_virustotal_api_key

# MalwareBazaar — https://auth.abuse.ch/
MB_API_KEY=your_malwarebazaar_api_key

# Hybrid Analysis — https://www.hybrid-analysis.com/
HA_API_KEY=your_hybrid_analysis_api_key

# MalShare — https://malshare.com/register.php
MALSHARE_API_KEY=your_malshare_api_key

# AlienVault OTX — https://otx.alienvault.com/account/profile
OTX_API_KEY=your_otx_api_key

# SecurityTrails — https://securitytrails.com/app/account/credentials
SECURITYTRAILS_API_KEY=your_securitytrails_api_key

# Shodan — https://account.shodan.io/
SHODAN_API_KEY=your_shodan_api_key

# GreyNoise — https://www.greynoise.io/account/signup
GREYNOISE_API_KEY=your_greynoise_api_key

# Team Cymru — https://www.team-cymru.com/
CYMRU_API_USERNAME=your_cymru_username
CYMRU_API_PASSWORD=your_cymru_password

# Any.run — https://any.run/
ANYRUN_API_KEY=your_anyrun_api_key

# IBM X-Force Exchange — https://exchange.xforce.ibmcloud.com/
XFORCE_API_KEY=your_xforce_api_key
XFORCE_API_PASSWORD=your_xforce_password

# To disable a source, comment out or empty its credentials:
# VT_API_KEY=
# SHODAN_API_KEY=
```

### Intelligent Source Disabling

Sources are **automatically enabled/disabled at runtime** based on credential availability:
- If credentials are defined and non-empty, the source is enabled
- If credentials are empty or commented out, the source is disabled at startup
- Check logs for "Active sources" and "Disabled sources" information
- **No code changes needed** — just manage credentials in `.env`

## Usage Notes

- **Local Cache**: All results stored in `data/threat_intel_db.json` with ISO timestamps. Use `-r/--refresh` to bypass cache
- **Correlated Indicator Search**: Use `--related` flag to find hashes/indicators correlated with a given IOC from OTX:
  ```bash
  python main.py <hash> --related              # Find related hashes
  python main.py <hash> --related -v           # Verbose JSON output
  python main.py <hash> --related -r           # Bypass cache
  ```
  This queries OTX for the malware family, APT groups, and related file hashes, then searches each related hash across all sources.
- **Bulk Hash Search**: Use Cymru's optimized bulk API for efficient batch hash lookups:
  ```bash
  python main.py -c hashes.csv --cymru-bulk   # Bulk hash search (1000 hashes per batch)
  python main.py -c hashes.csv --cymru-bulk -v # Verbose JSON output
  ```
- **Dependencies**: Minimal footprint - only `requests` and `python-dotenv` in production
- **Extensibility**: Add new sources without modifying existing code - just extend `Source` class
- **Integration**: Import and use: `from engine import run_osint_engine`
- **Performance**: First query ~5-10s (API calls), subsequent queries <100ms (cache hits)
- **Batch Processing**: CSV files auto-detect headers; supports single column or mixed formats

## License & Support

This repository is maintained as an active development workspace. For production use, add appropriate licensing (MIT/Apache 2.0 recommended).

### Use Cases

- 🔍 **Incident Response** - Quickly pivot on IOCs during active incidents
- 🛡️ **Threat Hunting** - Batch query suspicious indicators from logs
- 📊 **Threat Intelligence** - Aggregate data from multiple sources for analysis
- 🔗 **Security Automation** - Integrate into SOAR platforms and CI/CD pipelines

### Contributing

Suggestions for expansion:
- Additional threat intelligence sources (URLhaus, AbuseIPDB, ThreatFox, etc.)
- SQL database backend (PostgreSQL, MongoDB)
- REST API wrapper
- Async/parallel source querying
- Web UI dashboard

---

**Agrashandhani**: *Fast. Modular. Reliable. Threat Intelligence at Scale.*
