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

## Key Features

✅ **Multi-Source Threat Intelligence** - Query VirusTotal, MalwareBazaar, Hybrid Analysis, MetaDefender simultaneously  
✅ **Intelligent Caching** - Timestamped local JSON database prevents redundant API calls  
✅ **14+ IOC Types** - MD5/SHA1/SHA256 hashes, IPv4/IPv6, domains, URLs, emails, CVEs, APTs, malware families, OS, countries  
✅ **Batch Processing** - Process CSV files with automatic header detection and type validation  
✅ **Modular Architecture** - Clean, extensible design for adding new sources  
✅ **Smart Rate Limiting** - Built-in exponential backoff and retry logic  
✅ **Multiple Output Formats** - Human-readable or verbose JSON for integration  
✅ **Validation Mode** - Test IOC format without making API calls

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
├── threat_intel_db.json         # Local cache with timestamps
├── sample_iocs.csv              # Example batch file
│
├── config.py                    # Configuration & constants
├── clients.py                   # RateLimitedClient with retry logic
│
├── sources/                     # Threat intelligence source implementations
│   ├── __init__.py              # Source registry & factory
│   ├── base.py                  # Abstract Source class
│   ├── virustotal.py            # VirusTotal integration
│   ├── malwarebazaar.py         # MalwareBazaar integration
│   ├── hybrid_analysis.py       # Hybrid Analysis integration
│   └── metadefender.py          # MetaDefender integration
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

Create a `.env` file in the project root with your API keys:

```env
VT_API_KEY=your_virustotal_api_key
HA_API_KEY=your_hybrid_analysis_api_key
OPSWAT_API_KEY=your_metadefender_api_key
```

## Usage Notes

- **Local Cache**: All results stored in `threat_intel_db.json` with ISO timestamps. Use `-r/--refresh` to bypass cache
- **Dependencies**: Minimal footprint - only `requests` and `python-dotenv` in production
- **Extensibility**: Add new sources without modifying existing code - just extend `Source` class
- **Integration**: Import and use: `from engine import run_osint_search`
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
- Additional threat intelligence sources (AlienVault OTX, Shodan, URLhaus, etc.)
- SQL database backend (PostgreSQL, MongoDB)
- REST API wrapper
- Async/parallel source querying
- Web UI dashboard

---

**Agrashandhani**: *Fast. Modular. Reliable. Threat Intelligence at Scale.*
