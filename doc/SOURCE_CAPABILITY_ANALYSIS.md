# AGRASHANDHANI - SOURCE CAPABILITY ANALYSIS

## Executive Summary

This document provides a comprehensive analysis of all 11 integrated threat intelligence sources in the Agrashandhani framework. Each source has been analyzed for:
- **Supported IOC Types**: What indicators each source can query
- **Enrichment Capabilities**: What additional data each source provides (malware family, correlated hashes, APT attribution, etc.)
- **API Features**: Available endpoints and advanced search capabilities
- **Rate Limits**: API rate limiting information
- **Enhancement Opportunities**: Where each source could be improved

---

## Capability Matrix

| Source | Hash | IP | Domain | URL | Malware Family | Correlated Hashes | APT Info | Rate Limit | Notes |
|--------|------|----|---------|----|----------------|-------------------|----------|-----------|-------|
| **VirusTotal** | ✅ | ✅ | ✅ | ✅ | ✅ (via sandbox) | ✅ | ✅ | 4 req/min | Most comprehensive; provides sandbox analysis |
| **OTX** ⭐ | ✅ | ✅ | ✅ | ✅ | ✅ **ENHANCED** | ✅ **ENHANCED** | ✅ **ENHANCED** | Unlimited | Multi-section sequential queries; 3 new fields |
| **MalwareBazaar** | ✅ | ❌ | ❌ | ❌ | ✅ | ⚠️ Limited | ❌ | 2 req/sec | Hash-specific; minimal API responses |
| **Hybrid Analysis** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | 50 req/day | Powerful sandbox + searching capability |
| **Any.run** | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ | 100 req/day | TI Lookup + sandbox integration |
| **Shodan** | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | 1 req/sec | Internet asset discovery; no malware context |
| **GreyNoise** | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ⚠️ | Unlimited | IP noise classification; no enrichment |
| **SecurityTrails** | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | 50 req/day | DNS/infrastructure data only |
| **Cymru** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | Unlimited | Hash reputation only; minimal data |
| **MalShare** | ✅ | ❌ | ❌ | ❌ | ✅ | ⚠️ | ❌ | Varies | Basic sample metadata; slow API |
| **X-Force IBM** | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ✅ | 5 req/sec | Comprehensive but rate-limited |

---

## Detailed Source Analysis

### 1. VirusTotal ⭐⭐⭐ (HIGHLY RECOMMENDED FOR ENHANCEMENT)

**Supported IOC Types:**
- Hash: MD5, SHA1, SHA256, SSDEEP, TLSH
- IP: IPv4, IPv6
- Domain: Domain names
- URL: Full URLs

**Features:**
- 70+ antivirus engine scanning
- Community/expert intelligence
- Behavioral analysis (PE sections, imports, etc.)
- YARA rules
- Similar samples detection (relates files by hash proximity)
- Related samples (files with same filename patterns)
- Sandbox analysis (Zendesk, Dr.Web, etc.)

**Enrichment Capabilities:**
- ✅ **Malware Family**: Extracted from AV engine signatures ("Trojan.Win32.Generic")
- ✅ **Correlated Hashes**: Related samples through similarity/filename patterns
- ✅ **APT Attribution**: Some through vendor intelligence feeds

**Rate Limits:** 4 requests/minute (free tier)

**Enhancement Opportunity:**
- Current implementation basic (single query)
- **Recommended**: Enhanced multi-endpoint querying similar to OTX
  - Query `/file/{hash}` for basic analysis
  - Query `/file/{hash}/analysis` for detailed AV results
  - Query `/file/{hash}/objects/{file|domain|ip}` for related indicators
  - Extract malware family from AV engine "detected_as" strings with regex
  - Parse yara_rules for malware family and APT indicators

**Code Pattern Needed:**
```python
def _extract_vt_malware_family(analysis_results):
    """Extract malware family from AV engine detections"""
    families = {}
    for av_engine, detection in analysis_results.get('detected_as', {}).items():
        # Parse "Trojan.Win32.Generic!C" → "Trojan.Win32"
        family = '.'.join(detection.split('.')[:2])
        families[family] = families.get(family, 0) + 1
    return families

def _get_vt_correlated_hashes(sample_metadata):
    """Extract related file hashes from VT analysis"""
    related = set()
    for relation in sample_metadata.get('related', []):
        if relation['type'] == 'file':
            related.add(relation['hash'])
    return list(related)
```

---

### 2. OTX ⭐⭐⭐ (ENHANCED - REFERENCE IMPLEMENTATION)

**Supported IOC Types:**
- Hash: MD5, SHA1, SHA256
- IP: IPv4, IPv6
- Domain: Domain names
- URL: Full URLs

**Features:**
- Community threat intelligence
- 70+ threat feeds integrated
- Pulses (threat intelligence reports)
- Indicators correlated across feeds

**Enrichment Capabilities (ENHANCED):**
- ✅ **Malware Family**: NEW - Extracted from `/malware` section
- ✅ **Correlated Hashes**: NEW - From `/related` and `/analysis` sections
- ✅ **APT Groups**: NEW - From pulse metadata with 14+ keyword matching

**Rate Limits:** Unlimited

**Current Implementation:**
- Multi-section sequential querying (general → malware → analysis → related)
- `_extract_malware_family()` - Parses /malware section for family names
- `_extract_apt_groups()` - 14+ keyword-based APT mapping
- `_get_correlated_hashes()` - Collects related hashes from multiple sections
- Response includes 3 new fields: `malware_family`, `apt_groups`, `correlated_hashes`

**Enhancement Status:** ✅ Complete

**Code Location:** [sources/otx.py](sources/otx.py#L1)

---

### 3. MalwareBazaar ⭐ (LIMITED ENRICHMENT)

**Supported IOC Types:**
- Hash: MD5, SHA1, SHA256, ImpHash, TLSH, TelfHash, GimpHash

**Features:**
- Free malware sample database
- Collaborative submissions
- Recent malware samples

**Enrichment Capabilities:**
- ✅ **Malware Family**: Available in API response (e.g., "Emotet", "IcedID")
- ⚠️ **Correlated Hashes**: Limited - only provides single sample response
- ❌ **APT Info**: Not provided

**Rate Limits:** 2 requests/second

**Limitations:**
- POST-based API (not standard REST)
- Minimal response data
- Returns only exact match or "not found"

**Enhancement Opportunity:**
- Current implementation correct but minimal
- **Possible**: Add cross-reference to malware_families_mapping.json
  - Look up returned malware family name
  - Retrieve full family context (variants, APT actors, timeline)
  
---

### 4. Hybrid Analysis ⭐⭐ (GOOD ENRICHMENT)

**Supported IOC Types:**
- Hash: MD5, SHA1, SHA256
- IP: IPv4, IPv6
- Domain: Domain names
- URL: Full URLs
- Advanced search queries (API supports complex searching)

**Features:**
- Falcon Sandbox integration
- Advanced search with operators
- Behavioral analysis results
- Sandbox screenshots and process trees
- MITRE ATT&CK mapping

**Enrichment Capabilities:**
- ✅ **Malware Family**: Extraction available (environment_type, verdict_tags)
- ✅ **Correlated Hashes**: Through advanced search results
- ⚠️ **APT Info**: Limited to tags/verdicts

**Rate Limits:** 50 requests/day

**Implementation Status:** Basic but functional

**Enhancement Opportunity:**
- Current implementation: Single query endpoint
- **Recommended**: Multi-level querying
  - Query `/search/hash/{hash}` for sample metadata
  - Query advanced search for related indicators
  - Parse verdict tags for malware family extraction
  - Search for related hashes with same family field

---

### 5. Any.run ⭐⭐ (MODERATE ENRICHMENT)

**Supported IOC Types:**
- Hash: MD5, SHA1, SHA256
- IP: IPv4, IPv6
- Domain: Domain names
- URL: Full URLs

**Features:**
- Interactive sandbox analysis
- TI Lookup service
- Behavioral analysis
- Network activity capture
- API supports multiple indicators in single request

**Enrichment Capabilities:**
- ✅ **Malware Family**: Available in TI lookup response
- ⚠️ **Correlated Hashes**: Limited - via related analysis results
- ❌ **APT Info**: Not directly provided

**Rate Limits:** 100 requests/day

**Implementation Status:** Functional for basic TI lookup

---

### 6. Shodan (IP/DOMAIN INFRASTRUCTURE)

**Supported IOC Types:**
- IP: IPv4 only (domain support requires Pro plan)
- Domain: Limited support

**Features:**
- Internet-wide scanning data
- Open ports and running services
- Banner/fingerprint data
- Vulnerability associations (CVE)
- Geolocation and ASN data

**Enrichment Capabilities:**
- ❌ **Malware Family**: Not applicable (asset discovery, not malware)
- ❌ **Correlated Hashes**: Not applicable
- ❌ **APT Info**: Not applicable

**Rate Limits:** 1 request/second

**Purpose:** Infrastructure/asset discovery, not threat intelligence

**Not Suitable for Enhancement** - Different use case (asset discovery vs. malware analysis)

---

### 7. GreyNoise (IP REPUTATION)

**Supported IOC Types:**
- IP: IPv4 only

**Features:**
- Background noise classification
- Distinguishes scanners/researchers from attackers
- Organization and actor attribution
- Last activity timestamp

**Enrichment Capabilities:**
- ❌ **Malware Family**: Not applicable
- ❌ **Correlated Hashes**: Not applicable
- ⚠️ **APT Info**: Limited actor classification only

**Rate Limits:** Unlimited (Community tier)

**Purpose:** IP classification/noise filtering, not malware analysis

**Not Suitable for Enhancement** - Different use case (noise filtering vs. malware analysis)

---

### 8. SecurityTrails (DNS/INFRASTRUCTURE)

**Supported IOC Types:**
- Domain: Domain names
- IP: IPv4, IPv6

**Features:**
- Current and historical DNS records
- IP to hostname mapping
- Domain reputation
- WHOIS data
- Subdomain enumeration

**Enrichment Capabilities:**
- ❌ **Malware Family**: Not applicable
- ❌ **Correlated Hashes**: Not applicable
- ❌ **APT Info**: Not applicable

**Rate Limits:** 50 requests/day

**Purpose:** DNS/infrastructure investigation, not malware analysis

**Not Suitable for Enhancement** - Different use case (DNS/infrastructure vs. malware analysis)

---

### 9. Cymru (HASH REPUTATION)

**Supported IOC Types:**
- Hash: MD5, SHA1, SHA256
- IP: IPv4 (for ASN/BGP mapping)

**Features:**
- Hash reputation lookup
- Antivirus detection rate
- Last seen date
- IP to ASN mapping

**Enrichment Capabilities:**
- ❌ **Malware Family**: Not provided
- ❌ **Correlated Hashes**: Not applicable
- ❌ **APT Info**: Not applicable

**Rate Limits:** Unlimited

**Limitations:**
- Minimal data returned (detection ratio only)
- No enrichment data
- Simple reputation lookup

**Enhancement Opportunity:** Limited
- Could add malware family lookup via malware_families_mapping.json
- But source doesn't provide the data to map to

---

### 10. MalShare (MALWARE SAMPLES)

**Supported IOC Types:**
- Hash: MD5, SHA1, SHA256

**Features:**
- Malware sample sharing platform
- Detailed file analysis results
- Malware classification and metadata

**Enrichment Capabilities:**
- ✅ **Malware Family**: Provided if sample found
- ⚠️ **Correlated Hashes**: Limited - similar samples only
- ❌ **APT Info**: Not provided

**Rate Limits:** Varies by account tier

**Limitations:**
- Slow API response times
- Free tier has strict limits

---

### 11. X-Force IBM ⭐⭐ (COMPREHENSIVE)

**Supported IOC Types:**
- Hash: MD5, SHA1, SHA256
- IP: IPv4, IPv6
- Domain: Domain names
- URL: Full URLs

**Features:**
- IP reputation and geolocation
- Domain/URL threat scoring and categorization
- Malware hash analysis and family attribution
- Passive DNS data
- Vulnerability intelligence
- Threat actor and campaign correlation

**Enrichment Capabilities:**
- ✅ **Malware Family**: Available in hash analysis response
- ⚠️ **Correlated Hashes**: Limited - family-based grouping
- ✅ **APT Info**: Threat actor attribution available

**Rate Limits:** 5 requests/second

**Implementation Status:** Basic but comprehensive

**Enhancement Opportunity:**
- Current: Single query per IOC type
- **Recommended**: Multi-endpoint querying
  - Query `/malware/{hash}` with `apikey` parameter
  - Query `/collections/malware` for related samples
  - Extract family from response and enrich with timeline data

---

## Summary: Enrichment Capabilities

### Sources Providing Malware Family Information:
1. **VirusTotal** - Via AV engine detections (HIGH QUALITY)
2. **OTX** ✅ ENHANCED - Via /malware section (GOOD)
3. **MalwareBazaar** - Direct field (LIMITED DATA)
4. **Hybrid Analysis** - Via verdict tags (MODERATE)
5. **Any.run** - Via TI lookup (MODERATE)
6. **MalShare** - If sample exists (LIMITED)
7. **X-Force IBM** - Via malware/{hash} (GOOD)

### Sources Providing Correlated Hashes:
1. **VirusTotal** - Related samples, similar files (EXCELLENT)
2. **OTX** ✅ ENHANCED - Via /related and /analysis (GOOD)
3. **Hybrid Analysis** - Via advanced search (MODERATE)
4. **Any.run** - Via related analysis (LIMITED)
5. **MalShare** - Minimal (LIMITED)
6. **X-Force IBM** - Via family grouping (LIMITED)

### Sources Providing APT/Threat Actor Information:
1. **VirusTotal** - Some vendor intel (LIMITED)
2. **OTX** ✅ ENHANCED - Via pulse metadata with 14+ keywords (GOOD)
3. **X-Force IBM** - Direct attribution (MODERATE)
4. **GreyNoise** - Actor classification only (LIMITED)

---

## Recommended Enhancement Priorities

### Priority 1: HIGH IMPACT (Recommended for Enhancement)

#### VirusTotal Enhancement
- **Why**: Most comprehensive data; 70+ AV engines; excellent correlated hashes
- **Effort**: Medium
- **Impact**: Major - would provide best malware family extraction and correlation data
- **Implementation**:
  ```
  1. Query /file/{hash} for basic analysis
  2. Parse detected_as strings from AV engines for malware families
  3. Query /file/{hash}/objects/{type} for related indicators
  4. Normalize family names using malware_families_mapping.json
  5. Return normalized response with family, correlations, APT
  ```

#### X-Force IBM Enhancement
- **Why**: Comprehensive IOC support; enterprise-grade threat actor data
- **Effort**: Medium
- **Impact**: Major - would add enterprise perspective to threat intelligence
- **Implementation**:
  - Similar to VirusTotal enhancement
  - Multi-endpoint querying for hash/IP/domain/URL

### Priority 2: MEDIUM IMPACT (Good Enhancement Candidates)

#### Hybrid Analysis Enhancement
- **Why**: Good sandbox data; behavioral analysis; advanced search
- **Effort**: Medium
- **Impact**: Good - would add behavioral context to indicators

#### Any.run Enhancement
- **Why**: Good TI lookup; sandbox integration
- **Effort**: Low-Medium
- **Impact**: Good - would complement Hybrid Analysis

### Priority 3: LOW IMPACT (Not Worth Enhancement)

- **Shodan**: Infrastructure discovery, not malware analysis
- **GreyNoise**: IP noise classification only
- **SecurityTrails**: DNS/infrastructure data only
- **Cymru**: Minimal enrichment possible
- **MalShare**: Limited data availability

---

## IOC Type Coverage by Source

### Hash IOC (MD5/SHA1/SHA256):
✅ **Full Support**: VirusTotal, OTX, MalwareBazaar, Hybrid Analysis, Any.run, MalShare, X-Force IBM, Cymru
⚠️ **No Support**: Shodan, GreyNoise, SecurityTrails

### IP IOC (IPv4/IPv6):
✅ **Full Support**: VirusTotal, OTX, Hybrid Analysis, Any.run, Shodan, GreyNoise, SecurityTrails, Cymru, X-Force IBM
⚠️ **Limited**: (Only IPv4)

### Domain IOC:
✅ **Full Support**: VirusTotal, OTX, Hybrid Analysis, Any.run, Shodan, SecurityTrails, X-Force IBM
⚠️ **No Support**: MalwareBazaar, GreyNoise, Cymru, MalShare

### URL IOC:
✅ **Full Support**: VirusTotal, OTX, Hybrid Analysis, Any.run, X-Force IBM
⚠️ **No Support**: MalwareBazaar, Shodan, GreyNoise, SecurityTrails, Cymru, MalShare

---

## API Rate Limiting Summary

| Source | Rate Limit | Strategy |
|--------|-----------|----------|
| **VirusTotal** | 4 req/min | Queue queries, batch processing |
| **OTX** | Unlimited | No throttling needed |
| **MalwareBazaar** | 2 req/sec | Acceptable |
| **Hybrid Analysis** | 50 req/day | Schedule queries for optimal load |
| **Any.run** | 100 req/day | Batch queries |
| **Shodan** | 1 req/sec | Spread queries over time |
| **GreyNoise** | Unlimited | No throttling needed |
| **SecurityTrails** | 50 req/day | Schedule queries |
| **Cymru** | Unlimited | No throttling needed |
| **MalShare** | Varies | Check tier limits |
| **X-Force IBM** | 5 req/sec | Good throughput |

---

## Strategic Recommendations

### 1. Most Valuable Source for Cross-Enhancement
**VirusTotal** - Implement OTX-style enhancement with:
- Multi-endpoint sequential querying
- AV engine detection parsing for malware families
- Related samples extraction
- Community vote analysis for threat assessment

### 2. Enterprise Threat Intelligence
**X-Force IBM** - Add similar enhancements for:
- Threat actor attribution
- Campaign correlation
- Industry-specific threat data

### 3. Sandbox Behavioral Analysis
**Hybrid Analysis** - Leverage for:
- MITRE ATT&CK mapping
- Process execution analysis
- Network behavior correlation

### 4. Complementary Data
Group sources by purpose:
- **Malware Analysis**: VirusTotal, OTX, MalwareBazaar, Hybrid Analysis, X-Force IBM
- **Infrastructure Intelligence**: SecurityTrails, Shodan, Cymru
- **Reputation/Classification**: GreyNoise, Cymru, VirusTotal
- **Sandbox/Behavioral**: Hybrid Analysis, Any.run

### 5. Recommended Analysis Pipeline for Hash IOCs
```
Input Hash
    ↓
[OTX] → Get malware family, APT groups, correlated hashes
    ↓
[VirusTotal] → Get AV detections, related samples
    ↓
[Hybrid Analysis] → Get behavioral analysis (if available)
    ↓
[X-Force IBM] → Get enterprise threat intelligence
    ↓
[malware_families_mapping.json] → Normalize and enrich family data
    ↓
Output: Comprehensive threat profile
```

---

## Implementation Roadmap

### Phase 1: Immediate (Current)
- ✅ OTX Enhancement (COMPLETE)
- ✅ Malware Database (COMPLETE)

### Phase 2: Near-term (Recommended)
- [ ] VirusTotal Enhancement (2-3 days)
- [ ] Source capability documentation (Current - you are here)

### Phase 3: Medium-term
- [ ] X-Force IBM Enhancement (1-2 days after VT)
- [ ] Hybrid Analysis Enhancement (1 day)

### Phase 4: Long-term
- [ ] Any.run Enhancement (1 day)
- [ ] Multi-source aggregation and conflict resolution
- [ ] Confidence scoring based on source agreement

---

## Conclusion

The Agrashandhani framework currently integrates 11 diverse threat intelligence sources. While all sources are functional, only 5-6 sources provide meaningful malware enrichment data:

**Top Tier Sources** (with enrichment):
1. VirusTotal - Most comprehensive, needs enhancement
2. OTX - Recently enhanced, good baseline
3. X-Force IBM - Enterprise-grade, comprehensive

**Mid Tier Sources** (some enrichment):
4. Hybrid Analysis - Good sandbox data
5. Any.run - Good TI lookup
6. MalwareBazaar - Limited but malware-focused

**Infrastructure Tier** (specialized, not malware):
7. Shodan, SecurityTrails, Cymru, GreyNoise - Asset/reputation focused

### Key Finding
**VirusTotal enhancement would provide the highest ROI** - it has the most data sources (70+ AV engines), best correlation data, and no rate limiting constraints compared to other premium sources.

