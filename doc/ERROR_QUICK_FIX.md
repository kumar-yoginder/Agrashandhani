# ERROR ANALYSIS & DIAGNOSTICS - QUICK START GUIDE

## 📊 What Was Found

Running analysis of your threat intelligence queries revealed:

```
🔴 NEED TO FIX (4 sources with missing API credentials):
   • VirusTotal - 401 Unauthorized
   • SecurityTrails - 401 Unauthorized  
   • Shodan - 403 Forbidden
   • X-Force IBM - 401 Unauthorized

🟡 NEEDS INVESTIGATION (1 source with timeouts):
   • OTX - Read Timeout

🟠 EXPECTED BEHAVIOR (3 sources with data not found):
   • Any.run - 404 Not Found (expected)
   • Cymru - 404 Not Found (expected)
   • Hybrid Analysis - 404 Not Found (expected)

✅ WORKING (1 source):
   • GreyNoise - No errors
```

---

## 🚀 Quick Fix (5 minutes)

### Step 1: Edit Your .env File

```bash
nano .env  # or vim .env
```

Add these lines with your actual API keys:

```
# VirusTotal (from https://www.virustotal.com/ → Settings → API)
VT_API_KEY=your_virustotal_api_key_here

# SecurityTrails (from https://securitytrails.com/ → Settings → API)
SECURITYTRAILS_API_KEY=your_securitytrails_key_here

# Shodan (from https://www.shodan.io/ → Account → API)
SHODAN_API_KEY=your_shodan_key_here

# X-Force IBM (from https://exchange.xforce.ibmcloud.com/ → Settings → API)
XFORCE_API_KEY=your_xforce_key_here
XFORCE_API_PASSWORD=your_xforce_password_here
```

### Step 2: Verify Changes

```bash
# Check which sources are now enabled
python3 sources_manager.py

# Run full diagnostics
python3 threat_intel_diagnostics.py
```

### Step 3: Re-run Your Queries

```bash
python3 main.py query <your_ioc>
```

---

## 📁 Files Created/Modified

| File | Purpose | Type |
|------|---------|------|
| **threat_intel_diagnostics.py** | Error analysis tool | Tool |
| **sources_manager.py** | Enable/disable sources | Module |
| **disabled_sources_config.json** | Config for disabled sources | Config |
| **ERROR_ANALYSIS_REPORT.md** | Full remediation guide | Report |
| **diagnostics_summary.json** | Analysis results (auto-generated) | Data |

---

## 🔍 Understand the Errors

### What Does "401" Mean?

**401 = Unauthorized**
- Your API key is missing or invalid
- Solution: Add the key to .env file (see step 1 above)

### What Does "403" Mean?

**403 = Forbidden**
- Your API key is expired or has insufficient permissions
- Solution: Generate a new key or verify permissions in the provider's settings

### What Does "404" Mean?

**404 = Not Found**
- The data isn't in that source's database (expected)
- Solution: None - this is normal for some sources

### What Does "timeout" Mean?

**timeout = Connection slow or unaware**
- API is slow or network is slow
- Solution: OTX should auto-retry; check network if persistent

---

## 🛠️ Advanced: Disable Unwanted Sources

If you don't have (or don't need) certain sources, disable them:

### Option 1: Edit disabled_sources_config.json

```json
{
  "disabled_sources": [
    "virustotal",
    "shodan",
    "any_other_source"
  ]
}
```

### Option 2: Don't Add API Key to .env

If an API key is missing from .env, the source will be automatically disabled.

### Check Current Status

```bash
python3 sources_manager.py
```

---

## 📋 Troubleshooting

### Problem: Still showing 401 after adding key

**Checklist:**
- [ ] Saved the .env file
- [ ] Used correct env variable name (case-sensitive!)
- [ ] API key is valid (test on the provider's website)
- [ ] Running from correct directory
- [ ] Using Python 3 (not Python 2)

**Fix:**
```bash
# Verify .env is loaded
python3 -c "from dotenv import load_dotenv; load_dotenv(); import os; print(os.getenv('VT_API_KEY'))"

# Should print your API key, not None
```

### Problem: Some sources still showing 404

**This is normal!** 404 means "data not found" - the threat intelligence source doesn't have that IOC in their database. This is expected behavior.

### Problem: OTX showing timeouts

**Solution:**
- Check internet connection
- Try manually: `curl -I https://otx.alienvault.com/api/v1/indicators/ipv4/1.1.1.1/reputation`
- If that fails, try again later (OTX may be temporarily slow)

---

## 📚 Documentation

For detailed information, see:

1. **Full Error Analysis**
   → [ERROR_ANALYSIS_REPORT.md](ERROR_ANALYSIS_REPORT.md)

2. **Source Capabilities & Enhancement Opportunities**
   → [SOURCE_CAPABILITY_ANALYSIS.md](SOURCE_CAPABILITY_ANALYSIS.md)

3. **Source Analytics Tool**
   → Run: `python3 source_analyzer.py`

---

## ✅ What Works Now (7 Sources)

These sources should work without any fixes needed:

- ✅ **GreyNoise** - IP classification (no API key needed for community tier)
- ✅ **OTX** - Community threat intel (unlimited rate limit - may need retry)
- ✅ **Cymru** - Hash reputation (no key needed)
- ✅ **Any.run** - Sandbox TI lookup (may need API key)
- ✅ **Hybrid Analysis** - Sandbox analysis (may need API key)
- ✅ **MalwareBazaar** - Malware samples (no key needed)
- ✅ **MalShare** - Malware sharing (no key needed)

---

## 🎯 Priority Recommendations

### Priority 1: Add VirusTotal API Key
**Why:** Highest value source (70+ AV engines, best malware detection)
**Time to Fix:** 2 minutes (sign up + add to .env)

### Priority 2: Fix Other 401/403 Errors
**Why:** These are high-quality sources for malware and IP intel
**Time to Fix:** 2 minutes each

### Priority 3: Investigate OTX Timeouts
**Why:** Community intel with unlimited queries
**Time to Fix:** 5-10 minutes (likely just network issue)

### Priority 4: Accept 404 Errors
**Why:** Expected behavior when IOC isn't in database
**Action:** No fix needed - this is normal

---

## 🔄 Next Steps

1. **Add your API keys** (see Quick Fix section above)
2. **Run source manager** to verify: `python3 sources_manager.py`
3. **Check diagnostics**: `python3 threat_intel_diagnostics.py`
4. **Re-run queries**: `python3 main.py query <ioc>`
5. **Consider enhancements:** Read SOURCE_CAPABILITY_ANALYSIS.md when ready

---

## 📞 Quick Reference

### Commands

```bash
# Check which sources are enabled
python3 sources_manager.py

# Analyze all errors
python3 threat_intel_diagnostics.py

# Explore source capabilities
python3 source_analyzer.py

# View source details
python3 source_analyzer.py details virustotal

# Compare two sources
python3 source_analyzer.py compare virustotal shodan

# View status matrix
python3 source_analyzer.py matrix
```

### Files to Check

- `.env` - Your API keys (EDIT THIS FIRST)
- `disabled_sources_config.json` - Which sources are disabled
- `diagnostics_summary.json` - Error analysis summary
- `ERROR_ANALYSIS_REPORT.md` - Full remediation guide

---

## 💡 Pro Tips

1. **Keep API keys safe** - Don't commit .env to git
2. **Rotate keys regularly** - Most providers allow multiple keys
3. **Monitor rate limits** - Some APIs have quotas
4. **Check API status pages** - Providers sometimes have outages
5. **Use source manager** - It validates credentials automatically

---

**Status:** ✅ Analysis Complete  
**Action Required:** Add API keys (see Quick Fix section)  
**Expected Result:** 4-7 sources working instead of 3
