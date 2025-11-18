# Email Attack Surface Analyzer - Project Summary

## Overview

A comprehensive Python tool for analyzing an organization's email security posture by discovering domains, analyzing DNS security records (SPF, DKIM, DMARC), detecting email providers, and identifying security misconfigurations.

---

## Features Implemented

### ✅ Domain & Subdomain Enumeration
- **Multiple sources integrated:**
  - crt.sh (Certificate Transparency logs)
  - Sublist3r (optional external tool)
  - Amass (optional external tool)
  - DNS zone transfer attempts
  - VirusTotal API (optional, with API key)
- **Deduplication and validation** of discovered domains
- **Configurable** - can skip enumeration or external tools

### ✅ DNS Email Security Analysis
- **SPF Record Analysis:**
  - Record detection and parsing
  - Mechanism extraction (includes, IP ranges)
  - Policy evaluation (all mechanism)
  - Security assessment
  
- **DKIM Detection:**
  - Common selector checking (20+ selectors)
  - Custom selector support
  - Record validation
  
- **DMARC Policy Analysis:**
  - Record detection and parsing
  - Policy extraction (p, sp, pct)
  - Reporting address extraction (rua, ruf)
  - Alignment mode detection
  
- **MX Record Collection:**
  - Priority-sorted mail servers
  - Server identification

### ✅ External Email Provider Detection
- **12+ Provider Signatures:**
  - Google Workspace
  - Microsoft 365
  - Zoho Mail
  - Proofpoint
  - Cloudflare Email
  - SendGrid
  - Mailgun
  - Amazon SES
  - Mimecast
  - Barracuda
  - GoDaddy
  - Rackspace
  
- **Multi-factor Detection:**
  - MX record pattern matching
  - SPF include analysis
  - DKIM selector detection
  - Confidence scoring

### ✅ Security Misconfiguration Detection
- **Critical Issues:**
  - Overly permissive SPF (+all)
  - Missing email authentication
  
- **High Severity:**
  - Missing SPF records
  - Missing DMARC policies
  - Email servers without protection
  
- **Medium Severity:**
  - Weak DMARC policies (p=none)
  - Incomplete SPF records
  - Missing DKIM configuration
  - Provider-specific misconfigurations
  
- **Low Severity:**
  - Missing DMARC reporting
  - Suboptimal configurations

### ✅ Comprehensive Reporting
- **Markdown Reports:**
  - Executive summary
  - Domain inventory
  - DNS security analysis tables
  - Provider detection results
  - Security findings by severity
  - Prioritized recommendations
  - Detailed per-domain reports
  
- **JSON Reports:**
  - Complete machine-readable data
  - Timestamp and metadata
  - Structured results for automation

### ✅ Production-Ready Code
- **Modular architecture** - 5 separate modules
- **Error handling** with timeouts and retries
- **Type hints** for better code clarity
- **Comprehensive documentation** in docstrings
- **Command-line interface** with argparse
- **Configuration management** via .env files
- **Colored output** with colorama
- **Cross-platform support** (Windows, Linux, macOS)

---

## Project Structure

```
email-attack-surface/
├── Core Modules:
│   ├── main.py                 # Main orchestration script
│   ├── subdomain_enum.py       # Subdomain enumeration module
│   ├── dns_analyzer.py         # DNS record analysis module
│   ├── provider_detector.py    # Email provider detection module
│   └── report_generator.py     # Report generation module
│
├── Documentation:
│   ├── README.md              # Main documentation
│   ├── SETUP.md              # Setup guide
│   ├── PROJECT_SUMMARY.md    # This file
│   └── LICENSE               # MIT License
│
├── Configuration:
│   ├── requirements.txt       # Python dependencies
│   ├── .env.example          # Configuration template
│   ├── .gitignore            # Git ignore rules
│   └── domains.txt.example   # Domain list template
│
└── Examples & Testing:
    ├── quick_start.py         # Quick start example
    └── test_installation.py   # Test suite
```

---

## Technology Stack

### Core Libraries
- **dnspython** (2.6.1) - DNS queries and record parsing
- **requests** (2.31.0) - HTTP requests for APIs
- **beautifulsoup4** (4.12.3) - HTML parsing for web scraping
- **python-dotenv** (1.0.0) - Environment configuration
- **colorama** (0.4.6) - Cross-platform colored output
- **tabulate** (0.9.0) - Table formatting

### Optional External Tools
- **Sublist3r** - Additional subdomain enumeration
- **Amass** - OWASP subdomain discovery tool

### APIs (Optional)
- **VirusTotal API** - Additional subdomain discovery

---

## Key Functions

### subdomain_enum.py
- `enum_domains()` - Main enumeration function
- `SubdomainEnumerator.enumerate_all()` - Coordinate all sources
- `SubdomainEnumerator._enumerate_crtsh()` - crt.sh scraping
- `SubdomainEnumerator._enumerate_virustotal()` - VirusTotal API
- `SubdomainEnumerator._attempt_zone_transfer()` - DNS AXFR
- `SubdomainEnumerator._run_sublister()` - Sublist3r integration
- `SubdomainEnumerator._run_amass()` - Amass integration

### dns_analyzer.py
- `get_dns_records()` - Main analysis function
- `DNSAnalyzer.analyze_domain()` - Complete DNS analysis
- `DNSAnalyzer.get_spf_record()` - SPF extraction
- `DNSAnalyzer.get_dmarc_record()` - DMARC extraction
- `DNSAnalyzer.get_dkim_records()` - DKIM detection
- `DNSAnalyzer.get_mx_records()` - MX collection
- `assess_security_posture()` - Security scoring

### provider_detector.py
- `detect_email_providers()` - Main detection function
- `EmailProviderDetector.detect_providers()` - Provider identification
- `EmailProviderDetector.detect_misconfigurations()` - Issue detection
- `calculate_risk_score()` - Risk assessment

### report_generator.py
- `generate_report()` - Main report function
- `ReportGenerator.generate_markdown_report()` - Markdown output
- `ReportGenerator.generate_json_report()` - JSON output
- Multiple section generators for detailed reports

---

## Usage Examples

### Basic Analysis
```bash
python main.py example.com
```

### Multiple Domains
```bash
python main.py example.com example.org
```

### From File
```bash
python main.py -f domains.txt
```

### Verbose Output
```bash
python main.py example.com -v
```

### Skip Subdomain Enumeration
```bash
python main.py example.com --no-enum
```

### Quick Start
```bash
python quick_start.py example.com
```

---

## Output Examples

### Console Output
```
===================================================================
   Email Attack Surface Analyzer
===================================================================

[12:34:56] Loading Target Domains
------------------------------------
[*] Analyzing 1 domain(s)
  • example.com

[12:34:57] Enumerating Subdomains
------------------------------------
[+] example.com: Found 15 subdomains

[12:34:58] Analyzing DNS Email Security Records
------------------------------------
[*] Getting DNS records for: example.com
[+] Analyzed 15 domains
    5 domains have email capability

[12:34:59] Detecting Email Providers & Misconfigurations
------------------------------------
[+] Detected 2 email providers
    Found 8 security issues
    3 HIGH severity issues

[12:35:00] Generating Reports
------------------------------------
[+] Reports generated:
    Markdown: ./reports/report_20250118_123500.md
    JSON: ./reports/results_20250118_123500.json
```

### Report Structure
```markdown
# Email Attack Surface Analysis Report

**Generated:** 2025-01-18 12:35:00

## Executive Summary
- Root Domains Analyzed: 1
- Total Subdomains Discovered: 15
- Domains with Email Capability: 5

### Security Findings Summary
- Critical Issues: 0
- High Severity Issues: 3
- Medium Severity Issues: 5

## Domain Inventory
### example.com
**Total Subdomains:** 15
...

## DNS Security Records Analysis
...

## Email Provider Detection
...

## Security Findings
...

## Recommendations
...
```

---

## Configuration Options

### Environment Variables (.env)
```env
VIRUSTOTAL_API_KEY=your_api_key
SUBLISTER_PATH=/path/to/sublist3r.py
AMASS_PATH=amass
DNS_TIMEOUT=5
DKIM_SELECTORS=default,google,k1,k2,selector1,selector2
```

### Command-Line Arguments
- `-f, --file` - Input file with domains
- `-o, --output` - Output directory
- `-t, --timeout` - DNS timeout
- `--no-enum` - Skip subdomain enumeration
- `--skip-tools` - Skip external tools
- `-v, --verbose` - Verbose output

---

## Testing

### Test Suite Included
```bash
python test_installation.py
```

**Tests:**
1. Module imports
2. DNS resolution
3. Subdomain enumeration
4. DNS analysis
5. Provider detection
6. Report generation

---

## Security Considerations

### Authorization Required
⚠️ Only scan domains you own or have explicit permission to scan.

### Network Activity
- DNS queries (may be logged)
- HTTP requests to crt.sh
- Optional API calls (VirusTotal)
- Optional external tool execution

### Rate Limiting
- Built-in delays between requests
- Configurable timeouts
- Respects API rate limits

---

## Extensibility

### Easy to Extend

**Add new email providers:**
```python
# In provider_detector.py
'New Provider': {
    'mx_patterns': [r'.*\.newprovider\.com$'],
    'spf_includes': ['spf.newprovider.com'],
    'dkim_selectors': ['selector']
}
```

**Add new DKIM selectors:**
```python
# In .env file
DKIM_SELECTORS=default,google,custom1,custom2
```

**Add new subdomain sources:**
```python
# In subdomain_enum.py
def _enumerate_newsource(self, domain):
    # Implementation
    return subdomains
```

---

## Performance

### Speed Optimizations
- Parallel DNS queries where possible
- Configurable timeouts
- Option to skip slow enumeration
- Efficient data structures

### Resource Usage
- Minimal memory footprint
- No heavy dependencies
- Scalable to hundreds of domains
- Optional caching opportunities

---

## Best Practices

### Regular Scanning
- Quarterly security audits
- After email provider changes
- When onboarding new domains
- After DNS configuration changes

### DMARC Deployment
1. Start with `p=none` (monitor)
2. Review reports for 2-4 weeks
3. Move to `p=quarantine`
4. Monitor for issues
5. Upgrade to `p=reject`

### SPF Management
- Use `-all` for strict policy
- Regularly audit includes
- Monitor for 10+ lookups
- Document authorized senders

---

## Known Limitations

1. **DKIM selector detection** - Only checks common selectors
2. **External tools** - Require separate installation
3. **Rate limiting** - May affect large-scale scans
4. **DNS caching** - Recent changes may not be reflected
5. **Zone transfers** - Rarely allowed (expected)

---

## Future Enhancements

### Potential Features
- [ ] BIMI (Brand Indicators for Message Identification) detection
- [ ] Historical comparison reports
- [ ] Webhook notifications
- [ ] API endpoint for automation
- [ ] Database storage of results
- [ ] Email delivery testing
- [ ] TLS/STARTTLS verification
- [ ] DANE/TLSA record checking
- [ ] Advanced DMARC report parsing
- [ ] Subdomain takeover detection

---

## License

MIT License - See LICENSE file for details

**Disclaimer:** This tool is for authorized security assessments only. Users are responsible for ensuring they have permission to scan target domains.

---

## Quick Start Checklist

- [x] Install Python 3.8+
- [x] Install dependencies: `pip install -r requirements.txt`
- [x] Run test suite: `python test_installation.py`
- [x] Try example: `python quick_start.py example.com`
- [x] Run full analysis: `python main.py example.com -v`
- [x] Review reports in `./reports/`
- [ ] Configure .env for your environment (optional)
- [ ] Install external tools (optional)
- [ ] Scan your domains
- [ ] Implement recommendations

---

## Support

For questions, issues, or contributions:
1. Review documentation (README.md, SETUP.md)
2. Run test suite (test_installation.py)
3. Check verbose output (-v flag)
4. Verify prerequisites are met

**Happy Scanning! 🔒**
