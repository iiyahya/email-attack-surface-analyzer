# Company Domain Discovery Feature

## Overview

The Company Domain Discovery feature automatically identifies all domains associated with a company name, including:

- **Primary domains** (company.com, company.net, etc.)
- **Regional domains** (company-us.com, europe.company.com)
- **Subsidiary domains** (companylabs.com, company-ventures.com)
- **Sub-brands** and product-specific domains
- **International variations** with different TLDs

## How It Works

The discovery engine uses multiple methods to find domains:

### 1. Certificate Transparency Logs
- Searches crt.sh for SSL certificates issued to the organization
- Extracts domains from certificate Common Names (CN)
- Parses Subject Alternative Names (SAN) for additional domains
- Matches both exact organization names and patterns

### 2. Common Domain Patterns
- Tests standard patterns: `company.com`, `company.net`, `company.io`
- Corporate variations: `companycorp.com`, `companyinc.com`
- Branded patterns: `mycompany.com`, `getcompany.com`
- Acronym-based domains from company initials

### 3. TLD Variations
- Tests all major TLDs: `.com`, `.net`, `.org`, `.io`, `.ai`, `.app`
- Country-specific TLDs: `.us`, `.uk`, `.ca`, `.de`, `.ae`, etc.
- Regional combinations: `.co.uk`, `.com.au`, `.co.jp`

### 4. Subsidiary Patterns
- Searches for common subsidiary keywords:
  - `company-labs`, `company-ventures`, `company-capital`
  - `company-technologies`, `company-software`, `company-services`
  - `company-digital`, `company-cloud`, `company-security`
  
### 5. Regional Patterns
- Geographic variations:
  - `company-us`, `company-emea`, `company-apac`
  - `us.company.com`, `eu.company.com`, `asia.company.com`

### 6. DNS Verification
- Verifies each discovered domain using DNS lookups
- Checks for A records (website hosting)
- Checks for MX records (email capability)
- Filters out non-existent domains

## Usage

### Command-Line Usage

```bash
# Basic discovery
python company_domains.py "Microsoft Corporation"

# Discovery with verbose output
python company_domains.py "Google Inc"

# Analyze a specific company
python company_domains.py "Adobe Systems"
```

### Interactive Menu

1. Launch interactive mode:
   ```bash
   python main_interactive.py
   ```

2. Select option **3** - "Discover Company Domains"

3. Enter company name when prompted

4. Review discovered domains

5. Choose to:
   - Analyze domains for email security
   - Save results to JSON
   - Return to main menu

### Python API

```python
from company_domains import discover_company_domains, format_results_table

# Discover domains
results = discover_company_domains("Acme Corporation", verbose=True)

# Access results
print(f"Total domains found: {results['total_domains']}")

# Get primary domains
for domain_info in results['categories']['primary_domains']:
    print(f"Primary: {domain_info['domain']}")
    print(f"Sources: {domain_info['sources']}")

# Get all domains as list
all_domains = results['all_domains']

# Format and print table
print(format_results_table(results))
```

## Output Format

### Categories

Discovered domains are automatically categorized:

#### 1. **Primary Domains**
The main domain(s) for the company:
```
microsoft.com
microsoft.net
microsoft.io
```

#### 2. **Regional Domains**
Geographic or location-specific domains:
```
microsoft-us.com
microsoft-emea.com
microsoft.apac
```

#### 3. **Subsidiary Domains**
Sub-brands, divisions, or product lines:
```
microsoftlabs.com
microsoft-ventures.com
microsoft-gaming.com
```

#### 4. **Subdomains**
Third-level domains discovered:
```
careers.microsoft.com
support.microsoft.com
azure.microsoft.com
```

#### 5. **Other Related Domains**
Additional domains associated with the company:
```
ms.com
msn.com
```

### JSON Output Structure

```json
{
  "company_name": "Microsoft Corporation",
  "total_domains": 45,
  "discovery_timestamp": "2025-11-18 15:30:00",
  "categories": {
    "primary_domains": [
      {
        "domain": "microsoft.com",
        "sources": ["TLD Variation (.com)", "Certificate Transparency"],
        "discovery_methods": 2
      }
    ],
    "regional_domains": [...],
    "subsidiary_domains": [...],
    "subdomains": [...],
    "other_domains": [...]
  },
  "all_domains": [
    "microsoft.com",
    "microsoft.net",
    ...
  ],
  "summary": {
    "primary": 5,
    "regional": 3,
    "subsidiaries": 8,
    "subdomains": 25,
    "other": 4
  }
}
```

## Integration with Email Security Analysis

After discovering company domains, you can:

### 1. Analyze All Discovered Domains
```bash
python main_interactive.py
# Option 3: Discover Company Domains
# Enter company name
# Choose "Yes" to analyze domains
```

### 2. Use Discovered Domains as Input
```bash
# Save discovered domains
python company_domains.py "Company Name"

# Extract domains to file
cat company_domains_Company_Name.json | jq -r '.all_domains[]' > domains.txt

# Analyze with main tool
python main.py -f domains.txt --export-excel
```

### 3. Selective Analysis
Load discovered domains in interactive mode, then:
- Review and filter domains
- Remove unwanted domains
- Run comprehensive email security analysis
- Export results in multiple formats

## Use Cases

### 1. M&A Due Diligence
Discover all digital assets of a target company:
```bash
python company_domains.py "Target Company Inc"
```

### 2. Competitor Analysis
Identify competitor's digital presence:
```bash
python company_domains.py "Competitor Corp"
# Analyze their email security posture
```

### 3. Brand Protection
Find all domains that might be associated with your brand:
```bash
python company_domains.py "Your Company Name"
# Check for typosquatting or unauthorized use
```

### 4. Security Audit
Comprehensive security assessment of all company assets:
```bash
python main_interactive.py
# Option 3: Discover Company Domains
# Automatically analyze all discovered domains
# Export comprehensive security report
```

### 5. Asset Inventory
Maintain current list of all company domains:
```bash
# Monthly automated discovery
python company_domains.py "Your Company" > monthly_inventory.json
```

## Performance Considerations

### Speed
- **Fast discovery** (~30-60 seconds for most companies)
- **Certificate Transparency**: 10-20 seconds
- **DNS verification**: 2-5 seconds per pattern
- **Total time**: Depends on company size and internet speed

### Rate Limiting
- Automatic delays between API calls
- Respects crt.sh rate limits
- DNS queries are throttled

### Accuracy
- **High precision** for Certificate Transparency data
- **Pattern matching** may include related domains
- **DNS verification** ensures domains are active
- **False positives** possible for common company names

## Limitations

### 1. Common Names
Very common company names may return many unrelated domains:
```bash
# Example: "Apple" might return apple-store.com, apple-farms.com, etc.
# Solution: Use full legal name "Apple Inc." for better accuracy
```

### 2. Private/Unlisted Domains
- Internal domains may not appear in Certificate Transparency
- Domains without SSL certificates won't be found via crt.sh
- Recently registered domains may not be indexed yet

### 3. International Variations
- Non-English company names may require localized search
- Some country-specific TLDs require local presence

### 4. Acquisition History
- Recently acquired companies may still use old domains
- Rebranded companies need both old and new names searched

## Tips for Best Results

### 1. Use Full Legal Name
```bash
# Good
python company_domains.py "Microsoft Corporation"

# Better for disambiguation
python company_domains.py "Adobe Systems Incorporated"
```

### 2. Try Variations
```bash
# Original name
python company_domains.py "International Business Machines"

# Common abbreviation
python company_domains.py "IBM"

# Both may yield different results
```

### 3. Review Certificate Data
Certificate Transparency is the most accurate source:
- Based on actual SSL certificate registrations
- Includes organization field matching
- Shows currently active domains

### 4. Verify Results
Always review discovered domains:
- Some pattern matches may be false positives
- Regional domains might belong to resellers
- Check WHOIS data for verification

### 5. Combine with Subdomain Enumeration
For complete coverage:
```bash
# Discover company domains
python company_domains.py "Company Name"

# Then run full analysis with subdomain enumeration
python main.py -f discovered_domains.txt --export-excel
```

## Examples

### Example 1: Technology Company
```bash
$ python company_domains.py "Salesforce"

Discovering domains for: Salesforce
...

Found 38 unique domains:

PRIMARY DOMAINS
  • salesforce.com
  • salesforce.net
  • salesforce.io

SUBSIDIARY DOMAINS
  • heroku.com
  • mulesoft.com
  • tableau.com
  • slack.com

REGIONAL DOMAINS
  • salesforce-emea.com
  • salesforce.jp
```

### Example 2: Retail Company
```bash
$ python company_domains.py "Walmart"

Found 25 unique domains:

PRIMARY DOMAINS
  • walmart.com
  • walmart.net

REGIONAL DOMAINS
  • walmart.ca
  • walmart.com.mx
  • asda.com (UK)

SUBSIDIARY DOMAINS
  • samsclub.com
  • jet.com
```

## Troubleshooting

### Issue: No Domains Found
**Solutions:**
1. Try full legal company name
2. Check spelling of company name
3. Try company abbreviation or trading name
4. Company may not have SSL certificates issued to org name

### Issue: Too Many Unrelated Domains
**Solutions:**
1. Use more specific company name (include "Inc", "Corp", etc.)
2. Filter results by reviewing sources
3. Focus on Certificate Transparency results (most accurate)

### Issue: Slow Performance
**Solutions:**
1. Check internet connection
2. crt.sh may be experiencing high load
3. Run with `--skip-tools` to use only CT logs
4. DNS verification can be slow for many patterns

### Issue: Missing Known Domains
**Solutions:**
1. Domain may not have SSL certificate
2. Certificate may be issued to different organization name
3. Add domain manually after discovery
4. Run subdomain enumeration on discovered domains

## Future Enhancements

Planned improvements:
- [ ] Integration with WHOIS databases
- [ ] Reverse IP lookup
- [ ] ASN (Autonomous System Number) correlation
- [ ] Historical domain ownership tracking
- [ ] Social media account discovery
- [ ] Cloud service provider detection
- [ ] Domain expiration monitoring
- [ ] Brand similarity detection

## Support

For issues or questions about Company Domain Discovery:
- Check main README.md
- Review USAGE_GUIDE.md
- Report issues on GitHub
- See API_DOCS.md for programmatic usage

---

**Part of Email Attack Surface Analyzer - Enterprise Edition v2.1**
