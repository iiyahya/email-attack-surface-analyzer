# Email Attack Surface Analyzer - Usage Guide

## Table of Contents
1. [Quick Start](#quick-start)
2. [Interactive Mode](#interactive-mode)
3. [Command-Line Mode](#command-line-mode)
4. [Export Formats](#export-formats)
5. [Configuration](#configuration)
6. [Advanced Usage](#advanced-usage)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start

The fastest way to get started is using interactive mode:

```bash
# Activate virtual environment (if using one)
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Launch interactive mode
python main_interactive.py
```

### Your First Scan

1. Select option `1` (Quick Scan)
2. Enter your domain(s), one per line
3. Press Enter on empty line to finish
4. Choose `Y` to run analysis immediately
5. Select export format when prompted

---

## Interactive Mode

### Features

The interactive menu provides:
- **Visual Interface**: ASCII art banner and color-coded menus
- **Guided Workflow**: Step-by-step process for configuration and analysis
- **Real-time Status**: See current settings and loaded domains
- **Multiple Operations**: Configure, scan, export, and view results
- **Built-in Help**: Comprehensive documentation accessible from menu

### Menu Options

#### 1. Quick Scan
Enter domains directly and scan immediately.

**Use when:**
- Testing a few domains quickly
- One-off analysis needed
- You don't have a domains file

**Workflow:**
1. Enter domains one per line
2. Empty line to finish
3. Optionally run analysis immediately

#### 2. Load Domains from File
Import domains from a text file.

**File format:**
```
example.com
subdomain.example.com
another-domain.org
# Lines starting with # are comments
```

**Use when:**
- Analyzing many domains
- Repeated scans of same domains
- Batch processing required

#### 3. Configure Settings
Adjust analysis parameters without editing `.env` file.

**Available settings:**
- Toggle subdomain enumeration (on/off)
- Toggle external tools (Subfinder, Amass, Sublist3r)
- Toggle verbose mode
- Set DNS timeout
- Configure API keys (VirusTotal)
- Configure tool paths

**Best practices:**
- Disable external tools for faster scans
- Increase DNS timeout for slow networks
- Enable verbose mode for debugging
- Keep subdomain enumeration on for comprehensive results

#### 4. Run Full Analysis
Execute the complete analysis pipeline:

**Steps:**
1. **Subdomain Enumeration** (if enabled)
   - crt.sh (Certificate Transparency)
   - VirusTotal API (if configured)
   - DNS zone transfers
   - Subfinder (if installed)
   - Amass (if installed)
   - Sublist3r (if installed)

2. **DNS Analysis**
   - MX records
   - SPF records
   - DMARC policies
   - DKIM selectors

3. **Provider Detection**
   - Identify email service providers
   - Detect misconfigurations
   - Assess security posture

4. **Export Prompt**
   - Choose export format
   - Save results immediately

**Progress tracking:**
```
[1/4] Starting analysis for 3 domain(s)...
[2/4] Enumerating subdomains...
  ✓ Found 127 unique domains
[3/4] Analyzing DNS records...
  ✓ Analyzed 127 domains (45 with email)
[4/4] Detecting providers and security issues...
  ✓ Found 12 security issues
✓ Analysis complete!
```

#### 5. Export Results
Export previously completed analysis in multiple formats.

**Available formats:**
- **Markdown (.md)**: Human-readable reports with tables
- **JSON (.json)**: Machine-readable structured data
- **Excel (.xlsx)**: Multi-sheet workbook with formatting
- **CSV**: Individual CSV files for each data category

**Export all formats at once:** Select option 5

#### 6. View Last Results Summary
Quick overview of most recent analysis:

**Displays:**
- Analysis timestamp
- Domain counts (root, total, with email)
- Security records (SPF, DMARC, DKIM coverage)
- Security issues by severity (Critical, High, Medium, Low)

#### 7. Help & Documentation
Built-in help system with:
- Quick start guide
- Feature overview
- Configuration tips
- Export format descriptions
- External tools information

#### 8. Exit
Safely exit the application.

---

## Command-Line Mode

For scripting and automation, use the classic command-line interface.

### Basic Syntax

```bash
python main.py [domains...] [options]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `domains` | One or more root domains to analyze |

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-f, --file FILE` | string | - | Read domains from file (one per line) |
| `-o, --output DIR` | string | `./reports` | Output directory for reports |
| `-t, --timeout INT` | int | `5` | DNS query timeout in seconds |
| `--no-enum` | flag | false | Skip subdomain enumeration |
| `--skip-tools` | flag | false | Skip external tools |
| `--export-excel` | flag | false | Export to Excel (.xlsx) |
| `--export-csv` | flag | false | Export to CSV |
| `-v, --verbose` | flag | false | Enable verbose output |

### Examples

**Single domain:**
```bash
python main.py example.com
```

**Multiple domains:**
```bash
python main.py example.com example.org example.net
```

**From file:**
```bash
python main.py -f domains.txt
```

**Custom output directory:**
```bash
python main.py example.com -o ./my-reports
```

**With Excel export:**
```bash
python main.py example.com --export-excel
```

**With CSV export:**
```bash
python main.py example.com --export-csv
```

**Fast scan (skip subdomain enumeration):**
```bash
python main.py example.com --no-enum
```

**Fast scan (skip external tools):**
```bash
python main.py example.com --skip-tools
```

**Verbose mode:**
```bash
python main.py example.com -v
```

**Combined options:**
```bash
python main.py example.com -v --export-excel --export-csv -o ./reports
```

**Custom DNS timeout:**
```bash
python main.py example.com -t 10
```

**Scripting example:**
```bash
#!/bin/bash
# Scan multiple organizations

for file in domains/*.txt; do
    org_name=$(basename "$file" .txt)
    python main.py -f "$file" -o "./reports/$org_name" --export-excel -v
done
```

---

## Export Formats

### Markdown (.md)

**Contents:**
- Executive summary
- Domain inventory
- DNS records analysis
- Provider detection results
- Security issues by severity
- Recommendations

**Best for:**
- Human review
- Documentation
- Presentations
- Sharing with non-technical stakeholders

**Location:** `reports/report_YYYYMMDD_HHMMSS.md`

### JSON (.json)

**Contents:**
- Complete structured data
- All analysis results
- Raw DNS records
- Provider detection details
- Full misconfiguration data

**Best for:**
- Integration with other tools
- Automated processing
- API responses
- Data analysis pipelines

**Location:** `reports/results_YYYYMMDD_HHMMSS.json`

### Excel (.xlsx)

**Contents (6 sheets):**

1. **Executive Summary**
   - High-level overview
   - Key metrics
   - Critical issues
   - Provider summary

2. **Domain Inventory**
   - All analyzed domains
   - Email capability status
   - Provider information
   - Issue counts

3. **DNS Records**
   - Complete DNS record details
   - SPF, DKIM, DMARC records
   - MX records
   - Record validity status

4. **Email Providers**
   - Provider usage across domains
   - Configuration details
   - Provider-specific features

5. **Security Findings**
   - All identified issues
   - Severity levels
   - Recommendations
   - Affected domains

6. **Detailed Data**
   - Subdomain enumeration results
   - Complete analysis data
   - Raw findings

**Features:**
- Color-coded severity levels
- Auto-adjusted column widths
- Formatted headers
- Sortable/filterable data

**Best for:**
- Business reporting
- Management presentations
- Detailed analysis
- Pivot tables and charts

**Location:** `reports/analysis_YYYYMMDD_HHMMSS.xlsx`

### CSV

**Contents (multiple files):**
- `domains.csv`: Domain inventory
- `dns_records.csv`: DNS record details
- `findings.csv`: Security issues
- `providers.csv`: Provider information
- `subdomains.csv`: Subdomain enumeration results

**Best for:**
- Database imports
- Custom analysis tools
- Spreadsheet applications
- Data science workflows

**Location:** `reports/csv_YYYYMMDD_HHMMSS/`

---

## Configuration

### Environment Variables (.env)

Create a `.env` file in the project root:

```env
# VirusTotal API Key (optional, enhances subdomain discovery)
VIRUSTOTAL_API_KEY=your_api_key_here

# External Tool Paths
SUBLISTER_PATH=/path/to/Sublist3r/sublist3r.py
AMASS_PATH=amass
SUBFINDER_PATH=subfinder

# Analysis Settings
DNS_TIMEOUT=5
DKIM_SELECTORS=default,google,k1,k2,k3,selector1,selector2,dkim,mail,email,mx
```

### Getting VirusTotal API Key

1. Sign up at https://www.virustotal.com/
2. Go to your profile
3. Copy your API key
4. Add to `.env` file

**Benefits:**
- Additional subdomain sources
- Higher accuracy
- More comprehensive results

**Note:** Free tier has rate limits (4 requests/minute)

### Installing External Tools

#### Subfinder (Recommended)

```bash
# Using Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Or download binary
# Linux
wget https://github.com/projectdiscovery/subfinder/releases/download/v2.x.x/subfinder_2.x.x_linux_amd64.zip
unzip subfinder_2.x.x_linux_amd64.zip
sudo mv subfinder /usr/local/bin/

# macOS
brew install subfinder
```

#### Amass

```bash
# Ubuntu/Debian
sudo apt install amass

# macOS
brew install amass

# Or download from GitHub
# https://github.com/OWASP/Amass/releases
```

#### Sublist3r

```bash
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
pip install -r requirements.txt

# Update .env with path
SUBLISTER_PATH=/full/path/to/Sublist3r/sublist3r.py
```

---

## Advanced Usage

### Batch Processing Multiple Organizations

```bash
#!/bin/bash
# process_organizations.sh

organizations=("company1" "company2" "company3")

for org in "${organizations[@]}"; do
    echo "Processing $org..."
    python main.py -f "domains/${org}.txt" \
        -o "reports/${org}" \
        --export-excel \
        --export-csv \
        -v
done
```

### Automated Scheduling (Cron)

```bash
# Add to crontab: crontab -e

# Run weekly scan every Monday at 2 AM
0 2 * * 1 cd /path/to/analyzer && source venv/bin/activate && python main.py -f domains.txt --export-excel

# Run daily quick scan (no subdomain enum)
0 3 * * * cd /path/to/analyzer && source venv/bin/activate && python main.py -f domains.txt --no-enum --export-excel
```

### Integration with CI/CD

```yaml
# .github/workflows/email-security-scan.yml
name: Email Security Scan

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Run analysis
        env:
          VIRUSTOTAL_API_KEY: ${{ secrets.VIRUSTOTAL_API_KEY }}
        run: |
          python main.py -f domains.txt --export-excel --export-json
      
      - name: Upload reports
        uses: actions/upload-artifact@v2
        with:
          name: security-reports
          path: reports/
```

### Python API Usage

```python
from subdomain_enum import enum_domains
from dns_analyzer import get_dns_records
from provider_detector import detect_email_providers
from excel_exporter import export_to_excel

# Define domains
domains = ['example.com', 'example.org']

# Enumerate subdomains
subdomains = enum_domains(
    domains=domains,
    timeout=5,
    verbose=True
)

# Collect all domains
all_domains = []
for domain_subs in subdomains.values():
    all_domains.extend(domain_subs)

# Analyze DNS
dns_results = get_dns_records(
    domains=all_domains,
    timeout=5,
    verbose=True
)

# Detect providers
provider_results = detect_email_providers(
    dns_results_dict=dns_results,
    verbose=True
)

# Build results dictionary
results = {
    'root_domains': domains,
    'enumeration': subdomains,
    'all_analyzed_domains': all_domains,
    'dns_analysis': dns_results,
    'provider_detection': provider_results
}

# Export to Excel
export_to_excel(results, 'analysis.xlsx', verbose=True)
```

---

## Troubleshooting

### Common Issues

#### "No domains loaded" error
**Problem:** No domains specified for analysis  
**Solution:** 
- Use option 1 or 2 in interactive mode to load domains
- In CLI mode, specify domains or use `-f domains.txt`

#### DNS timeout errors
**Problem:** DNS queries timing out  
**Solution:**
- Increase timeout: `-t 10` or in Settings menu
- Check network connectivity
- Some domains may be slow to respond (normal)

#### External tools not found
**Problem:** Subfinder, Amass, or Sublist3r not installed  
**Solution:**
- Install tools (see Configuration section)
- Update `.env` with correct paths
- Or use `--skip-tools` to disable

#### VirusTotal rate limit exceeded
**Problem:** Too many requests to VirusTotal API  
**Solution:**
- Free tier: 4 requests/minute
- Wait before retrying
- Consider paid tier for higher limits
- Tool automatically handles rate limiting

#### Permission denied errors
**Problem:** Cannot write to output directory  
**Solution:**
- Check directory permissions
- Use `-o` to specify writable directory
- Run with appropriate user permissions

#### Import errors
**Problem:** Module not found errors  
**Solution:**
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install -r requirements.txt
```

#### Excel export fails
**Problem:** Error creating Excel file  
**Solution:**
```bash
# Install required packages
pip install openpyxl pandas

# Check disk space
df -h  # Linux/Mac
```

### Getting Help

**Check logs:**
- Enable verbose mode: `-v` or toggle in Settings
- Review error messages carefully
- Check `reports/` directory for partial results

**Documentation:**
- `README.md`: Overview and quick start
- `SETUP.md`: Installation guide
- `API_DOCS.md`: Developer reference
- `PROJECT_SUMMARY.md`: Feature details

**GitHub Issues:**
- https://github.com/iiyahya/email-attack-surface-analyzer/issues
- Search existing issues
- Provide error logs and system info

---

## Best Practices

### For Accurate Results
1. **Use all available tools**: Install Subfinder, Amass, and Sublist3r
2. **Configure VirusTotal**: Enhances subdomain discovery
3. **Run comprehensive scans**: Don't skip subdomain enumeration
4. **Increase timeout**: For large organizations with many domains

### For Fast Scans
1. **Skip subdomain enumeration**: Use `--no-enum`
2. **Disable external tools**: Use `--skip-tools`
3. **Lower DNS timeout**: Use `-t 3`
4. **Analyze only known domains**: Provide specific list

### For Production Use
1. **Schedule regular scans**: Weekly or monthly
2. **Export to Excel**: For management reporting
3. **Keep historical data**: Compare results over time
4. **Monitor critical issues**: Focus on critical/high severity
5. **Document remediation**: Track fixes and improvements

### Security Considerations
1. **Protect API keys**: Never commit `.env` to version control
2. **Limit scope**: Only scan domains you own or have permission
3. **Rate limiting**: Respect external API limits
4. **Network security**: Be aware of DNS queries leaving network
5. **Data handling**: Protect sensitive results appropriately

---

## Support

For questions, issues, or contributions:
- GitHub: https://github.com/iiyahya/email-attack-surface-analyzer
- Issues: Report bugs or request features
- Pull Requests: Contributions welcome!

---

*Email Attack Surface Analyzer v2.0 - Enterprise Edition*  
*Last Updated: November 18, 2025*
