# Email Attack Surface Analyzer - Enterprise Edition

A comprehensive, enterprise-grade Python tool for analyzing your organization's email security posture. Features an interactive menu system, advanced subdomain enumeration, and multiple export formats including Excel and CSV.

## Features

### 🎯 Interactive Menu System (NEW!)
- User-friendly command-line interface
- Visual ASCII art banner
- Step-by-step workflow guidance
- Real-time configuration management
- Progress tracking and status display

### 🔍 Domain & Subdomain Enumeration
Automatically discover subdomains using multiple sources:
  - **Subfinder** (NEW!) - Fast and efficient subdomain discovery
  - **Sublist3r** (if installed)
  - **Amass** (if installed)
  - **crt.sh** (Certificate Transparency logs)
  - **DNS zone transfer** attempts
  - **VirusTotal API** (optional)

### 🛡️ DNS Email Security Analysis
Extract and analyze:
  - **SPF** (Sender Policy Framework) records
  - **DKIM** (DomainKeys Identified Mail) selectors
  - **DMARC** (Domain-based Message Authentication) policies
  - **MX** (Mail Exchange) records

### 📧 External Email Provider Detection
Identify services like:
  - Google Workspace
  - Microsoft 365
  - Zoho Mail
  - Proofpoint
  - Cloudflare Email
  - And 7+ more providers

### ⚠️ Security Risk Assessment
Detect misconfigurations and vulnerabilities with severity levels

### 📊 Comprehensive Reporting (ENHANCED!)
Generate reports in multiple formats:
  - **Excel (.xlsx)** - Multi-sheet workbooks with formatting (NEW!)
  - **CSV** - Individual data tables for analysis (NEW!)
  - **Markdown (.md)** - Human-readable reports
  - **JSON** - Machine-readable structured data

## Installation

### Prerequisites

Python 3.8 or higher

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Optional External Tools

For enhanced subdomain enumeration, install:

**Subfinder (Recommended):**
```bash
# Using Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Or download binary from: https://github.com/projectdiscovery/subfinder
```

**Sublist3r:**
```bash
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
pip install -r requirements.txt
```

**Amass:**
```bash
# On Ubuntu/Debian
sudo apt install amass

# On macOS
brew install amass

# Or download from: https://github.com/OWASP/Amass
```

## Configuration

Create a `.env` file in the project root (or copy `.env.example`):

```env
# Optional: VirusTotal API Key for additional subdomain discovery
VIRUSTOTAL_API_KEY=your_api_key_here

# Optional: Path to Sublist3r installation
SUBLISTER_PATH=/path/to/Sublist3r/sublist3r.py

# Optional: Path to Amass binary
AMASS_PATH=amass

# Optional: Path to Subfinder binary
SUBFINDER_PATH=subfinder

# Optional: DNS timeout in seconds (default: 5)
DNS_TIMEOUT=5

# Optional: DKIM selectors to check (comma-separated)
DKIM_SELECTORS=default,google,k1,k2,selector1,selector2
```

## Usage

### Interactive Mode (NEW! Recommended)

Launch the interactive menu for guided analysis:

```bash
python main_interactive.py
```

Features:
- 🎯 User-friendly menu navigation
- ⚙️ Real-time configuration management
- 📊 Multiple export format options
- 📈 Analysis progress tracking
- 💡 Built-in help and documentation

### Command-Line Mode (Classic)

**Basic Usage:**

```bash
python main.py example.com
```

**Multiple Domains:**

```bash
python main.py example.com example.org example.net
```

**With Configuration File:**

Create a `domains.txt` file with one domain per line:
```
example.com
example.org
```

Run:
```bash
python main.py -f domains.txt
```

### Command-line Options

```bash
python main.py [domains...] [options]

Arguments:
  domains               One or more root domains to analyze

Options:
  -f, --file FILE      Read domains from a file (one per line)
  -o, --output DIR     Output directory for reports (default: ./reports)
  -t, --timeout INT    DNS query timeout in seconds (default: 5)
  --no-enum            Skip subdomain enumeration
  --skip-tools         Skip external tools (Sublist3r, Amass, Subfinder)
  --export-excel       Export results to Excel format (.xlsx) (NEW!)
  --export-csv         Export results to CSV format (NEW!)
  -v, --verbose        Enable verbose output
```

### Example Commands

```bash
# Interactive mode (recommended for enterprise users)
python main_interactive.py

# Analyze a single domain with verbose output
python main.py example.com -v

# Analyze with Excel export (comprehensive reporting)
python main.py example.com --export-excel

# Analyze with CSV export (data analysis)
python main.py example.com --export-csv

# Analyze with both Excel and CSV
python main.py example.com --export-excel --export-csv

# Analyze multiple domains and save to custom directory
python main.py example.com example.org -o /path/to/reports

# Skip subdomain enumeration, only analyze root domains
python main.py example.com --no-enum

# Skip external tools for faster analysis
python main.py example.com --skip-tools

# Read domains from file with full analysis
python main.py -f domains.txt --export-excel -v
```

## Output Formats

The tool generates multiple output formats in the reports directory:

### 1. Markdown Report (report_TIMESTAMP.md)
Human-readable report with:
   - Executive summary
   - Domain and subdomain inventory
   - DNS security record analysis
   - Email provider detection
   - Security findings and risk ratings
   - Recommendations

### 2. JSON Data (results_TIMESTAMP.json)
Machine-readable JSON with all collected data

### 3. Excel Workbook (analysis_TIMESTAMP.xlsx) - NEW!
Multi-sheet Excel file with:
   - **Executive Summary**: High-level overview and statistics
   - **Domain Inventory**: All discovered domains
   - **DNS Records**: SPF, DKIM, DMARC, MX records
   - **Email Providers**: Detected services and configurations
   - **Security Findings**: Issues with severity levels (color-coded)
   - **Detailed Data**: Complete raw data dump

### 4. CSV Files (csv_TIMESTAMP/) - NEW!
Directory containing multiple CSV files:
   - `domains.csv`: Domain inventory
   - `dns_records.csv`: DNS security records
   - `providers.csv`: Email provider information
   - `findings.csv`: Security issues and recommendations

## Report Sections

### 1. Domain Inventory
- All discovered domains and subdomains
- Sources of discovery

### 2. DNS Security Records
- SPF records and policies
- DKIM selector detection
- DMARC policies and enforcement
- MX records

### 3. Email Provider Detection
- Identified external email services
- Configuration status

### 4. Security Findings
- Missing or misconfigured records
- Risk ratings (Critical, High, Medium, Low)
- Specific vulnerabilities

### 5. Recommendations
- Prioritized action items
- Best practice guidelines

## Project Structure

```
email-attack-surface/
├── main.py                 # Main orchestration script
├── subdomain_enum.py       # Subdomain enumeration module
├── dns_analyzer.py         # DNS record analysis module
├── provider_detector.py    # Email provider detection module
├── report_generator.py     # Report generation module
├── requirements.txt        # Python dependencies
├── .env.example           # Example environment configuration
├── README.md              # This file
└── reports/               # Output directory (created automatically)
```

## Security Considerations

- This tool performs active reconnaissance and DNS queries
- Ensure you have authorization to scan target domains
- Some queries may be logged by target organizations
- Rate limiting is implemented to avoid overwhelming DNS servers
- External tools (Sublist3r, Amass) may have their own rate limits

## Troubleshooting

### DNS Resolution Errors
- Check your internet connection
- Verify DNS server accessibility
- Some domains may have rate limiting

### External Tools Not Found
- Ensure Sublist3r/Amass are installed and paths are correct in .env
- Use `--skip-tools` flag to run without external tools

### Timeout Issues
- Increase timeout with `-t` flag: `python main.py example.com -t 10`
- Some domains may have slow DNS responses

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

MIT License - feel free to use and modify for your needs.

## Disclaimer

This tool is for authorized security assessments only. Users are responsible for ensuring they have permission to scan target domains. The authors assume no liability for misuse.
