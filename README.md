# Email Attack Surface Analyzer

A comprehensive Python tool for analyzing your organization's email security posture by enumerating domains, checking DNS security records (SPF, DKIM, DMARC), and identifying potential vulnerabilities.

## Features

- **Domain & Subdomain Enumeration**: Automatically discover subdomains using multiple sources:
  - Sublist3r (if installed)
  - Amass (if installed)
  - crt.sh (Certificate Transparency logs)
  - DNS zone transfer attempts
  - VirusTotal API (optional)

- **DNS Email Security Analysis**: Extract and analyze:
  - SPF (Sender Policy Framework) records
  - DKIM (DomainKeys Identified Mail) selectors
  - DMARC (Domain-based Message Authentication) policies
  - MX (Mail Exchange) records

- **External Email Provider Detection**: Identify services like:
  - Google Workspace
  - Microsoft 365
  - Zoho Mail
  - Proofpoint
  - Cloudflare Email

- **Security Risk Assessment**: Detect misconfigurations and vulnerabilities

- **Comprehensive Reporting**: Generate both Markdown and JSON reports

## Installation

### Prerequisites

Python 3.8 or higher

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Optional External Tools

For enhanced subdomain enumeration, install:

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

Create a `.env` file in the project root:

```env
# Optional: VirusTotal API Key for additional subdomain discovery
VIRUSTOTAL_API_KEY=your_api_key_here

# Optional: Path to Sublist3r installation
SUBLISTER_PATH=/path/to/Sublist3r/sublist3r.py

# Optional: Path to Amass binary
AMASS_PATH=amass
```

## Usage

### Basic Usage

```bash
python main.py example.com
```

### Multiple Domains

```bash
python main.py example.com example.org example.net
```

### With Configuration File

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
  --skip-tools         Skip external tools (Sublist3r, Amass)
  -v, --verbose        Enable verbose output
```

### Example Commands

```bash
# Analyze a single domain with verbose output
python main.py example.com -v

# Analyze multiple domains and save to custom directory
python main.py example.com example.org -o /path/to/reports

# Skip subdomain enumeration, only analyze root domains
python main.py example.com --no-enum

# Read domains from file
python main.py -f domains.txt
```

## Output

The tool generates two types of output files in the reports directory:

1. **report_TIMESTAMP.md**: Human-readable Markdown report with:
   - Executive summary
   - Domain and subdomain inventory
   - DNS security record analysis
   - Email provider detection
   - Security findings and risk ratings
   - Recommendations

2. **results_TIMESTAMP.json**: Machine-readable JSON with all collected data

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
