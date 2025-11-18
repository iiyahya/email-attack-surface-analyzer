# Email Attack Surface Analyzer - Setup Guide

## Quick Setup

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. (Optional) Create Configuration File

Copy the example configuration:

```bash
cp .env.example .env
```

Edit `.env` and add your API keys:

```env
VIRUSTOTAL_API_KEY=your_api_key_here
```

### 3. Test Installation

Run the test suite to verify everything works:

```bash
python test_installation.py
```

### 4. Run Your First Analysis

Try the quick start script:

```bash
python quick_start.py example.com
```

Or use the full tool:

```bash
python main.py example.com -v
```

---

## Detailed Setup Instructions

### Prerequisites

- **Python 3.8+** (Check with: `python --version`)
- **pip** (Check with: `pip --version`)
- **Internet connection** (for DNS queries and API calls)

### Step-by-Step Installation

#### 1. Clone or Download the Project

If you have the project in a directory, navigate to it:

```bash
cd /path/to/email-attack-surface
```

#### 2. (Recommended) Create Virtual Environment

Create an isolated Python environment:

```bash
# On Windows
python -m venv venv
venv\Scripts\activate

# On Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

#### 3. Install Required Packages

```bash
pip install -r requirements.txt
```

This installs:
- `dnspython` - DNS query library
- `requests` - HTTP library
- `beautifulsoup4` - HTML parsing
- `python-dotenv` - Environment variable management
- `colorama` - Colored terminal output
- `tabulate` - Table formatting

#### 4. Verify Installation

Run the test suite:

```bash
python test_installation.py
```

Expected output:
```
[TEST] Testing module imports...
  ✓ dnspython
  ✓ requests
  ✓ beautifulsoup4
  ...
  
Total: 6/6 tests passed
✓ All tests passed! The tool is ready to use.
```

---

## Optional: External Tools Setup

For enhanced subdomain discovery, you can install these optional tools:

### Sublist3r

```bash
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
pip install -r requirements.txt
cd ..
```

Add to your `.env` file:
```env
SUBLISTER_PATH=/path/to/Sublist3r/sublist3r.py
```

### Amass

**On Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install amass
```

**On macOS:**
```bash
brew install amass
```

**On Windows:**
Download from: https://github.com/OWASP/Amass/releases

Add to your `.env` file:
```env
AMASS_PATH=amass
```

---

## Configuration Options

### Environment Variables (.env file)

```env
# Optional: VirusTotal API Key
# Get yours at: https://www.virustotal.com/gui/user/apikey
VIRUSTOTAL_API_KEY=your_key_here

# Optional: Sublist3r Path
SUBLISTER_PATH=/path/to/Sublist3r/sublist3r.py

# Optional: Amass Binary Path
AMASS_PATH=amass

# DNS Settings
DNS_TIMEOUT=5
DNS_RETRIES=2

# DKIM Selectors to Check
DKIM_SELECTORS=default,google,k1,k2,selector1,selector2
```

### Command-Line Options

```bash
python main.py --help
```

Common options:
- `-f, --file` - Read domains from file
- `-o, --output` - Output directory (default: ./reports)
- `-t, --timeout` - DNS timeout in seconds (default: 5)
- `--no-enum` - Skip subdomain enumeration
- `--skip-tools` - Skip external tools
- `-v, --verbose` - Verbose output

---

## Usage Examples

### Basic Usage

Analyze a single domain:
```bash
python main.py example.com
```

### Multiple Domains

```bash
python main.py example.com example.org example.net
```

### From File

Create `domains.txt`:
```
example.com
example.org
example.net
```

Run:
```bash
python main.py -f domains.txt
```

### With Verbose Output

```bash
python main.py example.com -v
```

### Skip Subdomain Enumeration

Analyze only the root domain:
```bash
python main.py example.com --no-enum
```

### Custom Output Directory

```bash
python main.py example.com -o /path/to/reports
```

### Skip External Tools

Faster analysis without Sublist3r/Amass:
```bash
python main.py example.com --skip-tools
```

---

## Troubleshooting

### ImportError: No module named 'dns'

**Solution:**
```bash
pip install dnspython
```

### DNS Resolution Errors

**Causes:**
- No internet connection
- DNS server issues
- Firewall blocking DNS queries

**Solutions:**
1. Check internet connection
2. Try a different DNS server:
   ```python
   # Add to dns_analyzer.py
   self.resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Google DNS
   ```

### Timeout Issues

**Solution:** Increase timeout:
```bash
python main.py example.com -t 10
```

### External Tools Not Found

**For Sublist3r:**
```bash
# Verify path in .env
SUBLISTER_PATH=/absolute/path/to/Sublist3r/sublist3r.py
```

**For Amass:**
```bash
# Check if installed
which amass  # Linux/Mac
where amass  # Windows
```

### Permission Errors (Reports Directory)

**Solution:**
```bash
# Create directory manually
mkdir reports

# Or specify different directory
python main.py example.com -o ~/my-reports
```

---

## Performance Tips

### 1. Skip External Tools for Speed

External tools (Sublist3r, Amass) can be slow:
```bash
python main.py example.com --skip-tools
```

### 2. Adjust Timeout

For slow DNS servers, increase timeout:
```bash
python main.py example.com -t 10
```

### 3. Analyze Only Root Domain

Skip subdomain enumeration:
```bash
python main.py example.com --no-enum
```

### 4. Use Quick Start Script

For basic analysis:
```bash
python quick_start.py example.com
```

---

## Security Considerations

### Legal Authorization

⚠️ **IMPORTANT:** Only scan domains you own or have explicit permission to scan.

### Rate Limiting

The tool implements basic rate limiting, but be aware:
- crt.sh may rate limit aggressive queries
- DNS servers may rate limit/block excessive queries
- VirusTotal API has rate limits

### Network Activity

This tool performs:
- DNS queries (TXT, MX, NS records)
- HTTP requests to crt.sh
- Optional API calls to VirusTotal
- Optional subprocess calls to Sublist3r/Amass

### Logging

Some activities may be logged by:
- Target domain DNS servers
- Certificate Transparency logs (already public)
- Third-party APIs (VirusTotal)

---

## Next Steps

1. **Run Test Suite:**
   ```bash
   python test_installation.py
   ```

2. **Try Quick Start:**
   ```bash
   python quick_start.py example.com
   ```

3. **Run Full Analysis:**
   ```bash
   python main.py example.com -v
   ```

4. **Review Reports:**
   - Check `./reports/report_*.md` for human-readable report
   - Check `./reports/results_*.json` for machine-readable data

5. **Customize:**
   - Edit `.env` for your environment
   - Add more DKIM selectors
   - Configure API keys

---

## Getting Help

### Check Verbose Output

Add `-v` flag for detailed output:
```bash
python main.py example.com -v
```

### Run Tests

```bash
python test_installation.py
```

### Common Issues

1. **No results:** Domain may not have email configured
2. **Timeouts:** Increase timeout with `-t` flag
3. **Import errors:** Run `pip install -r requirements.txt`
4. **External tools fail:** Use `--skip-tools` flag

---

## Project Structure

```
email-attack-surface/
├── main.py                 # Main entry point
├── subdomain_enum.py       # Subdomain enumeration
├── dns_analyzer.py         # DNS record analysis
├── provider_detector.py    # Email provider detection
├── report_generator.py     # Report generation
├── quick_start.py          # Quick start example
├── test_installation.py    # Test suite
├── requirements.txt        # Python dependencies
├── .env.example           # Configuration template
├── domains.txt.example    # Domain list template
├── README.md              # Main documentation
├── SETUP.md              # This file
├── LICENSE               # License information
└── reports/              # Output directory (created automatically)
```

---

## Support

For issues, questions, or contributions:

1. Check this SETUP.md guide
2. Review README.md for usage examples
3. Run test_installation.py to diagnose issues
4. Check verbose output with `-v` flag

**Disclaimer:** This tool is for authorized security assessments only. Always ensure you have permission to scan target domains.
