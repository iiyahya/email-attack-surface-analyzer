# Quick Start Guide - Email Attack Surface Analyzer

Get started with the Email Attack Surface Analyzer in 5 minutes!

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/iiyahya/email-attack-surface-analyzer.git
cd email-attack-surface-analyzer
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## First Run - Interactive Mode

The easiest way to get started is using the interactive menu:

```bash
python main_interactive.py
```

### Interactive Menu Walkthrough

When you launch the interactive menu, you'll see:

```
╔══════════════════════════════════════════════════════════════════════╗
║              Email Attack Surface Analyzer - Enterprise Edition      ║
╚══════════════════════════════════════════════════════════════════════╝

  MAIN MENU
  
  1. Quick Scan (Enter domains and scan)
  2. Load Domains from File
  3. Configure Settings
  4. Run Full Analysis
  5. Export Results
  6. View Last Results Summary
  7. Help & Documentation
  8. Exit (Q)
```

### Option 1: Quick Scan (Recommended for First-Time Users)

1. Select **1** from the main menu
2. Enter your domain(s) one per line:
   ```
   > example.com
   > company.org
   > 
   ```
3. Press Enter on empty line to finish
4. Choose **Y** to run analysis immediately
5. Wait for analysis to complete
6. Choose export format (Excel recommended for comprehensive reports)

### Option 2: Load Domains from File

1. Create a file with your domains:
   ```bash
   echo "example.com" > domains.txt
   echo "company.org" >> domains.txt
   ```
2. Select **2** from main menu
3. Enter file path: `domains.txt`
4. Select **4** to run full analysis
5. Select **5** to export results

## Command-Line Mode

For automation or scripting:

### Basic Scan

```bash
python main.py example.com
```

### Multiple Domains

```bash
python main.py example.com company.org
```

### With Excel Export

```bash
python main.py example.com --export-excel
```

### From File

```bash
python main.py -f domains.txt --export-excel -v
```

## Understanding Results

### Excel Report (Recommended)

Open the generated `.xlsx` file to view:

- **Executive Summary**: Quick overview of findings
- **Domain Inventory**: All discovered domains
- **DNS Records**: Security configuration status
- **Email Providers**: Detected services
- **Security Findings**: Issues sorted by severity (color-coded)

### Severity Levels

- 🔴 **Critical**: Immediate action required
- 🟠 **High**: Address as soon as possible
- 🟡 **Medium**: Plan to fix
- 🟢 **Low**: Minor issue or informational

## Common Use Cases

### 1. Quick Security Check

```bash
python main.py yourcompany.com --export-excel
```

### 2. Comprehensive Analysis

```bash
python main_interactive.py
# Select Option 1: Quick Scan
# Enter your domain
# Export to Excel + CSV
```

### 3. Automated Monitoring

```bash
# Add to cron job or scheduled task
python main.py -f domains.txt --export-excel -o ./daily-reports
```

### 4. Subdomain Discovery Only

```bash
python main.py example.com -v
# Check the domain inventory in the report
```

### 5. Fast Analysis (Skip External Tools)

```bash
python main.py example.com --skip-tools
```

## Configuration (Optional)

For enhanced features, create a `.env` file:

```env
# Optional: For more subdomain discovery
VIRUSTOTAL_API_KEY=your_api_key_here

# Optional: External tool paths
SUBFINDER_PATH=/usr/local/bin/subfinder
AMASS_PATH=/usr/local/bin/amass
SUBLISTER_PATH=/path/to/Sublist3r/sublist3r.py

# Optional: Adjust timeouts
DNS_TIMEOUT=5
```

## External Tools (Optional)

For maximum subdomain discovery, install these tools:

### Subfinder (Recommended)

```bash
# Install via Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Or download binary from GitHub
# https://github.com/projectdiscovery/subfinder
```

### Amass

```bash
# Ubuntu/Debian
sudo apt install amass

# macOS
brew install amass

# Or download from GitHub
# https://github.com/OWASP/Amass
```

### Sublist3r

```bash
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
pip install -r requirements.txt
```

## Troubleshooting

### Issue: No subdomains found

**Solution**: Enable external tools in settings or use VirusTotal API key

### Issue: Timeout errors

**Solution**: Increase DNS timeout in settings (Option 3) or `.env` file

### Issue: Permission denied

**Solution**: Ensure you're in the virtual environment:
```bash
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

### Issue: Module not found

**Solution**: Install dependencies:
```bash
pip install -r requirements.txt
```

## Next Steps

1. ✅ Run your first scan
2. 📊 Review the Excel report
3. 🔧 Fix identified security issues
4. 📖 Read [README.md](README.md) for advanced features
5. 🔐 Configure external tools for comprehensive discovery
6. 🤖 Set up automated monitoring

## Support

- **Documentation**: See [README.md](README.md), [SETUP.md](SETUP.md), and [API_DOCS.md](API_DOCS.md)
- **Issues**: Report bugs on GitHub
- **Examples**: Check the `examples/` directory

## Tips for Best Results

✅ **Do:**
- Run scans during off-peak hours
- Export to Excel for executive reporting
- Use interactive mode for guided workflows
- Enable verbose mode to understand what's happening
- Review all severity levels, not just critical

❌ **Don't:**
- Scan domains you don't own or have permission to test
- Ignore low-severity findings (they can compound)
- Skip subdomain enumeration (it finds hidden attack surface)
- Forget to update external tools regularly

---

**Ready to scan?** Start with the interactive menu:

```bash
python main_interactive.py
```

Happy analyzing! 🔍🛡️
