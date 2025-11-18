# Email Attack Surface Analyzer - API Documentation

## Module Reference

This document provides detailed API documentation for developers who want to use the tool's modules programmatically.

---

## Table of Contents

1. [subdomain_enum Module](#subdomain_enum-module)
2. [dns_analyzer Module](#dns_analyzer-module)
3. [provider_detector Module](#provider_detector-module)
4. [report_generator Module](#report_generator-module)

---

## subdomain_enum Module

### Classes

#### `SubdomainEnumerator`

Main class for subdomain enumeration.

**Constructor:**
```python
SubdomainEnumerator(timeout: int = 5, verbose: bool = False)
```

**Parameters:**
- `timeout` (int): Timeout in seconds for HTTP requests (default: 5)
- `verbose` (bool): Enable verbose output (default: False)

**Methods:**

##### `enumerate_all()`
```python
enumerate_all(
    domain: str,
    use_external_tools: bool = True,
    virustotal_api_key: str = None,
    sublister_path: str = None,
    amass_path: str = None
) -> Set[str]
```

Enumerate subdomains using all available methods.

**Parameters:**
- `domain` (str): Root domain to enumerate
- `use_external_tools` (bool): Whether to use Sublist3r and Amass
- `virustotal_api_key` (str, optional): VirusTotal API key
- `sublister_path` (str, optional): Path to Sublist3r script
- `amass_path` (str, optional): Path to Amass binary

**Returns:**
- Set[str]: Set of discovered subdomains

**Example:**
```python
from subdomain_enum import SubdomainEnumerator

enumerator = SubdomainEnumerator(timeout=10, verbose=True)
subdomains = enumerator.enumerate_all(
    domain='example.com',
    use_external_tools=False
)

print(f"Found {len(subdomains)} subdomains")
for subdomain in subdomains:
    print(f"  - {subdomain}")
```

### Functions

#### `enum_domains()`
```python
enum_domains(
    domains: List[str],
    timeout: int = 5,
    verbose: bool = False,
    use_external_tools: bool = True,
    virustotal_api_key: str = None,
    sublister_path: str = None,
    amass_path: str = None
) -> dict
```

Enumerate subdomains for multiple root domains.

**Parameters:**
- `domains` (List[str]): List of root domains to enumerate
- `timeout` (int): Timeout in seconds for requests
- `verbose` (bool): Enable verbose output
- `use_external_tools` (bool): Whether to use external tools
- `virustotal_api_key` (str, optional): VirusTotal API key
- `sublister_path` (str, optional): Path to Sublist3r script
- `amass_path` (str, optional): Path to Amass binary

**Returns:**
- dict: Dictionary mapping each root domain to its discovered subdomains

**Example:**
```python
from subdomain_enum import enum_domains

results = enum_domains(
    domains=['example.com', 'example.org'],
    timeout=5,
    verbose=True,
    use_external_tools=False
)

for domain, subdomains in results.items():
    print(f"{domain}: {len(subdomains)} subdomains found")
```

---

## dns_analyzer Module

### Classes

#### `DNSAnalyzer`

Main class for DNS record analysis.

**Constructor:**
```python
DNSAnalyzer(timeout: int = 5, retries: int = 2, verbose: bool = False)
```

**Parameters:**
- `timeout` (int): DNS query timeout in seconds (default: 5)
- `retries` (int): Number of retries for failed queries (default: 2)
- `verbose` (bool): Enable verbose output (default: False)

**Methods:**

##### `analyze_domain()`
```python
analyze_domain(domain: str, dkim_selectors: List[str] = None) -> Dict
```

Perform comprehensive DNS email security analysis.

**Parameters:**
- `domain` (str): Domain to analyze
- `dkim_selectors` (List[str], optional): List of DKIM selectors to check

**Returns:**
- Dict: Dictionary containing all DNS analysis results

**Return Structure:**
```python
{
    'domain': str,
    'spf': {
        'record': str,
        'valid': bool,
        'mechanisms': List[str],
        'all_mechanism': str,
        'includes': List[str],
        'ip4': List[str],
        'ip6': List[str],
        'errors': List[str]
    },
    'dmarc': {
        'record': str,
        'valid': bool,
        'policy': str,
        'subdomain_policy': str,
        'percentage': int,
        'rua': List[str],
        'ruf': List[str],
        'alignment_spf': str,
        'alignment_dkim': str,
        'errors': List[str]
    },
    'dkim': {
        'selectors_found': List[str],
        'selectors_checked': List[str],
        'records': Dict[str, Dict]
    },
    'mx': {
        'records': List[Dict],
        'servers': List[str],
        'errors': List[str]
    },
    'has_email': bool,
    'errors': List[str]
}
```

**Example:**
```python
from dns_analyzer import DNSAnalyzer

analyzer = DNSAnalyzer(timeout=5, verbose=True)
result = analyzer.analyze_domain('example.com')

print(f"Domain: {result['domain']}")
print(f"Has Email: {result['has_email']}")
print(f"SPF Valid: {result['spf']['valid']}")
print(f"DMARC Valid: {result['dmarc']['valid']}")
print(f"DKIM Selectors: {result['dkim']['selectors_found']}")
```

##### `get_spf_record()`
```python
get_spf_record(domain: str) -> Dict
```

Retrieve and parse SPF record.

**Example:**
```python
spf = analyzer.get_spf_record('example.com')
if spf['valid']:
    print(f"SPF: {spf['record']}")
    print(f"Policy: {spf['all_mechanism']}")
```

##### `get_dmarc_record()`
```python
get_dmarc_record(domain: str) -> Dict
```

Retrieve and parse DMARC record.

**Example:**
```python
dmarc = analyzer.get_dmarc_record('example.com')
if dmarc['valid']:
    print(f"DMARC: {dmarc['record']}")
    print(f"Policy: {dmarc['policy']}")
```

##### `get_dkim_records()`
```python
get_dkim_records(domain: str, selectors: List[str]) -> Dict
```

Retrieve DKIM records for specified selectors.

**Example:**
```python
dkim = analyzer.get_dkim_records('example.com', ['google', 'default'])
print(f"Found selectors: {dkim['selectors_found']}")
```

##### `get_mx_records()`
```python
get_mx_records(domain: str) -> Dict
```

Retrieve MX records.

**Example:**
```python
mx = analyzer.get_mx_records('example.com')
for record in mx['records']:
    print(f"Priority {record['priority']}: {record['server']}")
```

### Functions

#### `get_dns_records()`
```python
get_dns_records(
    domains: List[str],
    timeout: int = 5,
    retries: int = 2,
    verbose: bool = False,
    dkim_selectors: List[str] = None
) -> Dict
```

Get DNS email security records for multiple domains.

**Example:**
```python
from dns_analyzer import get_dns_records

results = get_dns_records(
    domains=['example.com', 'example.org'],
    timeout=5,
    verbose=True
)

for domain, data in results.items():
    print(f"{domain}: {data['has_email']}")
```

#### `assess_security_posture()`
```python
assess_security_posture(dns_results: Dict) -> Dict
```

Assess security posture based on DNS records.

**Parameters:**
- `dns_results` (Dict): DNS analysis results from `analyze_domain()`

**Returns:**
- Dict: Security assessment with risk level, score, findings, and recommendations

**Return Structure:**
```python
{
    'risk_level': str,  # 'low', 'medium', 'high', 'critical'
    'score': int,       # 0-100
    'findings': List[str],
    'recommendations': List[str]
}
```

**Example:**
```python
from dns_analyzer import DNSAnalyzer, assess_security_posture

analyzer = DNSAnalyzer()
dns_data = analyzer.analyze_domain('example.com')
assessment = assess_security_posture(dns_data)

print(f"Risk Level: {assessment['risk_level']}")
print(f"Score: {assessment['score']}/100")
print("\nFindings:")
for finding in assessment['findings']:
    print(f"  - {finding}")
```

---

## provider_detector Module

### Classes

#### `EmailProviderDetector`

Main class for email provider detection.

**Constructor:**
```python
EmailProviderDetector(verbose: bool = False)
```

**Parameters:**
- `verbose` (bool): Enable verbose output (default: False)

**Methods:**

##### `detect_providers()`
```python
detect_providers(dns_results: Dict) -> Dict
```

Detect email providers from DNS analysis results.

**Parameters:**
- `dns_results` (Dict): DNS analysis results from DNSAnalyzer

**Returns:**
- Dict: Detected providers with confidence levels

**Return Structure:**
```python
{
    'providers': List[str],
    'confidence': Dict[str, int],
    'details': Dict[str, Dict]
}
```

**Example:**
```python
from provider_detector import EmailProviderDetector

detector = EmailProviderDetector(verbose=True)
provider_info = detector.detect_providers(dns_results)

print("Detected Providers:")
for provider in provider_info['providers']:
    confidence = provider_info['confidence'][provider]
    print(f"  {provider}: {confidence}% confidence")
```

##### `detect_misconfigurations()`
```python
detect_misconfigurations(dns_results: Dict, provider_info: Dict) -> List[Dict]
```

Detect security misconfigurations.

**Parameters:**
- `dns_results` (Dict): DNS analysis results
- `provider_info` (Dict): Detected provider information

**Returns:**
- List[Dict]: List of misconfiguration findings

**Misconfiguration Structure:**
```python
{
    'severity': str,      # 'critical', 'high', 'medium', 'low'
    'type': str,
    'title': str,
    'description': str,
    'remediation': str
}
```

**Example:**
```python
misconfigs = detector.detect_misconfigurations(dns_results, provider_info)

for misc in misconfigs:
    print(f"[{misc['severity'].upper()}] {misc['title']}")
    print(f"  {misc['description']}")
    print(f"  Fix: {misc['remediation']}")
```

### Functions

#### `detect_email_providers()`
```python
detect_email_providers(
    dns_results_dict: Dict,
    verbose: bool = False
) -> Dict
```

Detect email providers for multiple domains.

**Example:**
```python
from provider_detector import detect_email_providers

provider_results = detect_email_providers(
    dns_results_dict=dns_analysis,
    verbose=True
)

for domain, results in provider_results.items():
    providers = results['providers']['providers']
    misconfigs = results['misconfigurations']
    risk = results['risk_score']
    
    print(f"\n{domain}:")
    print(f"  Providers: {', '.join(providers)}")
    print(f"  Issues: {len(misconfigs)}")
    print(f"  Risk: {risk['level']}")
```

#### `calculate_risk_score()`
```python
calculate_risk_score(misconfigurations: List[Dict]) -> Dict
```

Calculate risk score based on misconfigurations.

**Returns:**
```python
{
    'score': int,
    'level': str,
    'severity_counts': Dict[str, int]
}
```

**Example:**
```python
from provider_detector import calculate_risk_score

risk = calculate_risk_score(misconfigurations)
print(f"Risk Score: {risk['score']}")
print(f"Risk Level: {risk['level']}")
print(f"Critical Issues: {risk['severity_counts']['critical']}")
```

---

## report_generator Module

### Classes

#### `ReportGenerator`

Main class for report generation.

**Constructor:**
```python
ReportGenerator(verbose: bool = False)
```

**Methods:**

##### `generate_markdown_report()`
```python
generate_markdown_report(
    analysis_results: Dict,
    output_file: str = None
) -> str
```

Generate comprehensive Markdown report.

**Parameters:**
- `analysis_results` (Dict): Complete analysis results
- `output_file` (str, optional): File path to save report

**Returns:**
- str: Markdown report as string

**Example:**
```python
from report_generator import ReportGenerator

generator = ReportGenerator(verbose=True)

analysis_results = {
    'root_domains': ['example.com'],
    'enumeration': {...},
    'all_analyzed_domains': [...],
    'dns_analysis': {...},
    'provider_detection': {...}
}

markdown = generator.generate_markdown_report(
    analysis_results=analysis_results,
    output_file='./reports/report.md'
)

print(markdown)  # Print report content
```

##### `generate_json_report()`
```python
generate_json_report(
    analysis_results: Dict,
    output_file: str = None
) -> str
```

Generate machine-readable JSON report.

**Example:**
```python
import json

json_str = generator.generate_json_report(
    analysis_results=analysis_results,
    output_file='./reports/results.json'
)

data = json.loads(json_str)
print(data['metadata']['generated_at'])
```

### Functions

#### `generate_report()`
```python
generate_report(
    analysis_results: Dict,
    output_dir: str = ".",
    verbose: bool = False
) -> Dict
```

Generate both Markdown and JSON reports.

**Parameters:**
- `analysis_results` (Dict): Complete analysis results
- `output_dir` (str): Directory to save reports
- `verbose` (bool): Enable verbose output

**Returns:**
- Dict: Paths to generated reports

**Return Structure:**
```python
{
    'markdown': str,  # Path to Markdown report
    'json': str       # Path to JSON report
}
```

**Example:**
```python
from report_generator import generate_report

report_files = generate_report(
    analysis_results=results,
    output_dir='./reports',
    verbose=True
)

print(f"Markdown: {report_files['markdown']}")
print(f"JSON: {report_files['json']}")
```

---

## Complete Example

### Full Analysis Workflow

```python
#!/usr/bin/env python3
"""
Complete analysis workflow example.
"""

from subdomain_enum import enum_domains
from dns_analyzer import get_dns_records, assess_security_posture
from provider_detector import detect_email_providers
from report_generator import generate_report

def analyze_organization(domains, output_dir='./reports'):
    """
    Perform complete email attack surface analysis.
    
    Args:
        domains: List of root domains
        output_dir: Output directory for reports
    
    Returns:
        Dictionary with complete analysis results
    """
    
    # Step 1: Enumerate subdomains
    print("[1/4] Enumerating subdomains...")
    enumeration = enum_domains(
        domains=domains,
        timeout=5,
        verbose=True,
        use_external_tools=False
    )
    
    # Collect all domains
    all_domains = []
    for domain_list in enumeration.values():
        all_domains.extend(domain_list)
    all_domains = list(set(all_domains))
    
    print(f"Found {len(all_domains)} unique domains\n")
    
    # Step 2: Analyze DNS records
    print("[2/4] Analyzing DNS records...")
    dns_results = get_dns_records(
        domains=all_domains,
        timeout=5,
        verbose=True
    )
    
    # Step 3: Detect providers and issues
    print("[3/4] Detecting providers and issues...")
    provider_results = detect_email_providers(
        dns_results_dict=dns_results,
        verbose=True
    )
    
    # Step 4: Generate reports
    print("[4/4] Generating reports...")
    
    analysis_results = {
        'root_domains': domains,
        'enumeration': enumeration,
        'all_analyzed_domains': all_domains,
        'dns_analysis': dns_results,
        'provider_detection': provider_results
    }
    
    report_files = generate_report(
        analysis_results=analysis_results,
        output_dir=output_dir,
        verbose=True
    )
    
    print("\nAnalysis complete!")
    print(f"Markdown report: {report_files['markdown']}")
    print(f"JSON report: {report_files['json']}")
    
    return analysis_results


if __name__ == "__main__":
    # Analyze your domains
    results = analyze_organization(
        domains=['example.com', 'example.org']
    )
    
    # Access specific results
    for domain in results['root_domains']:
        subdomains = results['enumeration'][domain]
        print(f"\n{domain}: {len(subdomains)} subdomains")
        
        # Check email domains
        email_domains = [
            d for d in subdomains
            if results['dns_analysis'][d]['has_email']
        ]
        print(f"  Email domains: {len(email_domains)}")
        
        # Check for issues
        for email_domain in email_domains:
            misconfigs = results['provider_detection'][email_domain]['misconfigurations']
            if misconfigs:
                print(f"  {email_domain}: {len(misconfigs)} issues found")
```

---

## Error Handling

All modules implement proper error handling:

```python
try:
    from dns_analyzer import DNSAnalyzer
    
    analyzer = DNSAnalyzer(timeout=5)
    result = analyzer.analyze_domain('invalid-domain-12345.com')
    
    # Check for errors
    if result['spf']['errors']:
        print(f"SPF errors: {result['spf']['errors']}")
    
    if result['dmarc']['errors']:
        print(f"DMARC errors: {result['dmarc']['errors']}")
    
except Exception as e:
    print(f"Analysis failed: {e}")
```

---

## Type Hints

All functions use type hints for better IDE support:

```python
from typing import List, Dict, Set, Optional

def enum_domains(
    domains: List[str],
    timeout: int = 5,
    verbose: bool = False
) -> Dict[str, List[str]]:
    ...
```

---

## Best Practices

### 1. Use Context Managers for Resources

```python
import os
from contextlib import contextmanager

@contextmanager
def analysis_session():
    """Create analysis session with cleanup."""
    # Setup
    os.makedirs('./temp', exist_ok=True)
    
    yield
    
    # Cleanup
    # ... cleanup code ...

with analysis_session():
    results = analyze_organization(['example.com'])
```

### 2. Implement Rate Limiting

```python
import time

def analyze_many_domains(domains, rate_limit=1.0):
    """Analyze domains with rate limiting."""
    results = {}
    
    for domain in domains:
        result = analyze_domain(domain)
        results[domain] = result
        time.sleep(rate_limit)  # Rate limit
    
    return results
```

### 3. Use Logging

```python
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

logger.info("Starting analysis")
logger.warning("Timeout occurred")
logger.error("Analysis failed")
```

---

## Thread Safety

The modules are generally thread-safe for reading, but use caution with:
- DNS resolver instances (create per-thread)
- HTTP session objects (use session pools)
- File I/O operations (use locks)

```python
from concurrent.futures import ThreadPoolExecutor
from dns_analyzer import DNSAnalyzer

def analyze_domain_wrapper(domain):
    # Create new analyzer per thread
    analyzer = DNSAnalyzer()
    return analyzer.analyze_domain(domain)

with ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(analyze_domain_wrapper, domains)
```

---

## Performance Optimization

### Batch Processing

```python
def batch_analyze(domains, batch_size=10):
    """Analyze domains in batches."""
    results = {}
    
    for i in range(0, len(domains), batch_size):
        batch = domains[i:i+batch_size]
        batch_results = get_dns_records(batch)
        results.update(batch_results)
        
        print(f"Processed {i+len(batch)}/{len(domains)}")
    
    return results
```

### Caching Results

```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def cached_dns_lookup(domain, record_type):
    """Cache DNS lookups."""
    # ... DNS query code ...
    return result
```

---

## Debugging

Enable verbose output for debugging:

```python
# Enable verbose output
enumerator = SubdomainEnumerator(verbose=True)
analyzer = DNSAnalyzer(verbose=True)
detector = EmailProviderDetector(verbose=True)
generator = ReportGenerator(verbose=True)
```

Use Python debugger:

```python
import pdb

# Set breakpoint
pdb.set_trace()

# Or use breakpoint() in Python 3.7+
breakpoint()
```

---

## Contributing

To extend the modules:

1. Follow existing code structure
2. Add type hints
3. Write docstrings
4. Handle errors gracefully
5. Add tests
6. Update documentation

---

## Support

For API questions or issues, please refer to:
- Module source code comments
- README.md for usage examples
- SETUP.md for installation help
- PROJECT_SUMMARY.md for overview
