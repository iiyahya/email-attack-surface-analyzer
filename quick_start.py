#!/usr/bin/env python3
"""
Quick Start Example for Email Attack Surface Analyzer

This script demonstrates basic usage of the analyzer.
"""

from subdomain_enum import enum_domains
from dns_analyzer import get_dns_records, assess_security_posture
from provider_detector import detect_email_providers
from report_generator import generate_report

def quick_analysis(domain: str):
    """
    Perform a quick analysis of a single domain.
    
    Args:
        domain: Domain to analyze (e.g., 'example.com')
    """
    print(f"Analyzing {domain}...\n")
    
    # Step 1: Enumerate subdomains
    print("[1/4] Enumerating subdomains...")
    enumeration = enum_domains(
        domains=[domain],
        timeout=5,
        verbose=False,
        use_external_tools=False  # Faster without external tools
    )
    
    all_domains = enumeration[domain]
    print(f"Found {len(all_domains)} domains/subdomains\n")
    
    # Step 2: Analyze DNS records
    print("[2/4] Analyzing DNS records...")
    dns_results = get_dns_records(
        domains=all_domains,
        timeout=5,
        verbose=False
    )
    
    # Count domains with email
    email_domains = [d for d, r in dns_results.items() if r['has_email']]
    print(f"{len(email_domains)} domains have email capability\n")
    
    # Step 3: Detect providers and issues
    print("[3/4] Detecting email providers and issues...")
    provider_results = detect_email_providers(
        dns_results_dict=dns_results,
        verbose=False
    )
    
    # Step 4: Generate report
    print("[4/4] Generating report...")
    
    analysis_results = {
        'root_domains': [domain],
        'enumeration': enumeration,
        'all_analyzed_domains': all_domains,
        'dns_analysis': dns_results,
        'provider_detection': provider_results
    }
    
    reports = generate_report(
        analysis_results=analysis_results,
        output_dir='./reports',
        verbose=False
    )
    
    print("\n" + "="*50)
    print("ANALYSIS COMPLETE")
    print("="*50)
    
    # Print summary
    for d in email_domains[:5]:  # Show first 5
        dns_data = dns_results[d]
        provider_data = provider_results[d]
        
        print(f"\nDomain: {d}")
        print(f"  SPF: {'✓' if dns_data['spf']['valid'] else '✗'}")
        print(f"  DMARC: {'✓' if dns_data['dmarc']['valid'] else '✗'}")
        print(f"  DKIM Selectors: {len(dns_data['dkim']['selectors_found'])}")
        
        providers = provider_data['providers']['providers']
        if providers:
            print(f"  Provider: {providers[0]}")
        
        issues = len(provider_data['misconfigurations'])
        if issues > 0:
            print(f"  ⚠ {issues} security issues found")
    
    print(f"\nReports saved to:")
    print(f"  - {reports['markdown']}")
    print(f"  - {reports['json']}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python quick_start.py <domain>")
        print("Example: python quick_start.py example.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    quick_analysis(domain)
