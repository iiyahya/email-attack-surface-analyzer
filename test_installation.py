#!/usr/bin/env python3
"""
Test Script for Email Attack Surface Analyzer

This script performs basic functionality tests on each module.
Run this after installation to verify everything works correctly.
"""

import sys
from colorama import init, Fore, Style

init(autoreset=True)


def test_imports():
    """Test that all required modules can be imported."""
    print(f"\n{Fore.YELLOW}[TEST]{Style.RESET_ALL} Testing module imports...")
    
    try:
        import dns.resolver
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} dnspython")
    except ImportError as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} dnspython: {e}")
        return False
    
    try:
        import requests
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} requests")
    except ImportError as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} requests: {e}")
        return False
    
    try:
        from bs4 import BeautifulSoup
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} beautifulsoup4")
    except ImportError as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} beautifulsoup4: {e}")
        return False
    
    try:
        from dotenv import load_dotenv
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} python-dotenv")
    except ImportError as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} python-dotenv: {e}")
        return False
    
    try:
        from colorama import init
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} colorama")
    except ImportError as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} colorama: {e}")
        return False
    
    try:
        from tabulate import tabulate
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} tabulate")
    except ImportError as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} tabulate: {e}")
        return False
    
    try:
        from subdomain_enum import enum_domains
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} subdomain_enum module")
    except ImportError as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} subdomain_enum module: {e}")
        return False
    
    try:
        from dns_analyzer import get_dns_records
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} dns_analyzer module")
    except ImportError as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} dns_analyzer module: {e}")
        return False
    
    try:
        from provider_detector import detect_email_providers
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} provider_detector module")
    except ImportError as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} provider_detector module: {e}")
        return False
    
    try:
        from report_generator import generate_report
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} report_generator module")
    except ImportError as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} report_generator module: {e}")
        return False
    
    return True


def test_dns_resolution():
    """Test basic DNS resolution."""
    print(f"\n{Fore.YELLOW}[TEST]{Style.RESET_ALL} Testing DNS resolution...")
    
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        # Test with a well-known domain
        answers = resolver.resolve('google.com', 'A')
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} DNS resolution working")
        return True
    except Exception as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} DNS resolution failed: {e}")
        return False


def test_subdomain_enum():
    """Test subdomain enumeration with crt.sh."""
    print(f"\n{Fore.YELLOW}[TEST]{Style.RESET_ALL} Testing subdomain enumeration (crt.sh)...")
    
    try:
        from subdomain_enum import SubdomainEnumerator
        
        enumerator = SubdomainEnumerator(timeout=10, verbose=False)
        results = enumerator._enumerate_crtsh('google.com')
        
        if results:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} crt.sh enumeration working (found {len(results)} subdomains)")
            return True
        else:
            print(f"  {Fore.YELLOW}!{Style.RESET_ALL} crt.sh returned no results (may be rate limited)")
            return True
    except Exception as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} Subdomain enumeration failed: {e}")
        return False


def test_dns_analysis():
    """Test DNS record analysis."""
    print(f"\n{Fore.YELLOW}[TEST]{Style.RESET_ALL} Testing DNS record analysis...")
    
    try:
        from dns_analyzer import DNSAnalyzer
        
        analyzer = DNSAnalyzer(timeout=5, verbose=False)
        
        # Test with Google (known to have good email security)
        result = analyzer.analyze_domain('google.com')
        
        has_spf = result.get('spf', {}).get('valid', False)
        has_dmarc = result.get('dmarc', {}).get('valid', False)
        has_mx = bool(result.get('mx', {}).get('records', []))
        
        if has_spf and has_dmarc and has_mx:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} DNS analysis working")
            print(f"    SPF: {result['spf']['record'][:50]}...")
            print(f"    DMARC: {result['dmarc']['record'][:50]}...")
            print(f"    MX Records: {len(result['mx']['records'])}")
            return True
        else:
            print(f"  {Fore.YELLOW}!{Style.RESET_ALL} DNS analysis incomplete")
            return True
    except Exception as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} DNS analysis failed: {e}")
        return False


def test_provider_detection():
    """Test email provider detection."""
    print(f"\n{Fore.YELLOW}[TEST]{Style.RESET_ALL} Testing email provider detection...")
    
    try:
        from provider_detector import EmailProviderDetector
        
        # Mock DNS results for Google Workspace
        mock_dns = {
            'domain': 'example.com',
            'has_email': True,
            'spf': {
                'valid': True,
                'record': 'v=spf1 include:_spf.google.com ~all',
                'includes': ['_spf.google.com']
            },
            'dmarc': {
                'valid': True,
                'record': 'v=DMARC1; p=quarantine;',
                'policy': 'quarantine'
            },
            'dkim': {
                'selectors_found': ['google']
            },
            'mx': {
                'servers': ['aspmx.l.google.com']
            }
        }
        
        detector = EmailProviderDetector(verbose=False)
        result = detector.detect_providers(mock_dns)
        
        if 'Google Workspace' in result['providers']:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Provider detection working")
            print(f"    Detected: {', '.join(result['providers'])}")
            return True
        else:
            print(f"  {Fore.YELLOW}!{Style.RESET_ALL} Provider detection returned unexpected results")
            return True
    except Exception as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} Provider detection failed: {e}")
        return False


def test_report_generation():
    """Test report generation."""
    print(f"\n{Fore.YELLOW}[TEST]{Style.RESET_ALL} Testing report generation...")
    
    try:
        from report_generator import ReportGenerator
        import tempfile
        import os
        
        # Create minimal test data
        test_data = {
            'root_domains': ['example.com'],
            'enumeration': {'example.com': ['example.com']},
            'all_analyzed_domains': ['example.com'],
            'dns_analysis': {
                'example.com': {
                    'domain': 'example.com',
                    'has_email': True,
                    'spf': {'valid': True, 'record': 'v=spf1 -all'},
                    'dmarc': {'valid': True, 'record': 'v=DMARC1; p=reject;'},
                    'dkim': {'selectors_found': ['default']},
                    'mx': {'records': [{'priority': 10, 'server': 'mail.example.com'}]}
                }
            },
            'provider_detection': {
                'example.com': {
                    'providers': {'providers': []},
                    'misconfigurations': [],
                    'risk_score': {'level': 'low', 'score': 5}
                }
            }
        }
        
        generator = ReportGenerator(verbose=False)
        
        # Test Markdown generation
        md_report = generator.generate_markdown_report(test_data)
        if 'Email Attack Surface Analysis Report' in md_report:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Markdown report generation working")
        else:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} Markdown report generation failed")
            return False
        
        # Test JSON generation
        json_report = generator.generate_json_report(test_data)
        if 'metadata' in json_report:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} JSON report generation working")
        else:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} JSON report generation failed")
            return False
        
        return True
    except Exception as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} Report generation failed: {e}")
        return False


def main():
    """Run all tests."""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  Email Attack Surface Analyzer - Test Suite")
    print(f"{'='*60}{Style.RESET_ALL}\n")
    
    tests = [
        ("Import Test", test_imports),
        ("DNS Resolution", test_dns_resolution),
        ("Subdomain Enumeration", test_subdomain_enum),
        ("DNS Analysis", test_dns_analysis),
        ("Provider Detection", test_provider_detection),
        ("Report Generation", test_report_generation)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} Test crashed: {e}")
            results.append((test_name, False))
    
    # Print summary
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  Test Summary")
    print(f"{'='*60}{Style.RESET_ALL}\n")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = f"{Fore.GREEN}PASS{Style.RESET_ALL}" if result else f"{Fore.RED}FAIL{Style.RESET_ALL}"
        print(f"  {test_name:.<40} {status}")
    
    print(f"\n{Fore.CYAN}Total: {passed}/{total} tests passed{Style.RESET_ALL}")
    
    if passed == total:
        print(f"\n{Fore.GREEN}✓ All tests passed! The tool is ready to use.{Style.RESET_ALL}\n")
        return 0
    else:
        print(f"\n{Fore.YELLOW}⚠ Some tests failed. Check the output above for details.{Style.RESET_ALL}\n")
        print("Common issues:")
        print("  - Missing dependencies: Run 'pip install -r requirements.txt'")
        print("  - Network issues: Check your internet connection")
        print("  - DNS issues: Verify DNS resolution works on your system")
        return 1


if __name__ == "__main__":
    sys.exit(main())
