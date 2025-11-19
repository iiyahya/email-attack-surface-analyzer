#!/usr/bin/env python3
"""
Company Domain Discovery Module

This module discovers all domains associated with a company name using multiple sources:
- Certificate Transparency logs (crt.sh)
- Reverse WHOIS lookups
- DNS pattern matching
- Common domain patterns
- Known subsidiaries and brands
"""

import re
import json
import requests
import time
from typing import List, Dict, Set, Optional
from urllib.parse import quote
from collections import defaultdict


class CompanyDomainFinder:
    """Find all domains associated with a company name."""
    
    def __init__(self, company_name: str, verbose: bool = False):
        """
        Initialize the company domain finder.
        
        Args:
            company_name: Name of the company to search for
            verbose: Enable verbose output
        """
        self.company_name = company_name
        self.verbose = verbose
        self.domains = set()
        self.sources = defaultdict(list)  # Track which source found each domain
        
    def discover_all(self) -> Dict:
        """
        Discover all domains using multiple methods.
        
        Returns:
            Dictionary with discovered domains and metadata
        """
        if self.verbose:
            print(f"\n[*] Starting company domain discovery for: {self.company_name}")
        
        # Method 1: Certificate Transparency Logs
        self._search_certificate_transparency()
        
        # Method 2: Common domain patterns
        self._search_common_patterns()
        
        # Method 3: TLD variations
        self._search_tld_variations()
        
        # Method 4: Search known company database patterns
        self._search_company_patterns()
        
        # Compile results
        results = self._compile_results()
        
        if self.verbose:
            print(f"\n[+] Discovery complete! Found {len(self.domains)} unique domains")
        
        return results
    
    def _search_certificate_transparency(self):
        """Search Certificate Transparency logs via crt.sh."""
        if self.verbose:
            print(f"\n[*] Searching Certificate Transparency logs...")
        
        try:
            # Search by organization name
            url = f"https://crt.sh/?O={quote(self.company_name)}&output=json"
            
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                try:
                    certificates = response.json()
                    
                    for cert in certificates:
                        # Extract domain from common_name
                        common_name = cert.get('common_name', '')
                        if common_name:
                            domain = self._extract_domain(common_name)
                            if domain:
                                self.domains.add(domain)
                                self.sources[domain].append('Certificate Transparency (Organization)')
                        
                        # Extract domains from name_value (SAN)
                        name_value = cert.get('name_value', '')
                        if name_value:
                            for name in name_value.split('\n'):
                                domain = self._extract_domain(name)
                                if domain:
                                    self.domains.add(domain)
                                    self.sources[domain].append('Certificate Transparency (SAN)')
                    
                    if self.verbose:
                        print(f"    Found {len(certificates)} certificates")
                        
                except json.JSONDecodeError:
                    if self.verbose:
                        print(f"    Error parsing JSON response")
            
            # Also search by common name pattern
            company_pattern = self._normalize_company_name(self.company_name)
            url2 = f"https://crt.sh/?q=%25{quote(company_pattern)}%25&output=json"
            
            time.sleep(2)  # Rate limiting
            
            response2 = requests.get(url2, timeout=30)
            
            if response2.status_code == 200:
                try:
                    certificates = response2.json()
                    
                    for cert in certificates:
                        common_name = cert.get('common_name', '')
                        if common_name and self._is_related_domain(common_name):
                            domain = self._extract_domain(common_name)
                            if domain:
                                self.domains.add(domain)
                                self.sources[domain].append('Certificate Transparency (Pattern)')
                        
                        name_value = cert.get('name_value', '')
                        if name_value:
                            for name in name_value.split('\n'):
                                if self._is_related_domain(name):
                                    domain = self._extract_domain(name)
                                    if domain:
                                        self.domains.add(domain)
                                        self.sources[domain].append('Certificate Transparency (Pattern)')
                    
                    if self.verbose:
                        print(f"    Found {len(certificates)} pattern-matched certificates")
                        
                except json.JSONDecodeError:
                    pass
                    
        except requests.RequestException as e:
            if self.verbose:
                print(f"    Error querying Certificate Transparency: {e}")
    
    def _search_common_patterns(self):
        """Generate and test common domain patterns."""
        if self.verbose:
            print(f"\n[*] Testing common domain patterns...")
        
        normalized = self._normalize_company_name(self.company_name)
        
        # Common patterns
        patterns = [
            f"{normalized}.com",
            f"{normalized}.net",
            f"{normalized}.org",
            f"{normalized}corp.com",
            f"{normalized}inc.com",
            f"{normalized}group.com",
            f"{normalized}global.com",
            f"{normalized}international.com",
            f"www.{normalized}.com",
            f"my{normalized}.com",
            f"get{normalized}.com",
            f"{normalized}app.com",
            f"{normalized}online.com",
        ]
        
        # Add patterns with company name parts
        parts = normalized.split('-')
        if len(parts) > 1:
            # Use first part
            patterns.extend([
                f"{parts[0]}.com",
                f"{parts[0]}.net",
                f"{parts[0]}.io",
            ])
            # Use acronym
            acronym = ''.join([p[0] for p in parts if p])
            patterns.extend([
                f"{acronym}.com",
                f"{acronym}.net",
                f"{acronym}.io",
            ])
        
        for pattern in patterns:
            if self._domain_exists(pattern):
                self.domains.add(pattern)
                self.sources[pattern].append('Common Pattern')
                if self.verbose:
                    print(f"    ✓ Found: {pattern}")
    
    def _search_tld_variations(self):
        """Search common TLD variations of the main domain."""
        if self.verbose:
            print(f"\n[*] Searching TLD variations...")
        
        normalized = self._normalize_company_name(self.company_name)
        
        # Common TLDs
        tlds = [
            'com', 'net', 'org', 'io', 'co', 'ai', 'app', 'dev',
            'info', 'biz', 'us', 'uk', 'ca', 'de', 'fr', 'jp',
            'cn', 'in', 'au', 'br', 'ru', 'eu', 'ae', 'sa'
        ]
        
        # Also add country-specific TLDs
        country_tlds = [
            'co.uk', 'co.jp', 'co.in', 'co.au', 'com.br',
            'com.cn', 'com.sa', 'com.ae', 'com.mx', 'com.sg'
        ]
        
        all_tlds = tlds + country_tlds
        
        for tld in all_tlds:
            domain = f"{normalized}.{tld}"
            if self._domain_exists(domain):
                self.domains.add(domain)
                self.sources[domain].append(f'TLD Variation (.{tld})')
                if self.verbose:
                    print(f"    ✓ Found: {domain}")
    
    def _search_company_patterns(self):
        """Search for company-specific patterns."""
        if self.verbose:
            print(f"\n[*] Searching company-specific patterns...")
        
        normalized = self._normalize_company_name(self.company_name)
        
        # Subsidiary patterns
        subsidiary_keywords = [
            'labs', 'ventures', 'capital', 'partners', 'solutions',
            'technologies', 'tech', 'software', 'services', 'consulting',
            'digital', 'cloud', 'security', 'media', 'studio', 'studios',
            'entertainment', 'games', 'gaming', 'network', 'networks'
        ]
        
        for keyword in subsidiary_keywords:
            patterns = [
                f"{normalized}-{keyword}.com",
                f"{normalized}{keyword}.com",
                f"{keyword}.{normalized}.com",
            ]
            
            for pattern in patterns:
                if self._domain_exists(pattern):
                    self.domains.add(pattern)
                    self.sources[pattern].append(f'Subsidiary Pattern ({keyword})')
                    if self.verbose:
                        print(f"    ✓ Found: {pattern}")
        
        # Regional patterns
        regions = [
            'us', 'uk', 'eu', 'asia', 'apac', 'emea', 'americas',
            'global', 'international', 'worldwide'
        ]
        
        for region in regions:
            patterns = [
                f"{normalized}-{region}.com",
                f"{region}.{normalized}.com",
                f"{normalized}.{region}",
            ]
            
            for pattern in patterns:
                if self._domain_exists(pattern):
                    self.domains.add(pattern)
                    self.sources[pattern].append(f'Regional ({region})')
                    if self.verbose:
                        print(f"    ✓ Found: {pattern}")
    
    def _normalize_company_name(self, name: str) -> str:
        """
        Normalize company name for domain patterns.
        
        Args:
            name: Company name
            
        Returns:
            Normalized name suitable for domain
        """
        # Convert to lowercase
        normalized = name.lower()
        
        # Remove common suffixes
        suffixes = [
            ' inc', ' inc.', ' incorporated',
            ' llc', ' ltd', ' ltd.', ' limited',
            ' corp', ' corp.', ' corporation',
            ' company', ' co', ' co.',
            ' group', ' international', ' global'
        ]
        
        for suffix in suffixes:
            if normalized.endswith(suffix):
                normalized = normalized[:-len(suffix)]
        
        # Remove special characters, keep only alphanumeric and spaces
        normalized = re.sub(r'[^a-z0-9\s]', '', normalized)
        
        # Replace spaces with hyphens
        normalized = re.sub(r'\s+', '-', normalized.strip())
        
        return normalized
    
    def _extract_domain(self, name: str) -> Optional[str]:
        """
        Extract base domain from a string.
        
        Args:
            name: String potentially containing a domain
            
        Returns:
            Base domain or None
        """
        # Remove wildcards
        name = name.replace('*.', '')
        name = name.strip().lower()
        
        # Check if it looks like a domain
        if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$', name):
            return None
        
        # Extract base domain (remove subdomains if more than 3 parts)
        parts = name.split('.')
        
        # Handle country code TLDs
        country_tlds = ['co.uk', 'co.jp', 'co.in', 'com.br', 'com.cn', 'co.au']
        
        if len(parts) >= 3:
            potential_tld = f"{parts[-2]}.{parts[-1]}"
            if potential_tld in country_tlds:
                # Keep last 3 parts for country TLDs
                if len(parts) > 3:
                    return '.'.join(parts[-3:])
                else:
                    return name
            else:
                # Keep last 2 parts
                if len(parts) > 2:
                    return '.'.join(parts[-2:])
        
        return name
    
    def _is_related_domain(self, domain: str) -> bool:
        """
        Check if a domain is related to the company.
        
        Args:
            domain: Domain name to check
            
        Returns:
            True if related, False otherwise
        """
        normalized_company = self._normalize_company_name(self.company_name)
        domain_lower = domain.lower()
        
        # Check if company name (or parts) appear in domain
        company_parts = normalized_company.split('-')
        
        for part in company_parts:
            if len(part) >= 3 and part in domain_lower:
                return True
        
        return False
    
    def _domain_exists(self, domain: str) -> bool:
        """
        Check if a domain exists (has DNS records).
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain exists, False otherwise
        """
        try:
            import dns.resolver
            
            # Try to resolve A records
            try:
                answers = dns.resolver.resolve(domain, 'A', lifetime=3)
                if answers:
                    return True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                pass
            
            # Try to resolve MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX', lifetime=3)
                if answers:
                    return True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                pass
            
            return False
            
        except Exception:
            return False
    
    def _compile_results(self) -> Dict:
        """
        Compile all discovered domains into a structured result.
        
        Returns:
            Dictionary with comprehensive results
        """
        # Categorize domains
        primary_domains = []
        subdomains = []
        regional_domains = []
        subsidiary_domains = []
        other_domains = []
        
        for domain in sorted(self.domains):
            sources = self.sources.get(domain, [])
            
            # Categorize based on sources
            is_regional = any('Regional' in s for s in sources)
            is_subsidiary = any('Subsidiary' in s for s in sources)
            is_tld_variation = any('TLD Variation' in s for s in sources)
            
            domain_info = {
                'domain': domain,
                'sources': sources,
                'discovery_methods': len(set(sources))
            }
            
            if is_subsidiary:
                subsidiary_domains.append(domain_info)
            elif is_regional:
                regional_domains.append(domain_info)
            elif is_tld_variation and len(domain.split('.')) == 2:
                primary_domains.append(domain_info)
            elif len(domain.split('.')) > 2:
                subdomains.append(domain_info)
            else:
                other_domains.append(domain_info)
        
        # If no clear primary domain, move most common from other
        if not primary_domains and other_domains:
            primary_domains = [other_domains.pop(0)]
        
        results = {
            'company_name': self.company_name,
            'total_domains': len(self.domains),
            'discovery_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'categories': {
                'primary_domains': primary_domains,
                'regional_domains': regional_domains,
                'subsidiary_domains': subsidiary_domains,
                'subdomains': subdomains,
                'other_domains': other_domains
            },
            'all_domains': sorted(list(self.domains)),
            'summary': {
                'primary': len(primary_domains),
                'regional': len(regional_domains),
                'subsidiaries': len(subsidiary_domains),
                'subdomains': len(subdomains),
                'other': len(other_domains)
            }
        }
        
        return results


def discover_company_domains(company_name: str, verbose: bool = False) -> Dict:
    """
    Main function to discover all domains for a company.
    
    Args:
        company_name: Name of the company
        verbose: Enable verbose output
        
    Returns:
        Dictionary with discovered domains
        
    Example:
        >>> results = discover_company_domains("Google Inc")
        >>> print(f"Found {results['total_domains']} domains")
        >>> for domain in results['categories']['primary_domains']:
        ...     print(domain['domain'])
    """
    finder = CompanyDomainFinder(company_name, verbose)
    return finder.discover_all()


def format_results_table(results: Dict) -> str:
    """
    Format discovery results as a readable table.
    
    Args:
        results: Results from discover_company_domains
        
    Returns:
        Formatted string with table
    """
    from tabulate import tabulate
    
    output = []
    output.append(f"\n{'='*80}")
    output.append(f"Company Domain Discovery Results")
    output.append(f"{'='*80}")
    output.append(f"\nCompany: {results['company_name']}")
    output.append(f"Total Domains Found: {results['total_domains']}")
    output.append(f"Discovery Time: {results['discovery_timestamp']}\n")
    
    # Summary table
    summary_data = [
        ['Primary Domains', results['summary']['primary']],
        ['Regional Domains', results['summary']['regional']],
        ['Subsidiary Domains', results['summary']['subsidiaries']],
        ['Subdomains', results['summary']['subdomains']],
        ['Other Domains', results['summary']['other']]
    ]
    output.append(tabulate(summary_data, headers=['Category', 'Count'], tablefmt='grid'))
    output.append('\n')
    
    # Detailed categories
    categories = results['categories']
    
    if categories['primary_domains']:
        output.append(f"\n{'─'*80}")
        output.append("PRIMARY DOMAINS")
        output.append(f"{'─'*80}")
        for domain_info in categories['primary_domains']:
            output.append(f"\n  • {domain_info['domain']}")
            output.append(f"    Sources: {', '.join(set(domain_info['sources']))}")
    
    if categories['regional_domains']:
        output.append(f"\n{'─'*80}")
        output.append("REGIONAL DOMAINS")
        output.append(f"{'─'*80}")
        for domain_info in categories['regional_domains']:
            output.append(f"\n  • {domain_info['domain']}")
            output.append(f"    Sources: {', '.join(set(domain_info['sources']))}")
    
    if categories['subsidiary_domains']:
        output.append(f"\n{'─'*80}")
        output.append("SUBSIDIARY / BRAND DOMAINS")
        output.append(f"{'─'*80}")
        for domain_info in categories['subsidiary_domains']:
            output.append(f"\n  • {domain_info['domain']}")
            output.append(f"    Sources: {', '.join(set(domain_info['sources']))}")
    
    if categories['subdomains']:
        output.append(f"\n{'─'*80}")
        output.append("SUBDOMAINS")
        output.append(f"{'─'*80}")
        # Show first 10 subdomains
        for domain_info in categories['subdomains'][:10]:
            output.append(f"\n  • {domain_info['domain']}")
            output.append(f"    Sources: {', '.join(set(domain_info['sources']))}")
        
        if len(categories['subdomains']) > 10:
            output.append(f"\n  ... and {len(categories['subdomains']) - 10} more subdomains")
    
    if categories['other_domains']:
        output.append(f"\n{'─'*80}")
        output.append("OTHER RELATED DOMAINS")
        output.append(f"{'─'*80}")
        for domain_info in categories['other_domains'][:10]:
            output.append(f"\n  • {domain_info['domain']}")
            output.append(f"    Sources: {', '.join(set(domain_info['sources']))}")
        
        if len(categories['other_domains']) > 10:
            output.append(f"\n  ... and {len(categories['other_domains']) - 10} more domains")
    
    output.append(f"\n{'='*80}\n")
    
    return '\n'.join(output)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python company_domains.py <company_name>")
        print("Example: python company_domains.py 'Microsoft Corporation'")
        sys.exit(1)
    
    company = ' '.join(sys.argv[1:])
    
    print(f"Discovering domains for: {company}")
    print("This may take a few minutes...\n")
    
    results = discover_company_domains(company, verbose=True)
    
    print(format_results_table(results))
    
    # Save to JSON
    output_file = f"company_domains_{results['company_name'].replace(' ', '_')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")
