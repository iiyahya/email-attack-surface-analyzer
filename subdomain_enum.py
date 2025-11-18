"""
Subdomain Enumeration Module

This module provides functions to enumerate subdomains using multiple sources:
- crt.sh (Certificate Transparency logs)
- Sublist3r (if installed)
- Amass (if installed)
- DNS zone transfer attempts
- VirusTotal API (if API key provided)
"""

import re
import json
import subprocess
import os
import time
from typing import Set, List
from urllib.parse import quote

import requests
from bs4 import BeautifulSoup
import dns.resolver
import dns.zone
import dns.query


class SubdomainEnumerator:
    """Handles subdomain enumeration from multiple sources."""
    
    def __init__(self, timeout: int = 5, verbose: bool = False):
        """
        Initialize the SubdomainEnumerator.
        
        Args:
            timeout: Timeout in seconds for HTTP requests
            verbose: Enable verbose output
        """
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def enumerate_all(self, domain: str, use_external_tools: bool = True,
                     virustotal_api_key: str = None, sublister_path: str = None,
                     amass_path: str = None) -> Set[str]:
        """
        Enumerate subdomains using all available methods.
        
        Args:
            domain: Root domain to enumerate
            use_external_tools: Whether to use Sublist3r and Amass
            virustotal_api_key: VirusTotal API key (optional)
            sublister_path: Path to Sublist3r script (optional)
            amass_path: Path to Amass binary (optional)
        
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        # Add the root domain
        subdomains.add(domain)
        
        # crt.sh - Certificate Transparency logs
        if self.verbose:
            print(f"  [*] Querying crt.sh for {domain}...")
        crtsh_results = self._enumerate_crtsh(domain)
        subdomains.update(crtsh_results)
        if self.verbose:
            print(f"      Found {len(crtsh_results)} subdomains from crt.sh")
        
        # DNS Zone Transfer attempt
        if self.verbose:
            print(f"  [*] Attempting DNS zone transfer for {domain}...")
        zonetransfer_results = self._attempt_zone_transfer(domain)
        subdomains.update(zonetransfer_results)
        if self.verbose and zonetransfer_results:
            print(f"      Found {len(zonetransfer_results)} subdomains from zone transfer")
        elif self.verbose:
            print(f"      Zone transfer not allowed (expected)")
        
        # VirusTotal API
        if virustotal_api_key:
            if self.verbose:
                print(f"  [*] Querying VirusTotal for {domain}...")
            vt_results = self._enumerate_virustotal(domain, virustotal_api_key)
            subdomains.update(vt_results)
            if self.verbose:
                print(f"      Found {len(vt_results)} subdomains from VirusTotal")
        
        # External tools
        if use_external_tools:
            # Sublist3r
            if sublister_path and os.path.exists(sublister_path):
                if self.verbose:
                    print(f"  [*] Running Sublist3r for {domain}...")
                sublister_results = self._run_sublister(domain, sublister_path)
                subdomains.update(sublister_results)
                if self.verbose:
                    print(f"      Found {len(sublister_results)} subdomains from Sublist3r")
            
            # Amass
            if amass_path:
                if self.verbose:
                    print(f"  [*] Running Amass for {domain}...")
                amass_results = self._run_amass(domain, amass_path)
                subdomains.update(amass_results)
                if self.verbose:
                    print(f"      Found {len(amass_results)} subdomains from Amass")
        
        # Clean and validate results
        cleaned_subdomains = self._clean_subdomains(subdomains, domain)
        
        return cleaned_subdomains
    
    def _enumerate_crtsh(self, domain: str) -> Set[str]:
        """
        Enumerate subdomains using crt.sh Certificate Transparency logs.
        
        Args:
            domain: Domain to search
        
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        try:
            # Query crt.sh API
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        # Handle multiple domains in name_value (newline-separated)
                        for subdomain in name_value.split('\n'):
                            subdomain = subdomain.strip().lower()
                            if subdomain and domain in subdomain:
                                # Remove wildcard characters
                                subdomain = subdomain.replace('*.', '')
                                if subdomain:
                                    subdomains.add(subdomain)
                except json.JSONDecodeError:
                    pass
        
        except requests.RequestException as e:
            if self.verbose:
                print(f"      Error querying crt.sh: {e}")
        
        return subdomains
    
    def _enumerate_virustotal(self, domain: str, api_key: str) -> Set[str]:
        """
        Enumerate subdomains using VirusTotal API.
        
        Args:
            domain: Domain to search
            api_key: VirusTotal API key
        
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            headers = {
                'x-apikey': api_key
            }
            
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', []):
                    subdomain = item.get('id', '').lower()
                    if subdomain:
                        subdomains.add(subdomain)
            elif response.status_code == 401:
                if self.verbose:
                    print(f"      Invalid VirusTotal API key")
        
        except requests.RequestException as e:
            if self.verbose:
                print(f"      Error querying VirusTotal: {e}")
        
        return subdomains
    
    def _attempt_zone_transfer(self, domain: str) -> Set[str]:
        """
        Attempt DNS zone transfer (AXFR) to enumerate subdomains.
        
        Args:
            domain: Domain to attempt zone transfer
        
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        try:
            # Get nameservers for the domain
            ns_records = dns.resolver.resolve(domain, 'NS', lifetime=self.timeout)
            
            for ns in ns_records:
                nameserver = str(ns.target).rstrip('.')
                
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(nameserver, domain, lifetime=self.timeout)
                    )
                    
                    # Extract all names from the zone
                    for name, node in zone.nodes.items():
                        subdomain = str(name)
                        if subdomain == '@':
                            subdomains.add(domain)
                        else:
                            subdomains.add(f"{subdomain}.{domain}")
                    
                    # If we got here, zone transfer succeeded
                    break
                
                except Exception:
                    # Zone transfer not allowed (expected for most domains)
                    continue
        
        except Exception:
            # No NS records or other DNS error
            pass
        
        return subdomains
    
    def _run_sublister(self, domain: str, sublister_path: str) -> Set[str]:
        """
        Run Sublist3r to enumerate subdomains.
        
        Args:
            domain: Domain to enumerate
            sublister_path: Path to sublist3r.py script
        
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        try:
            # Run Sublist3r with minimal output
            cmd = ['python', sublister_path, '-d', domain, '-o', '/dev/null']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout
            )
            
            # Parse output for subdomains
            output = result.stdout + result.stderr
            # Look for domain patterns
            pattern = r'\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*' + re.escape(domain) + r'\b'
            matches = re.findall(pattern, output)
            
            for match in matches:
                if isinstance(match, tuple):
                    subdomain = match[0] + domain if match[0] else domain
                else:
                    subdomain = match
                subdomain = subdomain.lower().strip()
                if subdomain:
                    subdomains.add(subdomain)
        
        except subprocess.TimeoutExpired:
            if self.verbose:
                print(f"      Sublist3r timed out")
        except Exception as e:
            if self.verbose:
                print(f"      Error running Sublist3r: {e}")
        
        return subdomains
    
    def _run_amass(self, domain: str, amass_path: str) -> Set[str]:
        """
        Run Amass to enumerate subdomains.
        
        Args:
            domain: Domain to enumerate
            amass_path: Path to amass binary
        
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        try:
            # Run Amass in passive mode for faster results
            cmd = [amass_path, 'enum', '-passive', '-d', domain]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180  # 3 minute timeout
            )
            
            # Parse output - Amass outputs one subdomain per line
            for line in result.stdout.split('\n'):
                subdomain = line.strip().lower()
                if subdomain and domain in subdomain:
                    subdomains.add(subdomain)
        
        except subprocess.TimeoutExpired:
            if self.verbose:
                print(f"      Amass timed out")
        except FileNotFoundError:
            if self.verbose:
                print(f"      Amass not found at: {amass_path}")
        except Exception as e:
            if self.verbose:
                print(f"      Error running Amass: {e}")
        
        return subdomains
    
    def _clean_subdomains(self, subdomains: Set[str], root_domain: str) -> Set[str]:
        """
        Clean and validate subdomain list.
        
        Args:
            subdomains: Raw set of subdomains
            root_domain: Root domain for validation
        
        Returns:
            Cleaned set of valid subdomains
        """
        cleaned = set()
        
        for subdomain in subdomains:
            # Remove wildcards and extra whitespace
            subdomain = subdomain.replace('*.', '').strip().lower()
            
            # Skip empty strings
            if not subdomain:
                continue
            
            # Must contain the root domain
            if root_domain not in subdomain:
                continue
            
            # Must end with the root domain
            if not subdomain.endswith(root_domain):
                continue
            
            # Basic validation - must be valid hostname
            if re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$', subdomain):
                cleaned.add(subdomain)
        
        return cleaned


def enum_domains(domains: List[str], timeout: int = 5, verbose: bool = False,
                use_external_tools: bool = True, virustotal_api_key: str = None,
                sublister_path: str = None, amass_path: str = None) -> dict:
    """
    Enumerate subdomains for a list of root domains.
    
    Args:
        domains: List of root domains to enumerate
        timeout: Timeout in seconds for requests
        verbose: Enable verbose output
        use_external_tools: Whether to use Sublist3r and Amass
        virustotal_api_key: VirusTotal API key (optional)
        sublister_path: Path to Sublist3r script (optional)
        amass_path: Path to Amass binary (optional)
    
    Returns:
        Dictionary mapping each root domain to its discovered subdomains
    """
    enumerator = SubdomainEnumerator(timeout=timeout, verbose=verbose)
    results = {}
    
    for domain in domains:
        if verbose:
            print(f"\n[+] Enumerating subdomains for: {domain}")
        
        subdomains = enumerator.enumerate_all(
            domain=domain,
            use_external_tools=use_external_tools,
            virustotal_api_key=virustotal_api_key,
            sublister_path=sublister_path,
            amass_path=amass_path
        )
        
        results[domain] = sorted(list(subdomains))
        
        if verbose:
            print(f"[+] Total subdomains found for {domain}: {len(subdomains)}")
    
    return results


if __name__ == "__main__":
    # Example usage
    test_domains = ["example.com"]
    results = enum_domains(test_domains, verbose=True)
    
    print("\n" + "="*50)
    print("ENUMERATION RESULTS")
    print("="*50)
    
    for domain, subdomains in results.items():
        print(f"\n{domain}: {len(subdomains)} subdomains")
        for subdomain in subdomains[:10]:  # Show first 10
            print(f"  - {subdomain}")
        if len(subdomains) > 10:
            print(f"  ... and {len(subdomains) - 10} more")
