"""
DNS Email Security Analyzer Module

This module analyzes DNS records related to email security:
- SPF (Sender Policy Framework)
- DKIM (DomainKeys Identified Mail)
- DMARC (Domain-based Message Authentication)
- MX (Mail Exchange) records
"""

import re
from typing import Dict, List, Optional, Tuple
import dns.resolver
import dns.exception


class DNSAnalyzer:
    """Analyzes DNS records for email security configuration."""
    
    def __init__(self, timeout: int = 5, retries: int = 2, verbose: bool = False):
        """
        Initialize the DNS Analyzer.
        
        Args:
            timeout: DNS query timeout in seconds
            retries: Number of retries for failed queries
            verbose: Enable verbose output
        """
        self.timeout = timeout
        self.retries = retries
        self.verbose = verbose
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def analyze_domain(self, domain: str, dkim_selectors: List[str] = None) -> Dict:
        """
        Perform comprehensive DNS email security analysis for a domain.
        
        Args:
            domain: Domain to analyze
            dkim_selectors: List of DKIM selectors to check
        
        Returns:
            Dictionary containing all DNS analysis results
        """
        if self.verbose:
            print(f"    [*] Analyzing DNS records for {domain}...")
        
        results = {
            'domain': domain,
            'spf': self.get_spf_record(domain),
            'dmarc': self.get_dmarc_record(domain),
            'dkim': self.get_dkim_records(domain, dkim_selectors or self._default_dkim_selectors()),
            'mx': self.get_mx_records(domain),
            'has_email': False,
            'errors': []
        }
        
        # Determine if domain has email capability
        results['has_email'] = bool(results['mx']['records']) or bool(results['spf']['record'])
        
        return results
    
    def get_spf_record(self, domain: str) -> Dict:
        """
        Retrieve and parse SPF record for a domain.
        
        Args:
            domain: Domain to query
        
        Returns:
            Dictionary with SPF record details
        """
        result = {
            'record': None,
            'valid': False,
            'mechanisms': [],
            'all_mechanism': None,
            'includes': [],
            'ip4': [],
            'ip6': [],
            'errors': []
        }
        
        try:
            # Query TXT records
            answers = self.resolver.resolve(domain, 'TXT', lifetime=self.timeout)
            
            # Find SPF record (starts with v=spf1)
            for rdata in answers:
                txt_string = ''.join([s.decode('utf-8') if isinstance(s, bytes) else s for s in rdata.strings])
                
                if txt_string.strip().startswith('v=spf1'):
                    result['record'] = txt_string
                    result['valid'] = True
                    
                    # Parse SPF mechanisms
                    tokens = txt_string.split()
                    for token in tokens[1:]:  # Skip v=spf1
                        token = token.strip()
                        
                        # Extract mechanism type
                        if token.startswith('include:'):
                            result['includes'].append(token[8:])
                            result['mechanisms'].append(token)
                        elif token.startswith('ip4:'):
                            result['ip4'].append(token[4:])
                            result['mechanisms'].append(token)
                        elif token.startswith('ip6:'):
                            result['ip6'].append(token[4:])
                            result['mechanisms'].append(token)
                        elif token in ['-all', '~all', '+all', '?all']:
                            result['all_mechanism'] = token
                            result['mechanisms'].append(token)
                        else:
                            result['mechanisms'].append(token)
                    
                    break  # Only process first SPF record
        
        except dns.resolver.NXDOMAIN:
            result['errors'].append('Domain does not exist')
        except dns.resolver.NoAnswer:
            result['errors'].append('No TXT records found')
        except dns.exception.Timeout:
            result['errors'].append('DNS query timeout')
        except Exception as e:
            result['errors'].append(f'DNS query error: {str(e)}')
        
        return result
    
    def get_dmarc_record(self, domain: str) -> Dict:
        """
        Retrieve and parse DMARC record for a domain.
        
        Args:
            domain: Domain to query
        
        Returns:
            Dictionary with DMARC record details
        """
        result = {
            'record': None,
            'valid': False,
            'policy': None,
            'subdomain_policy': None,
            'percentage': 100,
            'rua': [],
            'ruf': [],
            'alignment_spf': 'r',  # relaxed by default
            'alignment_dkim': 'r',  # relaxed by default
            'errors': []
        }
        
        try:
            # DMARC record is at _dmarc.domain
            dmarc_domain = f'_dmarc.{domain}'
            answers = self.resolver.resolve(dmarc_domain, 'TXT', lifetime=self.timeout)
            
            # Find DMARC record (starts with v=DMARC1)
            for rdata in answers:
                txt_string = ''.join([s.decode('utf-8') if isinstance(s, bytes) else s for s in rdata.strings])
                
                if txt_string.strip().startswith('v=DMARC1'):
                    result['record'] = txt_string
                    result['valid'] = True
                    
                    # Parse DMARC tags
                    tags = txt_string.split(';')
                    for tag in tags:
                        tag = tag.strip()
                        if '=' in tag:
                            key, value = tag.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            
                            if key == 'p':
                                result['policy'] = value
                            elif key == 'sp':
                                result['subdomain_policy'] = value
                            elif key == 'pct':
                                try:
                                    result['percentage'] = int(value)
                                except ValueError:
                                    pass
                            elif key == 'rua':
                                result['rua'] = [addr.strip() for addr in value.split(',')]
                            elif key == 'ruf':
                                result['ruf'] = [addr.strip() for addr in value.split(',')]
                            elif key == 'aspf':
                                result['alignment_spf'] = value
                            elif key == 'adkim':
                                result['alignment_dkim'] = value
                    
                    break  # Only process first DMARC record
        
        except dns.resolver.NXDOMAIN:
            result['errors'].append('DMARC record does not exist')
        except dns.resolver.NoAnswer:
            result['errors'].append('No DMARC record found')
        except dns.exception.Timeout:
            result['errors'].append('DNS query timeout')
        except Exception as e:
            result['errors'].append(f'DNS query error: {str(e)}')
        
        return result
    
    def get_dkim_records(self, domain: str, selectors: List[str]) -> Dict:
        """
        Retrieve DKIM records for common selectors.
        
        Args:
            domain: Domain to query
            selectors: List of DKIM selectors to check
        
        Returns:
            Dictionary with DKIM selector results
        """
        result = {
            'selectors_found': [],
            'selectors_checked': selectors,
            'records': {}
        }
        
        for selector in selectors:
            dkim_domain = f'{selector}._domainkey.{domain}'
            
            try:
                answers = self.resolver.resolve(dkim_domain, 'TXT', lifetime=self.timeout)
                
                for rdata in answers:
                    txt_string = ''.join([s.decode('utf-8') if isinstance(s, bytes) else s for s in rdata.strings])
                    
                    # DKIM records typically contain v=DKIM1 or k= or p=
                    if any(tag in txt_string for tag in ['v=DKIM1', 'k=', 'p=']):
                        result['selectors_found'].append(selector)
                        result['records'][selector] = {
                            'record': txt_string,
                            'valid': True
                        }
                        break
            
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                # Selector doesn't exist - expected for most
                continue
            except dns.exception.Timeout:
                result['records'][selector] = {
                    'record': None,
                    'valid': False,
                    'error': 'Timeout'
                }
            except Exception as e:
                result['records'][selector] = {
                    'record': None,
                    'valid': False,
                    'error': str(e)
                }
        
        return result
    
    def get_mx_records(self, domain: str) -> Dict:
        """
        Retrieve MX (Mail Exchange) records for a domain.
        
        Args:
            domain: Domain to query
        
        Returns:
            Dictionary with MX record details
        """
        result = {
            'records': [],
            'servers': [],
            'errors': []
        }
        
        try:
            answers = self.resolver.resolve(domain, 'MX', lifetime=self.timeout)
            
            for rdata in answers:
                mx_record = {
                    'priority': rdata.preference,
                    'server': str(rdata.exchange).rstrip('.')
                }
                result['records'].append(mx_record)
                result['servers'].append(mx_record['server'])
            
            # Sort by priority
            result['records'].sort(key=lambda x: x['priority'])
        
        except dns.resolver.NXDOMAIN:
            result['errors'].append('Domain does not exist')
        except dns.resolver.NoAnswer:
            result['errors'].append('No MX records found')
        except dns.exception.Timeout:
            result['errors'].append('DNS query timeout')
        except Exception as e:
            result['errors'].append(f'DNS query error: {str(e)}')
        
        return result
    
    def _default_dkim_selectors(self) -> List[str]:
        """
        Get default list of common DKIM selectors to check.
        
        Returns:
            List of common DKIM selector names
        """
        return [
            'default', 'google', 'k1', 'k2', 'k3',
            'selector1', 'selector2', 'selector',
            'dkim', 'mail', 'email', 'mx',
            's1', 's2', 'smtp', 'mandrill',
            'pm', 'mta', 'key1', 'key2'
        ]


def get_dns_records(domains: List[str], timeout: int = 5, retries: int = 2,
                   verbose: bool = False, dkim_selectors: List[str] = None) -> Dict:
    """
    Get DNS email security records for a list of domains.
    
    Args:
        domains: List of domains to analyze
        timeout: DNS query timeout in seconds
        retries: Number of retries for failed queries
        verbose: Enable verbose output
        dkim_selectors: Custom list of DKIM selectors to check
    
    Returns:
        Dictionary mapping each domain to its DNS analysis results
    """
    analyzer = DNSAnalyzer(timeout=timeout, retries=retries, verbose=verbose)
    results = {}
    
    for domain in domains:
        if verbose:
            print(f"  [*] Getting DNS records for: {domain}")
        
        results[domain] = analyzer.analyze_domain(domain, dkim_selectors)
    
    return results


def assess_security_posture(dns_results: Dict) -> Dict:
    """
    Assess the security posture based on DNS records.
    
    Args:
        dns_results: DNS analysis results from analyze_domain()
    
    Returns:
        Dictionary with security assessment and findings
    """
    assessment = {
        'risk_level': 'low',
        'score': 100,
        'findings': [],
        'recommendations': []
    }
    
    domain = dns_results['domain']
    
    # Check if domain has email capability
    if not dns_results['has_email']:
        return {
            'risk_level': 'info',
            'score': 100,
            'findings': ['Domain does not appear to have email capability'],
            'recommendations': []
        }
    
    # Check SPF
    if not dns_results['spf']['valid']:
        assessment['findings'].append('No SPF record found')
        assessment['recommendations'].append('Implement SPF record to prevent email spoofing')
        assessment['score'] -= 30
    else:
        spf_all = dns_results['spf']['all_mechanism']
        if spf_all == '+all':
            assessment['findings'].append('SPF uses +all (allows all senders) - CRITICAL')
            assessment['recommendations'].append('Change SPF to use -all or ~all')
            assessment['score'] -= 40
        elif spf_all == '?all':
            assessment['findings'].append('SPF uses ?all (neutral policy)')
            assessment['recommendations'].append('Change SPF to use -all for strict policy')
            assessment['score'] -= 15
        elif spf_all == '~all':
            assessment['findings'].append('SPF uses ~all (softfail) - consider -all for stricter policy')
            assessment['score'] -= 5
        elif not spf_all:
            assessment['findings'].append('SPF record missing "all" mechanism')
            assessment['recommendations'].append('Add -all or ~all to end of SPF record')
            assessment['score'] -= 20
    
    # Check DMARC
    if not dns_results['dmarc']['valid']:
        assessment['findings'].append('No DMARC record found')
        assessment['recommendations'].append('Implement DMARC policy to protect domain reputation')
        assessment['score'] -= 35
    else:
        policy = dns_results['dmarc']['policy']
        if policy == 'none':
            assessment['findings'].append('DMARC policy is set to "none" (monitoring only)')
            assessment['recommendations'].append('Upgrade DMARC policy to "quarantine" or "reject"')
            assessment['score'] -= 10
        elif policy == 'quarantine':
            assessment['findings'].append('DMARC policy is "quarantine" - good, but "reject" is stronger')
            assessment['score'] -= 5
        
        if not dns_results['dmarc']['rua']:
            assessment['findings'].append('DMARC record has no aggregate reporting (rua)')
            assessment['recommendations'].append('Add rua tag to receive DMARC reports')
            assessment['score'] -= 5
    
    # Check DKIM
    if not dns_results['dkim']['selectors_found']:
        assessment['findings'].append('No DKIM selectors found (checked common selectors)')
        assessment['recommendations'].append('Implement DKIM signing for outbound email')
        assessment['score'] -= 20
    
    # Check MX records
    if not dns_results['mx']['records']:
        if dns_results['spf']['valid']:
            assessment['findings'].append('Has SPF but no MX records - unusual configuration')
    
    # Determine risk level based on score
    if assessment['score'] >= 80:
        assessment['risk_level'] = 'low'
    elif assessment['score'] >= 60:
        assessment['risk_level'] = 'medium'
    elif assessment['score'] >= 40:
        assessment['risk_level'] = 'high'
    else:
        assessment['risk_level'] = 'critical'
    
    return assessment


if __name__ == "__main__":
    # Example usage
    test_domains = ["example.com", "google.com"]
    
    print("DNS Email Security Analysis")
    print("="*50)
    
    results = get_dns_records(test_domains, verbose=True)
    
    for domain, data in results.items():
        print(f"\n{'='*50}")
        print(f"Domain: {domain}")
        print(f"{'='*50}")
        
        print(f"\nSPF Record: {data['spf']['record']}")
        print(f"DMARC Record: {data['dmarc']['record']}")
        print(f"DKIM Selectors Found: {data['dkim']['selectors_found']}")
        print(f"MX Records: {len(data['mx']['records'])}")
        
        # Security assessment
        assessment = assess_security_posture(data)
        print(f"\nSecurity Score: {assessment['score']}/100")
        print(f"Risk Level: {assessment['risk_level'].upper()}")
        
        if assessment['findings']:
            print("\nFindings:")
            for finding in assessment['findings']:
                print(f"  - {finding}")
