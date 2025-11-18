"""
Email Provider Detection Module

This module detects external email providers and services based on
MX records, SPF records, and other DNS indicators.
"""

import re
from typing import Dict, List, Set, Optional


class EmailProviderDetector:
    """Detects email providers and services from DNS records."""
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the Email Provider Detector.
        
        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        
        # Define provider signatures
        self.provider_patterns = {
            'Google Workspace': {
                'mx_patterns': [
                    r'.*\.googlemail\.com$',
                    r'.*google\.com$',
                    r'aspmx.*\.l\.google\.com$'
                ],
                'spf_includes': [
                    '_spf.google.com',
                    'include:_spf.google.com'
                ],
                'dkim_selectors': ['google']
            },
            'Microsoft 365': {
                'mx_patterns': [
                    r'.*\.mail\.protection\.outlook\.com$',
                    r'.*\.pamx1\.hotmail\.com$',
                    r'.*\.outlook\.com$'
                ],
                'spf_includes': [
                    'spf.protection.outlook.com',
                    'include:spf.protection.outlook.com'
                ],
                'dkim_selectors': ['selector1', 'selector2']
            },
            'Zoho Mail': {
                'mx_patterns': [
                    r'.*\.mx\.zoho\.com$',
                    r'.*\.zoho\.com$'
                ],
                'spf_includes': [
                    'zoho.com',
                    'include:zoho.com'
                ],
                'dkim_selectors': ['zoho']
            },
            'Proofpoint': {
                'mx_patterns': [
                    r'.*\.pphosted\.com$',
                    r'.*\.proofpoint\.com$'
                ],
                'spf_includes': [
                    'spf.protection.outlook.com',
                    '_spf.proofpoint.com'
                ],
                'dkim_selectors': []
            },
            'Cloudflare Email': {
                'mx_patterns': [
                    r'.*\.cloudflare\.net$'
                ],
                'spf_includes': [
                    '_spf.mx.cloudflare.net'
                ],
                'dkim_selectors': []
            },
            'SendGrid': {
                'mx_patterns': [
                    r'.*\.sendgrid\.net$'
                ],
                'spf_includes': [
                    'sendgrid.net',
                    'include:sendgrid.net'
                ],
                'dkim_selectors': ['sendgrid', 's1', 's2']
            },
            'Mailgun': {
                'mx_patterns': [
                    r'.*\.mailgun\.org$'
                ],
                'spf_includes': [
                    'mailgun.org',
                    'include:mailgun.org'
                ],
                'dkim_selectors': ['mailgun', 'smtp', 'mail']
            },
            'Amazon SES': {
                'mx_patterns': [
                    r'.*\.amazonaws\.com$',
                    r'inbound-smtp\..*\.amazonaws\.com$'
                ],
                'spf_includes': [
                    'amazonses.com',
                    'include:amazonses.com'
                ],
                'dkim_selectors': []
            },
            'Mimecast': {
                'mx_patterns': [
                    r'.*\.mimecast\.com$'
                ],
                'spf_includes': [
                    '_spf.mimecast.com'
                ],
                'dkim_selectors': []
            },
            'Barracuda': {
                'mx_patterns': [
                    r'.*\.barracudanetworks\.com$',
                    r'.*\.cuda-inc\.com$'
                ],
                'spf_includes': [
                    'barracudanetworks.com'
                ],
                'dkim_selectors': []
            },
            'GoDaddy': {
                'mx_patterns': [
                    r'.*\.secureserver\.net$',
                    r'mailstore1\.secureserver\.net$'
                ],
                'spf_includes': [
                    'secureserver.net'
                ],
                'dkim_selectors': ['default']
            },
            'Rackspace': {
                'mx_patterns': [
                    r'.*\.emailsrvr\.com$'
                ],
                'spf_includes': [
                    'emailsrvr.com'
                ],
                'dkim_selectors': []
            }
        }
    
    def detect_providers(self, dns_results: Dict) -> Dict:
        """
        Detect email providers from DNS analysis results.
        
        Args:
            dns_results: DNS analysis results from DNSAnalyzer
        
        Returns:
            Dictionary with detected providers and confidence levels
        """
        detected = {
            'providers': [],
            'confidence': {},
            'details': {}
        }
        
        mx_servers = dns_results.get('mx', {}).get('servers', [])
        spf_record = dns_results.get('spf', {}).get('record', '')
        spf_includes = dns_results.get('spf', {}).get('includes', [])
        dkim_selectors = dns_results.get('dkim', {}).get('selectors_found', [])
        
        # Check each provider
        for provider_name, patterns in self.provider_patterns.items():
            confidence_score = 0
            matches = []
            
            # Check MX patterns
            for mx_server in mx_servers:
                for pattern in patterns['mx_patterns']:
                    if re.match(pattern, mx_server, re.IGNORECASE):
                        confidence_score += 40
                        matches.append(f"MX: {mx_server}")
                        break
            
            # Check SPF includes
            for spf_include in spf_includes:
                for pattern in patterns['spf_includes']:
                    if pattern.replace('include:', '') in spf_include.lower():
                        confidence_score += 30
                        matches.append(f"SPF: {spf_include}")
                        break
            
            # Check DKIM selectors
            for dkim_selector in dkim_selectors:
                if dkim_selector in patterns['dkim_selectors']:
                    confidence_score += 20
                    matches.append(f"DKIM: {dkim_selector}")
            
            # If we have matches, record the provider
            if confidence_score > 0:
                detected['providers'].append(provider_name)
                detected['confidence'][provider_name] = min(100, confidence_score)
                detected['details'][provider_name] = {
                    'confidence': min(100, confidence_score),
                    'matches': matches
                }
        
        # Sort providers by confidence
        detected['providers'].sort(
            key=lambda x: detected['confidence'][x],
            reverse=True
        )
        
        return detected
    
    def detect_misconfigurations(self, dns_results: Dict, provider_info: Dict) -> List[Dict]:
        """
        Detect common misconfigurations based on DNS records and detected providers.
        
        Args:
            dns_results: DNS analysis results
            provider_info: Detected provider information
        
        Returns:
            List of misconfiguration findings
        """
        misconfigurations = []
        domain = dns_results.get('domain', 'unknown')
        
        # Check for missing SPF
        if not dns_results.get('spf', {}).get('valid'):
            misconfigurations.append({
                'severity': 'high',
                'type': 'missing_spf',
                'title': 'Missing SPF Record',
                'description': f'Domain {domain} has no SPF record, allowing email spoofing',
                'remediation': 'Create an SPF record to specify authorized mail servers'
            })
        else:
            # Check SPF configuration issues
            spf = dns_results['spf']
            
            # Check for overly permissive SPF
            if spf.get('all_mechanism') == '+all':
                misconfigurations.append({
                    'severity': 'critical',
                    'type': 'permissive_spf',
                    'title': 'Overly Permissive SPF Record',
                    'description': 'SPF record uses +all, allowing any server to send email',
                    'remediation': 'Change +all to -all or ~all to restrict unauthorized senders'
                })
            elif not spf.get('all_mechanism'):
                misconfigurations.append({
                    'severity': 'medium',
                    'type': 'incomplete_spf',
                    'title': 'Incomplete SPF Record',
                    'description': 'SPF record is missing the "all" mechanism',
                    'remediation': 'Add -all or ~all to the end of your SPF record'
                })
        
        # Check for missing DMARC
        if not dns_results.get('dmarc', {}).get('valid'):
            misconfigurations.append({
                'severity': 'high',
                'type': 'missing_dmarc',
                'title': 'Missing DMARC Record',
                'description': f'Domain {domain} has no DMARC policy',
                'remediation': 'Implement DMARC with at least p=none to enable monitoring'
            })
        else:
            # Check DMARC configuration issues
            dmarc = dns_results['dmarc']
            
            # Check for weak DMARC policy
            if dmarc.get('policy') == 'none':
                misconfigurations.append({
                    'severity': 'medium',
                    'type': 'weak_dmarc',
                    'title': 'Weak DMARC Policy',
                    'description': 'DMARC policy is set to "none" (monitoring only)',
                    'remediation': 'After monitoring, upgrade to p=quarantine or p=reject'
                })
            
            # Check for missing aggregate reports
            if not dmarc.get('rua'):
                misconfigurations.append({
                    'severity': 'low',
                    'type': 'no_dmarc_reports',
                    'title': 'No DMARC Reporting Configured',
                    'description': 'DMARC record does not specify aggregate report destination (rua)',
                    'remediation': 'Add rua tag to receive DMARC aggregate reports'
                })
        
        # Check for missing DKIM
        if not dns_results.get('dkim', {}).get('selectors_found'):
            misconfigurations.append({
                'severity': 'medium',
                'type': 'missing_dkim',
                'title': 'No DKIM Records Found',
                'description': 'No DKIM selectors found (checked common selectors)',
                'remediation': 'Configure DKIM signing for your email service'
            })
        
        # Check for MX without SPF/DMARC
        has_mx = bool(dns_results.get('mx', {}).get('records'))
        has_spf = dns_results.get('spf', {}).get('valid')
        has_dmarc = dns_results.get('dmarc', {}).get('valid')
        
        if has_mx and not (has_spf and has_dmarc):
            misconfigurations.append({
                'severity': 'high',
                'type': 'email_without_protection',
                'title': 'Email Server Without Full Protection',
                'description': 'Domain accepts email (has MX) but lacks complete email authentication',
                'remediation': 'Implement SPF, DKIM, and DMARC for complete email security'
            })
        
        # Provider-specific checks
        if provider_info.get('providers'):
            primary_provider = provider_info['providers'][0]
            
            # Google Workspace specific checks
            if primary_provider == 'Google Workspace':
                if 'google' not in dns_results.get('dkim', {}).get('selectors_found', []):
                    misconfigurations.append({
                        'severity': 'medium',
                        'type': 'missing_provider_dkim',
                        'title': 'Google Workspace DKIM Not Configured',
                        'description': 'Using Google Workspace but DKIM selector "google" not found',
                        'remediation': 'Enable DKIM signing in Google Workspace Admin Console'
                    })
            
            # Microsoft 365 specific checks
            elif primary_provider == 'Microsoft 365':
                found_selectors = dns_results.get('dkim', {}).get('selectors_found', [])
                if not any(s in found_selectors for s in ['selector1', 'selector2']):
                    misconfigurations.append({
                        'severity': 'medium',
                        'type': 'missing_provider_dkim',
                        'title': 'Microsoft 365 DKIM Not Configured',
                        'description': 'Using Microsoft 365 but default DKIM selectors not found',
                        'remediation': 'Enable DKIM signing in Microsoft 365 Security & Compliance Center'
                    })
        
        return misconfigurations


def detect_email_providers(dns_results_dict: Dict, verbose: bool = False) -> Dict:
    """
    Detect email providers and misconfigurations for multiple domains.
    
    Args:
        dns_results_dict: Dictionary mapping domains to their DNS analysis results
        verbose: Enable verbose output
    
    Returns:
        Dictionary with provider detection and misconfiguration results for each domain
    """
    detector = EmailProviderDetector(verbose=verbose)
    results = {}
    
    for domain, dns_results in dns_results_dict.items():
        if verbose:
            print(f"  [*] Detecting email providers for: {domain}")
        
        provider_info = detector.detect_providers(dns_results)
        misconfigurations = detector.detect_misconfigurations(dns_results, provider_info)
        
        results[domain] = {
            'providers': provider_info,
            'misconfigurations': misconfigurations,
            'risk_score': calculate_risk_score(misconfigurations)
        }
        
        if verbose and provider_info['providers']:
            print(f"      Detected: {', '.join(provider_info['providers'][:2])}")
        if verbose and misconfigurations:
            print(f"      Found {len(misconfigurations)} misconfigurations")
    
    return results


def calculate_risk_score(misconfigurations: List[Dict]) -> Dict:
    """
    Calculate risk score based on misconfigurations.
    
    Args:
        misconfigurations: List of misconfiguration findings
    
    Returns:
        Dictionary with risk score and level
    """
    severity_weights = {
        'critical': 40,
        'high': 25,
        'medium': 10,
        'low': 5
    }
    
    total_risk = 0
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    for misc in misconfigurations:
        severity = misc.get('severity', 'low')
        severity_counts[severity] += 1
        total_risk += severity_weights.get(severity, 0)
    
    # Determine risk level
    if total_risk >= 60:
        risk_level = 'critical'
    elif total_risk >= 40:
        risk_level = 'high'
    elif total_risk >= 20:
        risk_level = 'medium'
    else:
        risk_level = 'low'
    
    return {
        'score': total_risk,
        'level': risk_level,
        'severity_counts': severity_counts
    }


if __name__ == "__main__":
    # Example usage
    from dns_analyzer import get_dns_records
    
    test_domains = ["example.com"]
    
    print("Email Provider Detection")
    print("="*50)
    
    # First get DNS records
    dns_results = get_dns_records(test_domains, verbose=True)
    
    # Then detect providers
    provider_results = detect_email_providers(dns_results, verbose=True)
    
    for domain, results in provider_results.items():
        print(f"\n{'='*50}")
        print(f"Domain: {domain}")
        print(f"{'='*50}")
        
        providers = results['providers']['providers']
        if providers:
            print(f"\nDetected Providers:")
            for provider in providers:
                confidence = results['providers']['confidence'][provider]
                print(f"  - {provider} (confidence: {confidence}%)")
        else:
            print("\nNo known email providers detected")
        
        misconfigs = results['misconfigurations']
        if misconfigs:
            print(f"\nMisconfigurations Found: {len(misconfigs)}")
            for misc in misconfigs:
                print(f"  [{misc['severity'].upper()}] {misc['title']}")
        
        risk = results['risk_score']
        print(f"\nRisk Score: {risk['score']} ({risk['level'].upper()})")
