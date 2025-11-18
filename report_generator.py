"""
Report Generation Module

This module generates comprehensive reports in both Markdown and JSON formats
for email attack surface analysis results.
"""

import json
from datetime import datetime
from typing import Dict, List
from tabulate import tabulate


class ReportGenerator:
    """Generates reports from email attack surface analysis results."""
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the Report Generator.
        
        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
    
    def generate_markdown_report(self, analysis_results: Dict, output_file: str = None) -> str:
        """
        Generate a comprehensive Markdown report.
        
        Args:
            analysis_results: Complete analysis results dictionary
            output_file: Optional file path to save the report
        
        Returns:
            Markdown report as string
        """
        report_lines = []
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Header
        report_lines.extend([
            "# Email Attack Surface Analysis Report",
            "",
            f"**Generated:** {timestamp}",
            "",
            "---",
            ""
        ])
        
        # Executive Summary
        report_lines.extend(self._generate_executive_summary(analysis_results))
        
        # Domain Inventory
        report_lines.extend(self._generate_domain_inventory(analysis_results))
        
        # DNS Security Analysis
        report_lines.extend(self._generate_dns_analysis(analysis_results))
        
        # Email Provider Detection
        report_lines.extend(self._generate_provider_analysis(analysis_results))
        
        # Security Findings
        report_lines.extend(self._generate_security_findings(analysis_results))
        
        # Recommendations
        report_lines.extend(self._generate_recommendations(analysis_results))
        
        # Detailed Domain Reports
        report_lines.extend(self._generate_detailed_reports(analysis_results))
        
        report = "\n".join(report_lines)
        
        # Save to file if specified
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            if self.verbose:
                print(f"  [+] Markdown report saved to: {output_file}")
        
        return report
    
    def generate_json_report(self, analysis_results: Dict, output_file: str = None) -> str:
        """
        Generate a machine-readable JSON report.
        
        Args:
            analysis_results: Complete analysis results dictionary
            output_file: Optional file path to save the report
        
        Returns:
            JSON report as string
        """
        # Add metadata
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'version': '1.0',
                'tool': 'Email Attack Surface Analyzer'
            },
            'results': analysis_results
        }
        
        json_report = json.dumps(report_data, indent=2, default=str)
        
        # Save to file if specified
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(json_report)
            if self.verbose:
                print(f"  [+] JSON report saved to: {output_file}")
        
        return json_report
    
    def _generate_executive_summary(self, results: Dict) -> List[str]:
        """Generate executive summary section."""
        lines = [
            "## Executive Summary",
            ""
        ]
        
        # Count statistics
        total_domains = len(results.get('root_domains', []))
        total_subdomains = sum(
            len(results.get('enumeration', {}).get(domain, []))
            for domain in results.get('root_domains', [])
        )
        
        # Count domains with email
        domains_with_email = 0
        total_critical = 0
        total_high = 0
        total_medium = 0
        
        for domain in results.get('all_analyzed_domains', []):
            dns_data = results.get('dns_analysis', {}).get(domain, {})
            if dns_data.get('has_email'):
                domains_with_email += 1
            
            provider_data = results.get('provider_detection', {}).get(domain, {})
            misconfigs = provider_data.get('misconfigurations', [])
            for misc in misconfigs:
                severity = misc.get('severity', 'low')
                if severity == 'critical':
                    total_critical += 1
                elif severity == 'high':
                    total_high += 1
                elif severity == 'medium':
                    total_medium += 1
        
        lines.extend([
            f"- **Root Domains Analyzed:** {total_domains}",
            f"- **Total Subdomains Discovered:** {total_subdomains}",
            f"- **Domains with Email Capability:** {domains_with_email}",
            "",
            "### Security Findings Summary",
            "",
            f"- **Critical Issues:** {total_critical}",
            f"- **High Severity Issues:** {total_high}",
            f"- **Medium Severity Issues:** {total_medium}",
            "",
            "---",
            ""
        ])
        
        return lines
    
    def _generate_domain_inventory(self, results: Dict) -> List[str]:
        """Generate domain inventory section."""
        lines = [
            "## Domain Inventory",
            ""
        ]
        
        for root_domain in results.get('root_domains', []):
            subdomains = results.get('enumeration', {}).get(root_domain, [])
            
            lines.extend([
                f"### {root_domain}",
                "",
                f"**Total Subdomains:** {len(subdomains)}",
                ""
            ])
            
            if subdomains:
                lines.append("**Discovered Subdomains:**")
                lines.append("")
                for subdomain in sorted(subdomains)[:20]:  # Show first 20
                    lines.append(f"- `{subdomain}`")
                
                if len(subdomains) > 20:
                    lines.append(f"- ... and {len(subdomains) - 20} more")
                
                lines.append("")
        
        lines.extend(["---", ""])
        return lines
    
    def _generate_dns_analysis(self, results: Dict) -> List[str]:
        """Generate DNS security analysis section."""
        lines = [
            "## DNS Security Records Analysis",
            ""
        ]
        
        # Create summary table
        table_data = []
        
        for domain in results.get('all_analyzed_domains', []):
            dns_data = results.get('dns_analysis', {}).get(domain, {})
            
            if not dns_data.get('has_email'):
                continue
            
            spf_status = "✓" if dns_data.get('spf', {}).get('valid') else "✗"
            dmarc_status = "✓" if dns_data.get('dmarc', {}).get('valid') else "✗"
            dkim_count = len(dns_data.get('dkim', {}).get('selectors_found', []))
            mx_count = len(dns_data.get('mx', {}).get('records', []))
            
            # Risk assessment
            assessment = self._assess_domain_risk(dns_data)
            
            table_data.append([
                domain,
                spf_status,
                dmarc_status,
                dkim_count,
                mx_count,
                assessment.upper()
            ])
        
        if table_data:
            lines.append("### Summary Table")
            lines.append("")
            
            table = tabulate(
                table_data,
                headers=['Domain', 'SPF', 'DMARC', 'DKIM', 'MX', 'Risk'],
                tablefmt='pipe'
            )
            lines.append(table)
            lines.append("")
        
        lines.extend(["---", ""])
        return lines
    
    def _generate_provider_analysis(self, results: Dict) -> List[str]:
        """Generate email provider detection section."""
        lines = [
            "## Email Provider Detection",
            ""
        ]
        
        provider_summary = {}
        
        for domain in results.get('all_analyzed_domains', []):
            provider_data = results.get('provider_detection', {}).get(domain, {})
            providers = provider_data.get('providers', {}).get('providers', [])
            
            for provider in providers:
                if provider not in provider_summary:
                    provider_summary[provider] = []
                provider_summary[provider].append(domain)
        
        if provider_summary:
            lines.append("### Detected Providers")
            lines.append("")
            
            for provider, domains in sorted(provider_summary.items()):
                lines.append(f"#### {provider}")
                lines.append("")
                lines.append(f"**Domains using this provider:** {len(domains)}")
                lines.append("")
                for domain in sorted(domains)[:10]:
                    confidence = results.get('provider_detection', {}).get(domain, {}).get(
                        'providers', {}).get('confidence', {}).get(provider, 0)
                    lines.append(f"- `{domain}` (confidence: {confidence}%)")
                
                if len(domains) > 10:
                    lines.append(f"- ... and {len(domains) - 10} more")
                
                lines.append("")
        else:
            lines.append("No external email providers detected.")
            lines.append("")
        
        lines.extend(["---", ""])
        return lines
    
    def _generate_security_findings(self, results: Dict) -> List[str]:
        """Generate security findings section."""
        lines = [
            "## Security Findings",
            ""
        ]
        
        # Collect all misconfigurations by severity
        findings_by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for domain in results.get('all_analyzed_domains', []):
            provider_data = results.get('provider_detection', {}).get(domain, {})
            misconfigs = provider_data.get('misconfigurations', [])
            
            for misc in misconfigs:
                severity = misc.get('severity', 'low')
                findings_by_severity[severity].append((domain, misc))
        
        # Report findings by severity
        severity_icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢'
        }
        
        for severity in ['critical', 'high', 'medium', 'low']:
            findings = findings_by_severity[severity]
            
            if findings:
                lines.append(f"### {severity_icons[severity]} {severity.upper()} Severity Issues ({len(findings)})")
                lines.append("")
                
                # Group by type
                by_type = {}
                for domain, misc in findings:
                    misc_type = misc.get('type', 'unknown')
                    if misc_type not in by_type:
                        by_type[misc_type] = []
                    by_type[misc_type].append(domain)
                
                for misc_type, domains in by_type.items():
                    # Get example misconfiguration
                    example = next(
                        (m for d, m in findings if m.get('type') == misc_type),
                        {}
                    )
                    
                    lines.extend([
                        f"#### {example.get('title', misc_type)}",
                        "",
                        f"**Description:** {example.get('description', 'No description')}",
                        "",
                        f"**Affected Domains:** {len(domains)}",
                        ""
                    ])
                    
                    for domain in sorted(domains)[:5]:
                        lines.append(f"- `{domain}`")
                    
                    if len(domains) > 5:
                        lines.append(f"- ... and {len(domains) - 5} more")
                    
                    lines.extend([
                        "",
                        f"**Remediation:** {example.get('remediation', 'No remediation provided')}",
                        ""
                    ])
        
        if not any(findings_by_severity.values()):
            lines.append("No security findings detected. ✓")
            lines.append("")
        
        lines.extend(["---", ""])
        return lines
    
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate recommendations section."""
        lines = [
            "## Recommendations",
            "",
            "Based on the analysis, here are prioritized recommendations:",
            ""
        ]
        
        # Collect unique recommendations with priority
        recommendations = []
        
        # Count issues by type
        missing_spf = 0
        missing_dmarc = 0
        missing_dkim = 0
        weak_spf = 0
        weak_dmarc = 0
        
        for domain in results.get('all_analyzed_domains', []):
            dns_data = results.get('dns_analysis', {}).get(domain, {})
            
            if not dns_data.get('has_email'):
                continue
            
            if not dns_data.get('spf', {}).get('valid'):
                missing_spf += 1
            elif dns_data.get('spf', {}).get('all_mechanism') in ['+all', '?all']:
                weak_spf += 1
            
            if not dns_data.get('dmarc', {}).get('valid'):
                missing_dmarc += 1
            elif dns_data.get('dmarc', {}).get('policy') == 'none':
                weak_dmarc += 1
            
            if not dns_data.get('dkim', {}).get('selectors_found'):
                missing_dkim += 1
        
        # Generate prioritized recommendations
        if missing_spf > 0:
            recommendations.append(
                f"**[CRITICAL]** Implement SPF records for {missing_spf} domain(s) "
                "to prevent email spoofing and improve deliverability."
            )
        
        if missing_dmarc > 0:
            recommendations.append(
                f"**[HIGH]** Implement DMARC policies for {missing_dmarc} domain(s) "
                "to protect your domain reputation and enable email authentication reporting."
            )
        
        if missing_dkim > 0:
            recommendations.append(
                f"**[HIGH]** Configure DKIM signing for {missing_dkim} domain(s) "
                "to cryptographically authenticate your outbound email."
            )
        
        if weak_spf > 0:
            recommendations.append(
                f"**[MEDIUM]** Strengthen SPF policies for {weak_spf} domain(s) "
                "by using restrictive qualifiers (-all or ~all)."
            )
        
        if weak_dmarc > 0:
            recommendations.append(
                f"**[MEDIUM]** Upgrade DMARC policies for {weak_dmarc} domain(s) "
                "from p=none to p=quarantine or p=reject after monitoring period."
            )
        
        # Add best practices
        recommendations.extend([
            "",
            "### General Best Practices",
            "",
            "1. **Monitor DMARC Reports**: Regularly review aggregate (rua) and forensic (ruf) reports",
            "2. **Gradual Policy Enforcement**: Start with p=none, then move to p=quarantine, finally p=reject",
            "3. **Keep Records Updated**: Update SPF, DKIM, and DMARC records when changing email providers",
            "4. **Regular Audits**: Perform quarterly reviews of your email security posture",
            "5. **Subdomain Protection**: Ensure subdomains also have proper email authentication"
        ])
        
        if recommendations:
            for rec in recommendations:
                lines.append(rec)
                lines.append("")
        else:
            lines.append("✓ No critical recommendations - your email security posture is good!")
            lines.append("")
        
        lines.extend(["---", ""])
        return lines
    
    def _generate_detailed_reports(self, results: Dict) -> List[str]:
        """Generate detailed per-domain reports."""
        lines = [
            "## Detailed Domain Reports",
            ""
        ]
        
        for domain in sorted(results.get('all_analyzed_domains', []))[:10]:  # Show first 10
            dns_data = results.get('dns_analysis', {}).get(domain, {})
            provider_data = results.get('provider_detection', {}).get(domain, {})
            
            if not dns_data.get('has_email'):
                continue
            
            lines.extend([
                f"### {domain}",
                ""
            ])
            
            # DNS Records
            lines.append("#### DNS Email Records")
            lines.append("")
            
            spf = dns_data.get('spf', {})
            if spf.get('valid'):
                lines.append(f"**SPF Record:**")
                lines.append("```")
                lines.append(spf.get('record', 'N/A'))
                lines.append("```")
                lines.append("")
            else:
                lines.append("**SPF Record:** ✗ Not found")
                lines.append("")
            
            dmarc = dns_data.get('dmarc', {})
            if dmarc.get('valid'):
                lines.append(f"**DMARC Record:**")
                lines.append("```")
                lines.append(dmarc.get('record', 'N/A'))
                lines.append("```")
                lines.append("")
            else:
                lines.append("**DMARC Record:** ✗ Not found")
                lines.append("")
            
            dkim_selectors = dns_data.get('dkim', {}).get('selectors_found', [])
            if dkim_selectors:
                lines.append(f"**DKIM Selectors Found:** {', '.join(dkim_selectors)}")
                lines.append("")
            else:
                lines.append("**DKIM Selectors:** ✗ None found")
                lines.append("")
            
            mx_records = dns_data.get('mx', {}).get('records', [])
            if mx_records:
                lines.append("**MX Records:**")
                for mx in mx_records:
                    lines.append(f"- Priority {mx['priority']}: `{mx['server']}`")
                lines.append("")
            
            # Detected Providers
            providers = provider_data.get('providers', {}).get('providers', [])
            if providers:
                lines.append("**Detected Email Providers:**")
                for provider in providers:
                    confidence = provider_data.get('providers', {}).get('confidence', {}).get(provider, 0)
                    lines.append(f"- {provider} ({confidence}% confidence)")
                lines.append("")
            
            # Risk Assessment
            risk = provider_data.get('risk_score', {})
            risk_level = risk.get('level', 'unknown')
            lines.append(f"**Risk Level:** {risk_level.upper()}")
            lines.append("")
            
            lines.append("---")
            lines.append("")
        
        total_domains = len([d for d in results.get('all_analyzed_domains', [])
                           if results.get('dns_analysis', {}).get(d, {}).get('has_email')])
        if total_domains > 10:
            lines.append(f"*Showing first 10 of {total_domains} domains with email capability*")
            lines.append("")
        
        return lines
    
    def _assess_domain_risk(self, dns_data: Dict) -> str:
        """Assess risk level for a domain."""
        score = 0
        
        if not dns_data.get('spf', {}).get('valid'):
            score += 3
        elif dns_data.get('spf', {}).get('all_mechanism') == '+all':
            score += 4
        
        if not dns_data.get('dmarc', {}).get('valid'):
            score += 3
        elif dns_data.get('dmarc', {}).get('policy') == 'none':
            score += 1
        
        if not dns_data.get('dkim', {}).get('selectors_found'):
            score += 2
        
        if score >= 6:
            return 'critical'
        elif score >= 4:
            return 'high'
        elif score >= 2:
            return 'medium'
        else:
            return 'low'


def generate_report(analysis_results: Dict, output_dir: str = ".", verbose: bool = False) -> Dict:
    """
    Generate both Markdown and JSON reports.
    
    Args:
        analysis_results: Complete analysis results
        output_dir: Directory to save reports
        verbose: Enable verbose output
    
    Returns:
        Dictionary with paths to generated reports
    """
    import os
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    markdown_file = os.path.join(output_dir, f"report_{timestamp}.md")
    json_file = os.path.join(output_dir, f"results_{timestamp}.json")
    
    generator = ReportGenerator(verbose=verbose)
    
    if verbose:
        print("\n[+] Generating reports...")
    
    # Generate Markdown report
    generator.generate_markdown_report(analysis_results, markdown_file)
    
    # Generate JSON report
    generator.generate_json_report(analysis_results, json_file)
    
    return {
        'markdown': markdown_file,
        'json': json_file
    }


if __name__ == "__main__":
    # Example usage with sample data
    sample_results = {
        'root_domains': ['example.com'],
        'all_analyzed_domains': ['example.com'],
        'enumeration': {
            'example.com': ['example.com', 'mail.example.com']
        },
        'dns_analysis': {
            'example.com': {
                'domain': 'example.com',
                'has_email': True,
                'spf': {'valid': False, 'record': None},
                'dmarc': {'valid': False, 'record': None},
                'dkim': {'selectors_found': []},
                'mx': {'records': [{'priority': 10, 'server': 'mail.example.com'}]}
            }
        },
        'provider_detection': {
            'example.com': {
                'providers': {'providers': []},
                'misconfigurations': [
                    {
                        'severity': 'high',
                        'type': 'missing_spf',
                        'title': 'Missing SPF Record',
                        'description': 'No SPF record found',
                        'remediation': 'Implement SPF'
                    }
                ],
                'risk_score': {'level': 'high', 'score': 25}
            }
        }
    }
    
    print("Generating sample report...")
    generate_report(sample_results, output_dir="./reports", verbose=True)
    print("\nDone!")
