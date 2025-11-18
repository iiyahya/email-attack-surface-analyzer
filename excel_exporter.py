"""
Excel Export Module

This module handles exporting analysis results to Excel format with multiple sheets
for comprehensive data presentation.
"""

import os
from datetime import datetime
from typing import Dict, List
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
import pandas as pd


class ExcelExporter:
    """Exports analysis results to Excel format."""
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the Excel Exporter.
        
        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
    
    def export_to_excel(self, analysis_results: Dict, output_file: str) -> str:
        """
        Export analysis results to Excel file with multiple sheets.
        
        Args:
            analysis_results: Complete analysis results dictionary
            output_file: Path to save Excel file
        
        Returns:
            Path to generated Excel file
        """
        if self.verbose:
            print(f"  [*] Creating Excel workbook...")
        
        # Create workbook
        wb = openpyxl.Workbook()
        wb.remove(wb.active)  # Remove default sheet
        
        # Create sheets
        self._create_summary_sheet(wb, analysis_results)
        self._create_domain_inventory_sheet(wb, analysis_results)
        self._create_dns_records_sheet(wb, analysis_results)
        self._create_providers_sheet(wb, analysis_results)
        self._create_findings_sheet(wb, analysis_results)
        self._create_detailed_data_sheet(wb, analysis_results)
        
        # Save workbook
        wb.save(output_file)
        
        if self.verbose:
            print(f"  [+] Excel report saved: {output_file}")
        
        return output_file
    
    def _create_summary_sheet(self, wb, results: Dict):
        """Create executive summary sheet."""
        ws = wb.create_sheet("Executive Summary")
        
        # Header
        ws['A1'] = "Email Attack Surface Analysis - Executive Summary"
        ws['A1'].font = Font(size=16, bold=True, color="FFFFFF")
        ws['A1'].fill = PatternFill(start_color="1F4E78", end_color="1F4E78", fill_type="solid")
        ws['A1'].alignment = Alignment(horizontal='center')
        ws.merge_cells('A1:D1')
        
        # Metadata
        ws['A3'] = "Report Generated:"
        ws['B3'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ws['A3'].font = Font(bold=True)
        
        # Statistics
        row = 5
        ws[f'A{row}'] = "Analysis Statistics"
        ws[f'A{row}'].font = Font(size=14, bold=True)
        row += 1
        
        stats = [
            ("Root Domains Analyzed", len(results.get('root_domains', []))),
            ("Total Subdomains Discovered", sum(len(results.get('enumeration', {}).get(d, [])) for d in results.get('root_domains', []))),
            ("Domains with Email Capability", sum(1 for d in results.get('all_analyzed_domains', []) if results.get('dns_analysis', {}).get(d, {}).get('has_email')))
        ]
        
        for stat_name, stat_value in stats:
            ws[f'A{row}'] = stat_name
            ws[f'B{row}'] = stat_value
            ws[f'A{row}'].font = Font(bold=True)
            row += 1
        
        # Security findings
        row += 1
        ws[f'A{row}'] = "Security Findings"
        ws[f'A{row}'].font = Font(size=14, bold=True)
        row += 1
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for domain_data in results.get('provider_detection', {}).values():
            for misc in domain_data.get('misconfigurations', []):
                severity = misc.get('severity', 'low')
                severity_counts[severity] += 1
        
        findings = [
            ("Critical Issues", severity_counts['critical'], "FF0000"),
            ("High Severity Issues", severity_counts['high'], "FF6600"),
            ("Medium Severity Issues", severity_counts['medium'], "FFCC00"),
            ("Low Severity Issues", severity_counts['low'], "00CC00")
        ]
        
        for finding_name, finding_count, color in findings:
            ws[f'A{row}'] = finding_name
            ws[f'B{row}'] = finding_count
            ws[f'A{row}'].font = Font(bold=True)
            if finding_count > 0:
                ws[f'B{row}'].font = Font(bold=True, color=color)
            row += 1
        
        # Auto-adjust columns
        ws.column_dimensions['A'].width = 30
        ws.column_dimensions['B'].width = 20
    
    def _create_domain_inventory_sheet(self, wb, results: Dict):
        """Create domain inventory sheet."""
        ws = wb.create_sheet("Domain Inventory")
        
        # Headers
        headers = ["Root Domain", "Subdomain", "Has Email", "SPF", "DMARC", "DKIM", "MX Count"]
        for col, header in enumerate(headers, 1):
            cell = ws.cell(1, col, header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
            cell.alignment = Alignment(horizontal='center')
        
        # Data
        row = 2
        for root_domain in results.get('root_domains', []):
            subdomains = results.get('enumeration', {}).get(root_domain, [])
            
            if not subdomains:
                ws.cell(row, 1, root_domain)
                ws.cell(row, 2, "-")
                row += 1
                continue
            
            for subdomain in sorted(subdomains):
                dns_data = results.get('dns_analysis', {}).get(subdomain, {})
                
                ws.cell(row, 1, root_domain)
                ws.cell(row, 2, subdomain)
                ws.cell(row, 3, "Yes" if dns_data.get('has_email') else "No")
                ws.cell(row, 4, "✓" if dns_data.get('spf', {}).get('valid') else "✗")
                ws.cell(row, 5, "✓" if dns_data.get('dmarc', {}).get('valid') else "✗")
                ws.cell(row, 6, len(dns_data.get('dkim', {}).get('selectors_found', [])))
                ws.cell(row, 7, len(dns_data.get('mx', {}).get('records', [])))
                
                row += 1
        
        # Auto-adjust columns
        for col in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col)].width = 20
    
    def _create_dns_records_sheet(self, wb, results: Dict):
        """Create DNS records sheet."""
        ws = wb.create_sheet("DNS Security Records")
        
        # Headers
        headers = ["Domain", "SPF Record", "DMARC Record", "DKIM Selectors", "MX Servers", "Risk Level"]
        for col, header in enumerate(headers, 1):
            cell = ws.cell(1, col, header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
            cell.alignment = Alignment(horizontal='center')
        
        # Data
        row = 2
        for domain in sorted(results.get('all_analyzed_domains', [])):
            dns_data = results.get('dns_analysis', {}).get(domain, {})
            
            if not dns_data.get('has_email'):
                continue
            
            provider_data = results.get('provider_detection', {}).get(domain, {})
            risk_level = provider_data.get('risk_score', {}).get('level', 'unknown').upper()
            
            ws.cell(row, 1, domain)
            ws.cell(row, 2, dns_data.get('spf', {}).get('record', 'N/A') if dns_data.get('spf', {}).get('valid') else 'Not Found')
            ws.cell(row, 3, dns_data.get('dmarc', {}).get('record', 'N/A') if dns_data.get('dmarc', {}).get('valid') else 'Not Found')
            ws.cell(row, 4, ', '.join(dns_data.get('dkim', {}).get('selectors_found', [])) or 'None')
            
            mx_servers = ', '.join([r['server'] for r in dns_data.get('mx', {}).get('records', [])])
            ws.cell(row, 5, mx_servers or 'None')
            
            ws.cell(row, 6, risk_level)
            
            # Color code risk level
            risk_colors = {
                'CRITICAL': 'FF0000',
                'HIGH': 'FF6600',
                'MEDIUM': 'FFCC00',
                'LOW': '00CC00'
            }
            if risk_level in risk_colors:
                ws.cell(row, 6).font = Font(bold=True, color=risk_colors[risk_level])
            
            row += 1
        
        # Auto-adjust columns
        ws.column_dimensions['A'].width = 25
        ws.column_dimensions['B'].width = 50
        ws.column_dimensions['C'].width = 50
        ws.column_dimensions['D'].width = 30
        ws.column_dimensions['E'].width = 40
        ws.column_dimensions['F'].width = 15
    
    def _create_providers_sheet(self, wb, results: Dict):
        """Create email providers sheet."""
        ws = wb.create_sheet("Email Providers")
        
        # Headers
        headers = ["Domain", "Provider", "Confidence", "Detection Method"]
        for col, header in enumerate(headers, 1):
            cell = ws.cell(1, col, header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
            cell.alignment = Alignment(horizontal='center')
        
        # Data
        row = 2
        for domain in sorted(results.get('all_analyzed_domains', [])):
            provider_data = results.get('provider_detection', {}).get(domain, {})
            providers_info = provider_data.get('providers', {})
            
            providers = providers_info.get('providers', [])
            if not providers:
                ws.cell(row, 1, domain)
                ws.cell(row, 2, "None detected")
                row += 1
                continue
            
            for provider in providers:
                confidence = providers_info.get('confidence', {}).get(provider, 0)
                details = providers_info.get('details', {}).get(provider, {})
                matches = details.get('matches', [])
                
                ws.cell(row, 1, domain)
                ws.cell(row, 2, provider)
                ws.cell(row, 3, f"{confidence}%")
                ws.cell(row, 4, ', '.join(matches[:3]))  # Show first 3 matches
                
                row += 1
        
        # Auto-adjust columns
        for col in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col)].width = 25
    
    def _create_findings_sheet(self, wb, results: Dict):
        """Create security findings sheet."""
        ws = wb.create_sheet("Security Findings")
        
        # Headers
        headers = ["Severity", "Domain", "Issue Type", "Title", "Description", "Remediation"]
        for col, header in enumerate(headers, 1):
            cell = ws.cell(1, col, header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
            cell.alignment = Alignment(horizontal='center')
        
        # Collect all findings
        findings = []
        for domain in results.get('all_analyzed_domains', []):
            provider_data = results.get('provider_detection', {}).get(domain, {})
            for misc in provider_data.get('misconfigurations', []):
                findings.append((domain, misc))
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        findings.sort(key=lambda x: severity_order.get(x[1].get('severity', 'low'), 4))
        
        # Data
        row = 2
        for domain, misc in findings:
            severity = misc.get('severity', 'low').upper()
            
            ws.cell(row, 1, severity)
            ws.cell(row, 2, domain)
            ws.cell(row, 3, misc.get('type', 'unknown'))
            ws.cell(row, 4, misc.get('title', 'No title'))
            ws.cell(row, 5, misc.get('description', 'No description'))
            ws.cell(row, 6, misc.get('remediation', 'No remediation'))
            
            # Color code severity
            severity_colors = {
                'CRITICAL': 'FF0000',
                'HIGH': 'FF6600',
                'MEDIUM': 'FFCC00',
                'LOW': '00CC00'
            }
            if severity in severity_colors:
                ws.cell(row, 1).font = Font(bold=True, color=severity_colors[severity])
            
            # Wrap text
            ws.cell(row, 5).alignment = Alignment(wrap_text=True)
            ws.cell(row, 6).alignment = Alignment(wrap_text=True)
            
            row += 1
        
        # Auto-adjust columns
        ws.column_dimensions['A'].width = 12
        ws.column_dimensions['B'].width = 25
        ws.column_dimensions['C'].width = 20
        ws.column_dimensions['D'].width = 30
        ws.column_dimensions['E'].width = 50
        ws.column_dimensions['F'].width = 50
        
        # Set row height for better readability
        for r in range(2, row):
            ws.row_dimensions[r].height = 30
    
    def _create_detailed_data_sheet(self, wb, results: Dict):
        """Create detailed data sheet with all raw information."""
        ws = wb.create_sheet("Detailed Data")
        
        # Headers
        headers = [
            "Domain", "Root Domain", "Has Email", 
            "SPF Valid", "SPF Record", "SPF All Mechanism",
            "DMARC Valid", "DMARC Record", "DMARC Policy",
            "DKIM Selectors Found", "DKIM Selectors Checked",
            "MX Count", "MX Servers",
            "Providers Detected", "Risk Level", "Risk Score",
            "Issues Count", "Critical", "High", "Medium", "Low"
        ]
        
        for col, header in enumerate(headers, 1):
            cell = ws.cell(1, col, header)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
            cell.alignment = Alignment(horizontal='center')
        
        # Data
        row = 2
        for domain in sorted(results.get('all_analyzed_domains', [])):
            dns_data = results.get('dns_analysis', {}).get(domain, {})
            provider_data = results.get('provider_detection', {}).get(domain, {})
            
            # Find root domain
            root_domain = next((rd for rd in results.get('root_domains', []) if domain.endswith(rd)), 'N/A')
            
            # Count issues by severity
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for misc in provider_data.get('misconfigurations', []):
                severity = misc.get('severity', 'low')
                severity_counts[severity] += 1
            
            col = 1
            ws.cell(row, col, domain); col += 1
            ws.cell(row, col, root_domain); col += 1
            ws.cell(row, col, "Yes" if dns_data.get('has_email') else "No"); col += 1
            
            ws.cell(row, col, "Yes" if dns_data.get('spf', {}).get('valid') else "No"); col += 1
            ws.cell(row, col, dns_data.get('spf', {}).get('record', 'N/A')); col += 1
            ws.cell(row, col, dns_data.get('spf', {}).get('all_mechanism', 'N/A')); col += 1
            
            ws.cell(row, col, "Yes" if dns_data.get('dmarc', {}).get('valid') else "No"); col += 1
            ws.cell(row, col, dns_data.get('dmarc', {}).get('record', 'N/A')); col += 1
            ws.cell(row, col, dns_data.get('dmarc', {}).get('policy', 'N/A')); col += 1
            
            ws.cell(row, col, len(dns_data.get('dkim', {}).get('selectors_found', []))); col += 1
            ws.cell(row, col, len(dns_data.get('dkim', {}).get('selectors_checked', []))); col += 1
            
            ws.cell(row, col, len(dns_data.get('mx', {}).get('records', []))); col += 1
            mx_servers = ', '.join([r['server'] for r in dns_data.get('mx', {}).get('records', [])])
            ws.cell(row, col, mx_servers or 'None'); col += 1
            
            providers = ', '.join(provider_data.get('providers', {}).get('providers', []))
            ws.cell(row, col, providers or 'None'); col += 1
            
            risk_level = provider_data.get('risk_score', {}).get('level', 'unknown').upper()
            ws.cell(row, col, risk_level); col += 1
            ws.cell(row, col, provider_data.get('risk_score', {}).get('score', 0)); col += 1
            
            ws.cell(row, col, len(provider_data.get('misconfigurations', []))); col += 1
            ws.cell(row, col, severity_counts['critical']); col += 1
            ws.cell(row, col, severity_counts['high']); col += 1
            ws.cell(row, col, severity_counts['medium']); col += 1
            ws.cell(row, col, severity_counts['low']); col += 1
            
            row += 1
        
        # Auto-adjust columns
        for col in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col)].width = 20


def export_to_excel(analysis_results: Dict, output_file: str, verbose: bool = False) -> str:
    """
    Export analysis results to Excel file.
    
    Args:
        analysis_results: Complete analysis results
        output_file: Path to save Excel file
        verbose: Enable verbose output
    
    Returns:
        Path to generated Excel file
    """
    exporter = ExcelExporter(verbose=verbose)
    return exporter.export_to_excel(analysis_results, output_file)


def export_to_csv(analysis_results: Dict, output_dir: str, verbose: bool = False) -> List[str]:
    """
    Export analysis results to CSV files.
    
    Args:
        analysis_results: Complete analysis results
        output_dir: Directory to save CSV files
        verbose: Enable verbose output
    
    Returns:
        List of paths to generated CSV files
    """
    os.makedirs(output_dir, exist_ok=True)
    csv_files = []
    
    # DNS Records CSV
    dns_data = []
    for domain in sorted(analysis_results.get('all_analyzed_domains', [])):
        dns = analysis_results.get('dns_analysis', {}).get(domain, {})
        provider_data = analysis_results.get('provider_detection', {}).get(domain, {})
        
        dns_data.append({
            'Domain': domain,
            'Has_Email': dns.get('has_email'),
            'SPF_Valid': dns.get('spf', {}).get('valid'),
            'SPF_Record': dns.get('spf', {}).get('record', ''),
            'DMARC_Valid': dns.get('dmarc', {}).get('valid'),
            'DMARC_Record': dns.get('dmarc', {}).get('record', ''),
            'DMARC_Policy': dns.get('dmarc', {}).get('policy', ''),
            'DKIM_Selectors': ','.join(dns.get('dkim', {}).get('selectors_found', [])),
            'MX_Count': len(dns.get('mx', {}).get('records', [])),
            'Providers': ','.join(provider_data.get('providers', {}).get('providers', [])),
            'Risk_Level': provider_data.get('risk_score', {}).get('level', ''),
            'Issues_Count': len(provider_data.get('misconfigurations', []))
        })
    
    if dns_data:
        csv_file = os.path.join(output_dir, 'dns_records.csv')
        pd.DataFrame(dns_data).to_csv(csv_file, index=False)
        csv_files.append(csv_file)
        if verbose:
            print(f"  [+] CSV saved: {csv_file}")
    
    # Findings CSV
    findings_data = []
    for domain in analysis_results.get('all_analyzed_domains', []):
        provider_data = analysis_results.get('provider_detection', {}).get(domain, {})
        for misc in provider_data.get('misconfigurations', []):
            findings_data.append({
                'Domain': domain,
                'Severity': misc.get('severity', ''),
                'Type': misc.get('type', ''),
                'Title': misc.get('title', ''),
                'Description': misc.get('description', ''),
                'Remediation': misc.get('remediation', '')
            })
    
    if findings_data:
        csv_file = os.path.join(output_dir, 'security_findings.csv')
        pd.DataFrame(findings_data).to_csv(csv_file, index=False)
        csv_files.append(csv_file)
        if verbose:
            print(f"  [+] CSV saved: {csv_file}")
    
    return csv_files


if __name__ == "__main__":
    # Example usage
    print("Excel Export Module - Use export_to_excel() function")
