#!/usr/bin/env python3
"""
Email Attack Surface Analyzer - Main Script

This is the main orchestration script that coordinates all modules to perform
a comprehensive email security analysis of an organization's domains.

Usage:
    python main.py example.com example.org
    python main.py -f domains.txt
    python main.py example.com --no-enum -v
"""

import argparse
import os
import sys
from typing import List
from datetime import datetime
from dotenv import load_dotenv
from colorama import init, Fore, Style

# Import our modules
from subdomain_enum import enum_domains
from dns_analyzer import get_dns_records
from provider_detector import detect_email_providers
from report_generator import generate_report


# Initialize colorama for cross-platform colored output
init(autoreset=True)


class EmailAttackSurfaceAnalyzer:
    """Main orchestrator for email attack surface analysis."""
    
    def __init__(self, args):
        """
        Initialize the analyzer with command-line arguments.
        
        Args:
            args: Parsed command-line arguments
        """
        self.args = args
        self.verbose = args.verbose
        self.root_domains = []
        self.all_domains = []
        self.results = {
            'root_domains': [],
            'enumeration': {},
            'all_analyzed_domains': [],
            'dns_analysis': {},
            'provider_detection': {}
        }
        
        # Load environment variables
        load_dotenv()
        
        # Get configuration from environment or args
        self.config = {
            'virustotal_api_key': os.getenv('VIRUSTOTAL_API_KEY'),
            'sublister_path': os.getenv('SUBLISTER_PATH'),
            'amass_path': os.getenv('AMASS_PATH', 'amass'),
            'subfinder_path': os.getenv('SUBFINDER_PATH', 'subfinder'),
            'dns_timeout': int(os.getenv('DNS_TIMEOUT', args.timeout)),
            'dkim_selectors': os.getenv('DKIM_SELECTORS', 
                'default,google,k1,k2,k3,selector1,selector2,dkim,mail,email,mx').split(',')
        }
    
    def run(self):
        """Execute the complete analysis workflow."""
        try:
            self.print_banner()
            
            # Step 1: Load domains
            self.load_domains()
            
            # Step 2: Enumerate subdomains (if not disabled)
            if not self.args.no_enum:
                self.enumerate_subdomains()
            else:
                self.print_info("Subdomain enumeration disabled, analyzing root domains only")
                self.all_domains = self.root_domains.copy()
            
            # Step 3: Analyze DNS records
            self.analyze_dns()
            
            # Step 4: Detect email providers and misconfigurations
            self.detect_providers()
            
            # Step 5: Generate reports
            self.generate_reports()
            
            # Step 6: Print summary
            self.print_summary()
            
            self.print_success("\n✓ Analysis complete!")
            
            return 0
        
        except KeyboardInterrupt:
            self.print_error("\n\n✗ Analysis interrupted by user")
            return 1
        except Exception as e:
            self.print_error(f"\n✗ Fatal error: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return 1
    
    def load_domains(self):
        """Load domains from command line or file."""
        self.print_header("Loading Target Domains")
        
        if self.args.file:
            # Load from file
            try:
                with open(self.args.file, 'r') as f:
                    domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                self.root_domains = domains
                self.print_info(f"Loaded {len(domains)} domains from {self.args.file}")
            except FileNotFoundError:
                self.print_error(f"File not found: {self.args.file}")
                sys.exit(1)
            except Exception as e:
                self.print_error(f"Error reading file: {e}")
                sys.exit(1)
        else:
            # Load from command line
            self.root_domains = self.args.domains
            self.print_info(f"Analyzing {len(self.root_domains)} domain(s)")
        
        # Validate domains
        if not self.root_domains:
            self.print_error("No domains specified. Use 'python main.py --help' for usage.")
            sys.exit(1)
        
        # Display domains
        for domain in self.root_domains:
            self.print_item(domain)
        
        self.results['root_domains'] = self.root_domains
    
    def enumerate_subdomains(self):
        """Enumerate subdomains for all root domains."""
        self.print_header("Enumerating Subdomains")
        
        enumeration_results = enum_domains(
            domains=self.root_domains,
            timeout=self.config['dns_timeout'],
            verbose=self.verbose,
            use_external_tools=not self.args.skip_tools,
            virustotal_api_key=self.config['virustotal_api_key'],
            sublister_path=self.config['sublister_path'],
            amass_path=self.config['amass_path'],
            subfinder_path=self.config['subfinder_path']
        )
        
        # Store results and build all_domains list
        self.results['enumeration'] = enumeration_results
        
        for domain, subdomains in enumeration_results.items():
            self.all_domains.extend(subdomains)
            self.print_info(f"{domain}: Found {len(subdomains)} subdomains")
        
        self.all_domains = list(set(self.all_domains))  # Remove duplicates
        self.print_success(f"\n✓ Total unique domains to analyze: {len(self.all_domains)}")
    
    def analyze_dns(self):
        """Analyze DNS records for all domains."""
        self.print_header("Analyzing DNS Email Security Records")
        
        dns_results = get_dns_records(
            domains=self.all_domains,
            timeout=self.config['dns_timeout'],
            verbose=self.verbose,
            dkim_selectors=self.config['dkim_selectors']
        )
        
        self.results['dns_analysis'] = dns_results
        self.results['all_analyzed_domains'] = self.all_domains
        
        # Count domains with email capability
        email_domains = sum(1 for d in dns_results.values() if d.get('has_email'))
        self.print_success(f"\n✓ Analyzed {len(self.all_domains)} domains")
        self.print_info(f"  {email_domains} domains have email capability")
    
    def detect_providers(self):
        """Detect email providers and misconfigurations."""
        self.print_header("Detecting Email Providers & Misconfigurations")
        
        provider_results = detect_email_providers(
            dns_results_dict=self.results['dns_analysis'],
            verbose=self.verbose
        )
        
        self.results['provider_detection'] = provider_results
        
        # Count providers and issues
        providers_found = set()
        total_misconfigs = 0
        critical_count = 0
        high_count = 0
        
        for domain_results in provider_results.values():
            providers_found.update(domain_results['providers']['providers'])
            misconfigs = domain_results['misconfigurations']
            total_misconfigs += len(misconfigs)
            
            for misc in misconfigs:
                if misc['severity'] == 'critical':
                    critical_count += 1
                elif misc['severity'] == 'high':
                    high_count += 1
        
        self.print_success(f"\n✓ Detected {len(providers_found)} email providers")
        self.print_info(f"  Found {total_misconfigs} security issues")
        
        if critical_count > 0:
            self.print_error(f"  {critical_count} CRITICAL issues")
        if high_count > 0:
            self.print_warning(f"  {high_count} HIGH severity issues")
    
    def generate_reports(self):
        """Generate output reports."""
        self.print_header("Generating Reports")
        
        # Create output directory
        output_dir = self.args.output
        os.makedirs(output_dir, exist_ok=True)
        
        report_files = generate_report(
            analysis_results=self.results,
            output_dir=output_dir,
            verbose=self.verbose
        )
        
        self.print_success(f"\n✓ Reports generated:")
        self.print_info(f"  Markdown: {report_files['markdown']}")
        self.print_info(f"  JSON: {report_files['json']}")
        
        # Generate Excel export if requested
        if self.args.export_excel:
            from excel_exporter import export_to_excel
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            excel_file = os.path.join(output_dir, f"analysis_{timestamp}.xlsx")
            export_to_excel(self.results, excel_file, verbose=self.verbose)
            self.print_info(f"  Excel: {excel_file}")
        
        # Generate CSV export if requested
        if self.args.export_csv:
            from excel_exporter import export_to_csv
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            csv_dir = os.path.join(output_dir, f"csv_{timestamp}")
            export_to_csv(self.results, csv_dir, verbose=self.verbose)
            self.print_info(f"  CSV: {csv_dir}")
    
    def print_summary(self):
        """Print analysis summary."""
        self.print_header("Analysis Summary")
        
        print(f"\n{Fore.CYAN}Root Domains:{Style.RESET_ALL} {len(self.root_domains)}")
        print(f"{Fore.CYAN}Total Domains Analyzed:{Style.RESET_ALL} {len(self.all_domains)}")
        
        # Count email domains
        email_count = sum(
            1 for d in self.results['dns_analysis'].values()
            if d.get('has_email')
        )
        print(f"{Fore.CYAN}Domains with Email:{Style.RESET_ALL} {email_count}")
        
        # Count security records
        spf_count = sum(
            1 for d in self.results['dns_analysis'].values()
            if d.get('spf', {}).get('valid')
        )
        dmarc_count = sum(
            1 for d in self.results['dns_analysis'].values()
            if d.get('dmarc', {}).get('valid')
        )
        dkim_count = sum(
            1 for d in self.results['dns_analysis'].values()
            if d.get('dkim', {}).get('selectors_found')
        )
        
        print(f"\n{Fore.CYAN}Security Records:{Style.RESET_ALL}")
        print(f"  SPF Records: {spf_count}/{email_count}")
        print(f"  DMARC Records: {dmarc_count}/{email_count}")
        print(f"  DKIM Configured: {dkim_count}/{email_count}")
        
        # Count misconfigurations by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for domain_results in self.results['provider_detection'].values():
            for misc in domain_results.get('misconfigurations', []):
                severity_counts[misc['severity']] += 1
        
        print(f"\n{Fore.CYAN}Security Issues:{Style.RESET_ALL}")
        if severity_counts['critical'] > 0:
            print(f"  {Fore.RED}Critical: {severity_counts['critical']}{Style.RESET_ALL}")
        if severity_counts['high'] > 0:
            print(f"  {Fore.LIGHTRED_EX}High: {severity_counts['high']}{Style.RESET_ALL}")
        if severity_counts['medium'] > 0:
            print(f"  {Fore.YELLOW}Medium: {severity_counts['medium']}{Style.RESET_ALL}")
        if severity_counts['low'] > 0:
            print(f"  {Fore.LIGHTBLACK_EX}Low: {severity_counts['low']}{Style.RESET_ALL}")
        
        if sum(severity_counts.values()) == 0:
            print(f"  {Fore.GREEN}No issues found ✓{Style.RESET_ALL}")
    
    # Helper methods for formatted output
    def print_banner(self):
        """Print application banner."""
        banner = f"""
{Fore.CYAN}{'='*70}
   ___                _ _     _   _   _             _     
  | __|_ __  __ _ ___| |   /_\\ | |_| |_ __ _ __  _| |__  
  | _/ '_/ \\ '_ \\ / -_) |  / _ \\|  _|  _/ _` / _|| / / / 
  |___\\___|_| .__/\\___|_|_/_/ \\_\\|_\\__\\__|\\__,_\\___|_\\_\\_\\
  / _| / _\\__ _ _|_|__ ___  __| ___ /_\\ _ _  __ _ | |_  _ _____ _ _  
 |  _|| (_/ _` / __/ -_) | _/  (_-</ _ \\ ' \\/ _` || | || |_ / -_) '_|
 |_|   \\_,_,___\\__\\___|_(_|___/__/_/ \\_\\_||_\\__,_||_|\\_, /__\\___|_|  
                                                     |__/            
{'='*70}{Style.RESET_ALL}
{Fore.LIGHTBLACK_EX}Email Attack Surface Analysis Tool v1.0{Style.RESET_ALL}
"""
        print(banner)
    
    def print_header(self, text):
        """Print section header."""
        print(f"\n{Fore.YELLOW}[{datetime.now().strftime('%H:%M:%S')}] {text}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'-' * (len(text) + 12)}{Style.RESET_ALL}")
    
    def print_info(self, text):
        """Print info message."""
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {text}")
    
    def print_success(self, text):
        """Print success message."""
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {text}")
    
    def print_warning(self, text):
        """Print warning message."""
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {text}")
    
    def print_error(self, text):
        """Print error message."""
        print(f"{Fore.RED}[✗]{Style.RESET_ALL} {text}")
    
    def print_item(self, text):
        """Print list item."""
        print(f"  • {text}")


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Email Attack Surface Analyzer - Analyze email security for your domains',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com
  python main.py example.com example.org example.net
  python main.py -f domains.txt
  python main.py example.com --no-enum -v
  python main.py example.com -o ./my-reports --timeout 10
        """
    )
    
    parser.add_argument(
        'domains',
        nargs='*',
        help='One or more root domains to analyze'
    )
    
    parser.add_argument(
        '-f', '--file',
        type=str,
        help='Read domains from a file (one per line)'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        default='./reports',
        help='Output directory for reports (default: ./reports)'
    )
    
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=5,
        help='DNS query timeout in seconds (default: 5)'
    )
    
    parser.add_argument(
        '--no-enum',
        action='store_true',
        help='Skip subdomain enumeration, only analyze root domains'
    )
    
    parser.add_argument(
        '--skip-tools',
        action='store_true',
        help='Skip external tools (Sublist3r, Amass, Subfinder)'
    )
    
    parser.add_argument(
        '--export-excel',
        action='store_true',
        help='Export results to Excel format (.xlsx)'
    )
    
    parser.add_argument(
        '--export-csv',
        action='store_true',
        help='Export results to CSV format'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.domains and not args.file:
        parser.error('Please specify domains or use -f to read from file')
    
    return args


def main():
    """Main entry point."""
    args = parse_arguments()
    
    analyzer = EmailAttackSurfaceAnalyzer(args)
    exit_code = analyzer.run()
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
