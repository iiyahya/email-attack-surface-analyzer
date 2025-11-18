#!/usr/bin/env python3
"""
Email Attack Surface Analyzer - Interactive Mode

Interactive menu-driven interface for the email attack surface analyzer.
Provides enterprise-level UI with configuration management and multiple export options.

Usage:
    python main_interactive.py
"""

import os
import sys
import json
from datetime import datetime
from typing import List, Dict
from dotenv import load_dotenv
from colorama import init, Fore, Style, Back

# Import our modules
from subdomain_enum import enum_domains
from dns_analyzer import get_dns_records
from provider_detector import detect_email_providers
from report_generator import generate_report
from excel_exporter import export_to_excel, export_to_csv

# Initialize colorama
init(autoreset=True)


class InteractiveAnalyzer:
    """Interactive menu system for email attack surface analysis."""
    
    def __init__(self):
        """Initialize the interactive analyzer."""
        load_dotenv()
        
        self.config = {
            'virustotal_api_key': os.getenv('VIRUSTOTAL_API_KEY'),
            'sublister_path': os.getenv('SUBLISTER_PATH'),
            'amass_path': os.getenv('AMASS_PATH', 'amass'),
            'subfinder_path': os.getenv('SUBFINDER_PATH', 'subfinder'),
            'dns_timeout': int(os.getenv('DNS_TIMEOUT', '5')),
            'dkim_selectors': os.getenv('DKIM_SELECTORS', 
                'default,google,k1,k2,k3,selector1,selector2,dkim,mail,email,mx').split(',')
        }
        
        self.domains = []
        self.last_results = None
        self.verbose = False
        self.enable_subdomain_enum = True
        self.use_external_tools = True
    
    def run(self):
        """Run the interactive menu system."""
        while True:
            self.display_main_menu()
            choice = input(f"\n{Fore.CYAN}Enter your choice: {Style.RESET_ALL}").strip()
            
            if choice == '1':
                self.configure_scan()
            elif choice == '2':
                self.load_domains()
            elif choice == '3':
                self.configure_settings()
            elif choice == '4':
                self.run_analysis()
            elif choice == '5':
                self.export_results()
            elif choice == '6':
                self.view_last_results()
            elif choice == '7':
                self.display_help()
            elif choice == '8' or choice.lower() == 'q':
                print(f"\n{Fore.GREEN}Thank you for using Email Attack Surface Analyzer!{Style.RESET_ALL}\n")
                break
            else:
                print(f"\n{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")
                input("Press Enter to continue...")
    
    def display_main_menu(self):
        """Display the main menu."""
        self.clear_screen()
        self.print_banner()
        
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"  MAIN MENU")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        print(f"  {Fore.YELLOW}1.{Style.RESET_ALL} Quick Scan (Enter domains and scan)")
        print(f"  {Fore.YELLOW}2.{Style.RESET_ALL} Load Domains from File")
        print(f"  {Fore.YELLOW}3.{Style.RESET_ALL} Configure Settings")
        print(f"  {Fore.YELLOW}4.{Style.RESET_ALL} Run Full Analysis")
        print(f"  {Fore.YELLOW}5.{Style.RESET_ALL} Export Results")
        print(f"  {Fore.YELLOW}6.{Style.RESET_ALL} View Last Results Summary")
        print(f"  {Fore.YELLOW}7.{Style.RESET_ALL} Help & Documentation")
        print(f"  {Fore.YELLOW}8.{Style.RESET_ALL} Exit (Q)")
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        
        # Display current status
        print(f"\n{Fore.LIGHTBLACK_EX}Status:{Style.RESET_ALL}")
        print(f"  Domains loaded: {Fore.GREEN if self.domains else Fore.RED}{len(self.domains)}{Style.RESET_ALL}")
        print(f"  Subdomain enum: {Fore.GREEN if self.enable_subdomain_enum else Fore.RED}{'Enabled' if self.enable_subdomain_enum else 'Disabled'}{Style.RESET_ALL}")
        print(f"  External tools: {Fore.GREEN if self.use_external_tools else Fore.RED}{'Enabled' if self.use_external_tools else 'Disabled'}{Style.RESET_ALL}")
        print(f"  Verbose mode: {Fore.GREEN if self.verbose else Fore.RED}{'On' if self.verbose else 'Off'}{Style.RESET_ALL}")
    
    def print_banner(self):
        """Print application banner."""
        banner = f"""{Fore.CYAN}
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║     ███████╗███╗   ███╗ █████╗ ██╗██╗         █████╗ ███╗   ██╗    ║
║     ██╔════╝████╗ ████║██╔══██╗██║██║        ██╔══██╗████╗  ██║    ║
║     █████╗  ██╔████╔██║███████║██║██║        ███████║██╔██╗ ██║    ║
║     ██╔══╝  ██║╚██╔╝██║██╔══██║██║██║        ██╔══██║██║╚██╗██║    ║
║     ███████╗██║ ╚═╝ ██║██║  ██║██║███████╗   ██║  ██║██║ ╚████║    ║
║     ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝   ╚═╝  ╚═╝╚═╝  ╚═══╝    ║
║                                                                      ║
║              Attack Surface Analyzer - Enterprise Edition           ║
║                         Version 2.0                                  ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
        print(banner)
    
    def configure_scan(self):
        """Quick scan configuration and execution."""
        self.clear_screen()
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"  QUICK SCAN")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        print("Enter domains to scan (one per line, empty line to finish):")
        domains = []
        while True:
            domain = input(f"{Fore.GREEN}>{Style.RESET_ALL} ").strip()
            if not domain:
                break
            domains.append(domain)
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Added: {domain}")
        
        if not domains:
            print(f"\n{Fore.RED}No domains entered.{Style.RESET_ALL}")
            input("Press Enter to continue...")
            return
        
        self.domains = domains
        print(f"\n{Fore.GREEN}✓ {len(domains)} domain(s) loaded{Style.RESET_ALL}")
        
        # Ask if they want to run now
        run_now = input(f"\n{Fore.CYAN}Run analysis now? (Y/n): {Style.RESET_ALL}").strip().lower()
        if run_now != 'n':
            self.run_analysis()
    
    def load_domains(self):
        """Load domains from a file."""
        self.clear_screen()
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"  LOAD DOMAINS FROM FILE")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        file_path = input(f"{Fore.CYAN}Enter file path: {Style.RESET_ALL}").strip()
        
        if not os.path.exists(file_path):
            print(f"\n{Fore.RED}✗ File not found: {file_path}{Style.RESET_ALL}")
            input("Press Enter to continue...")
            return
        
        try:
            with open(file_path, 'r') as f:
                domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            self.domains = domains
            print(f"\n{Fore.GREEN}✓ Loaded {len(domains)} domain(s){Style.RESET_ALL}")
            
            # Display loaded domains
            print(f"\n{Fore.CYAN}Loaded domains:{Style.RESET_ALL}")
            for domain in domains[:10]:
                print(f"  • {domain}")
            if len(domains) > 10:
                print(f"  ... and {len(domains) - 10} more")
            
        except Exception as e:
            print(f"\n{Fore.RED}✗ Error reading file: {e}{Style.RESET_ALL}")
        
        input("\nPress Enter to continue...")
    
    def configure_settings(self):
        """Configure analysis settings."""
        while True:
            self.clear_screen()
            print(f"\n{Fore.CYAN}{'='*70}")
            print(f"  SETTINGS CONFIGURATION")
            print(f"{'='*70}{Style.RESET_ALL}\n")
            
            print(f"  {Fore.YELLOW}1.{Style.RESET_ALL} Toggle Subdomain Enumeration (Currently: {Fore.GREEN if self.enable_subdomain_enum else Fore.RED}{'Enabled' if self.enable_subdomain_enum else 'Disabled'}{Style.RESET_ALL})")
            print(f"  {Fore.YELLOW}2.{Style.RESET_ALL} Toggle External Tools (Currently: {Fore.GREEN if self.use_external_tools else Fore.RED}{'Enabled' if self.use_external_tools else 'Disabled'}{Style.RESET_ALL})")
            print(f"  {Fore.YELLOW}3.{Style.RESET_ALL} Toggle Verbose Mode (Currently: {Fore.GREEN if self.verbose else Fore.RED}{'On' if self.verbose else 'Off'}{Style.RESET_ALL})")
            print(f"  {Fore.YELLOW}4.{Style.RESET_ALL} Set DNS Timeout (Currently: {self.config['dns_timeout']}s)")
            print(f"  {Fore.YELLOW}5.{Style.RESET_ALL} Configure API Keys")
            print(f"  {Fore.YELLOW}6.{Style.RESET_ALL} Configure Tool Paths")
            print(f"  {Fore.YELLOW}7.{Style.RESET_ALL} Back to Main Menu")
            
            choice = input(f"\n{Fore.CYAN}Enter your choice: {Style.RESET_ALL}").strip()
            
            if choice == '1':
                self.enable_subdomain_enum = not self.enable_subdomain_enum
            elif choice == '2':
                self.use_external_tools = not self.use_external_tools
            elif choice == '3':
                self.verbose = not self.verbose
            elif choice == '4':
                timeout = input(f"{Fore.CYAN}Enter DNS timeout in seconds: {Style.RESET_ALL}").strip()
                try:
                    self.config['dns_timeout'] = int(timeout)
                    print(f"{Fore.GREEN}✓ Timeout set to {timeout}s{Style.RESET_ALL}")
                except ValueError:
                    print(f"{Fore.RED}✗ Invalid value{Style.RESET_ALL}")
                input("Press Enter to continue...")
            elif choice == '5':
                self.configure_api_keys()
            elif choice == '6':
                self.configure_tool_paths()
            elif choice == '7':
                break
    
    def configure_api_keys(self):
        """Configure API keys."""
        self.clear_screen()
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"  API KEYS CONFIGURATION")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        print(f"Current VirusTotal API Key: {Fore.GREEN if self.config['virustotal_api_key'] else Fore.RED}{'Set' if self.config['virustotal_api_key'] else 'Not Set'}{Style.RESET_ALL}")
        
        change = input(f"\n{Fore.CYAN}Enter new VirusTotal API key (or press Enter to skip): {Style.RESET_ALL}").strip()
        if change:
            self.config['virustotal_api_key'] = change
            print(f"{Fore.GREEN}✓ API key updated{Style.RESET_ALL}")
        
        input("\nPress Enter to continue...")
    
    def configure_tool_paths(self):
        """Configure external tool paths."""
        self.clear_screen()
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"  EXTERNAL TOOLS CONFIGURATION")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        tools = [
            ('Sublist3r', 'sublister_path'),
            ('Amass', 'amass_path'),
            ('Subfinder', 'subfinder_path')
        ]
        
        for tool_name, config_key in tools:
            current = self.config[config_key]
            print(f"\n{tool_name} Path: {Fore.CYAN}{current or 'Not Set'}{Style.RESET_ALL}")
            new_path = input(f"Enter new path (or press Enter to skip): ").strip()
            if new_path:
                self.config[config_key] = new_path
                print(f"{Fore.GREEN}✓ Path updated{Style.RESET_ALL}")
        
        input("\nPress Enter to continue...")
    
    def run_analysis(self):
        """Run the full analysis."""
        if not self.domains:
            print(f"\n{Fore.RED}✗ No domains loaded. Please add domains first.{Style.RESET_ALL}")
            input("Press Enter to continue...")
            return
        
        self.clear_screen()
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"  RUNNING ANALYSIS")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}[1/4]{Style.RESET_ALL} Starting analysis for {len(self.domains)} domain(s)...")
        
        try:
            # Step 1: Enumerate subdomains
            if self.enable_subdomain_enum:
                print(f"\n{Fore.GREEN}[2/4]{Style.RESET_ALL} Enumerating subdomains...")
                enumeration = enum_domains(
                    domains=self.domains,
                    timeout=self.config['dns_timeout'],
                    verbose=self.verbose,
                    use_external_tools=self.use_external_tools,
                    virustotal_api_key=self.config['virustotal_api_key'],
                    sublister_path=self.config['sublister_path'],
                    amass_path=self.config['amass_path'],
                    subfinder_path=self.config['subfinder_path']
                )
                
                all_domains = []
                for domain_list in enumeration.values():
                    all_domains.extend(domain_list)
                all_domains = list(set(all_domains))
                
                print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Found {len(all_domains)} unique domains")
            else:
                enumeration = {d: [d] for d in self.domains}
                all_domains = self.domains.copy()
                print(f"\n{Fore.YELLOW}[2/4]{Style.RESET_ALL} Subdomain enumeration skipped")
            
            # Step 2: Analyze DNS records
            print(f"\n{Fore.GREEN}[3/4]{Style.RESET_ALL} Analyzing DNS records...")
            dns_results = get_dns_records(
                domains=all_domains,
                timeout=self.config['dns_timeout'],
                verbose=self.verbose,
                dkim_selectors=self.config['dkim_selectors']
            )
            
            email_domains = sum(1 for d in dns_results.values() if d.get('has_email'))
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Analyzed {len(all_domains)} domains ({email_domains} with email)")
            
            # Step 3: Detect providers and issues
            print(f"\n{Fore.GREEN}[4/4]{Style.RESET_ALL} Detecting providers and security issues...")
            provider_results = detect_email_providers(
                dns_results_dict=dns_results,
                verbose=self.verbose
            )
            
            # Count issues
            total_issues = sum(len(d.get('misconfigurations', [])) for d in provider_results.values())
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Found {total_issues} security issues")
            
            # Store results
            self.last_results = {
                'timestamp': datetime.now().isoformat(),
                'root_domains': self.domains,
                'enumeration': enumeration,
                'all_analyzed_domains': all_domains,
                'dns_analysis': dns_results,
                'provider_detection': provider_results
            }
            
            print(f"\n{Fore.GREEN}✓ Analysis complete!{Style.RESET_ALL}")
            
            # Ask about export
            export = input(f"\n{Fore.CYAN}Export results now? (Y/n): {Style.RESET_ALL}").strip().lower()
            if export != 'n':
                self.export_results()
            else:
                input("\nPress Enter to continue...")
            
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}✗ Analysis interrupted by user{Style.RESET_ALL}")
            input("Press Enter to continue...")
        except Exception as e:
            print(f"\n{Fore.RED}✗ Analysis failed: {e}{Style.RESET_ALL}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            input("Press Enter to continue...")
    
    def export_results(self):
        """Export analysis results."""
        if not self.last_results:
            print(f"\n{Fore.RED}✗ No analysis results available. Please run an analysis first.{Style.RESET_ALL}")
            input("Press Enter to continue...")
            return
        
        self.clear_screen()
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"  EXPORT RESULTS")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        print(f"  {Fore.YELLOW}1.{Style.RESET_ALL} Export to Markdown (.md)")
        print(f"  {Fore.YELLOW}2.{Style.RESET_ALL} Export to JSON (.json)")
        print(f"  {Fore.YELLOW}3.{Style.RESET_ALL} Export to Excel (.xlsx)")
        print(f"  {Fore.YELLOW}4.{Style.RESET_ALL} Export to CSV (.csv)")
        print(f"  {Fore.YELLOW}5.{Style.RESET_ALL} Export All Formats")
        print(f"  {Fore.YELLOW}6.{Style.RESET_ALL} Back to Main Menu")
        
        choice = input(f"\n{Fore.CYAN}Enter your choice: {Style.RESET_ALL}").strip()
        
        if choice == '6':
            return
        
        # Get output directory
        output_dir = input(f"{Fore.CYAN}Enter output directory (default: ./reports): {Style.RESET_ALL}").strip()
        if not output_dir:
            output_dir = './reports'
        
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            if choice == '1' or choice == '5':
                # Markdown
                from report_generator import ReportGenerator
                generator = ReportGenerator(verbose=True)
                md_file = os.path.join(output_dir, f"report_{timestamp}.md")
                generator.generate_markdown_report(self.last_results, md_file)
                print(f"{Fore.GREEN}✓ Markdown report saved: {md_file}{Style.RESET_ALL}")
            
            if choice == '2' or choice == '5':
                # JSON
                from report_generator import ReportGenerator
                generator = ReportGenerator(verbose=True)
                json_file = os.path.join(output_dir, f"results_{timestamp}.json")
                generator.generate_json_report(self.last_results, json_file)
                print(f"{Fore.GREEN}✓ JSON report saved: {json_file}{Style.RESET_ALL}")
            
            if choice == '3' or choice == '5':
                # Excel
                excel_file = os.path.join(output_dir, f"analysis_{timestamp}.xlsx")
                export_to_excel(self.last_results, excel_file, verbose=True)
                print(f"{Fore.GREEN}✓ Excel report saved: {excel_file}{Style.RESET_ALL}")
            
            if choice == '4' or choice == '5':
                # CSV
                csv_dir = os.path.join(output_dir, f"csv_{timestamp}")
                csv_files = export_to_csv(self.last_results, csv_dir, verbose=True)
                print(f"{Fore.GREEN}✓ CSV files saved to: {csv_dir}{Style.RESET_ALL}")
            
            print(f"\n{Fore.GREEN}✓ Export complete!{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"\n{Fore.RED}✗ Export failed: {e}{Style.RESET_ALL}")
            if self.verbose:
                import traceback
                traceback.print_exc()
        
        input("\nPress Enter to continue...")
    
    def view_last_results(self):
        """View summary of last analysis results."""
        if not self.last_results:
            print(f"\n{Fore.RED}✗ No analysis results available.{Style.RESET_ALL}")
            input("Press Enter to continue...")
            return
        
        self.clear_screen()
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"  LAST ANALYSIS SUMMARY")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        results = self.last_results
        
        print(f"Analysis Timestamp: {Fore.CYAN}{results['timestamp']}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Domain Statistics:{Style.RESET_ALL}")
        print(f"  Root Domains: {len(results['root_domains'])}")
        print(f"  Total Domains: {len(results['all_analyzed_domains'])}")
        
        email_count = sum(1 for d in results['dns_analysis'].values() if d.get('has_email'))
        print(f"  With Email: {email_count}")
        
        print(f"\n{Fore.YELLOW}Security Records:{Style.RESET_ALL}")
        spf_count = sum(1 for d in results['dns_analysis'].values() if d.get('spf', {}).get('valid'))
        dmarc_count = sum(1 for d in results['dns_analysis'].values() if d.get('dmarc', {}).get('valid'))
        dkim_count = sum(1 for d in results['dns_analysis'].values() if d.get('dkim', {}).get('selectors_found'))
        
        print(f"  SPF Records: {spf_count}/{email_count}")
        print(f"  DMARC Records: {dmarc_count}/{email_count}")
        print(f"  DKIM Configured: {dkim_count}/{email_count}")
        
        print(f"\n{Fore.YELLOW}Security Issues:{Style.RESET_ALL}")
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for domain_data in results['provider_detection'].values():
            for misc in domain_data.get('misconfigurations', []):
                severity = misc.get('severity', 'low')
                severity_counts[severity] += 1
        
        if severity_counts['critical'] > 0:
            print(f"  {Fore.RED}Critical: {severity_counts['critical']}{Style.RESET_ALL}")
        if severity_counts['high'] > 0:
            print(f"  {Fore.LIGHTRED_EX}High: {severity_counts['high']}{Style.RESET_ALL}")
        if severity_counts['medium'] > 0:
            print(f"  {Fore.YELLOW}Medium: {severity_counts['medium']}{Style.RESET_ALL}")
        if severity_counts['low'] > 0:
            print(f"  {Fore.GREEN}Low: {severity_counts['low']}{Style.RESET_ALL}")
        
        if sum(severity_counts.values()) == 0:
            print(f"  {Fore.GREEN}No issues found ✓{Style.RESET_ALL}")
        
        input("\nPress Enter to continue...")
    
    def display_help(self):
        """Display help and documentation."""
        self.clear_screen()
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"  HELP & DOCUMENTATION")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        help_text = """
{yellow}Quick Start:{reset}
  1. Select option 1 to do a quick scan
  2. Enter your domains (one per line)
  3. Analysis will run automatically
  4. Export results in your preferred format

{yellow}Features:{reset}
  • Multiple subdomain enumeration sources (crt.sh, Subfinder, Amass, etc.)
  • Comprehensive DNS security analysis (SPF, DKIM, DMARC, MX)
  • Email provider detection (12+ providers)
  • Security misconfiguration detection
  • Multiple export formats (Markdown, JSON, Excel, CSV)

{yellow}Configuration:{reset}
  • Toggle subdomain enumeration on/off
  • Enable/disable external tools for faster scans
  • Configure API keys for enhanced results
  • Adjust DNS timeout for slow networks

{yellow}Export Formats:{reset}
  • Markdown (.md) - Human-readable reports
  • JSON (.json) - Machine-readable data
  • Excel (.xlsx) - Multi-sheet workbooks
  • CSV (.csv) - Individual data tables

{yellow}External Tools:{reset}
  • Subfinder - Fast subdomain enumeration
  • Amass - Comprehensive subdomain discovery
  • Sublist3r - Additional subdomain sources

{yellow}Documentation:{reset}
  • README.md - User guide
  • SETUP.md - Installation guide
  • API_DOCS.md - Developer reference
  • PROJECT_SUMMARY.md - Feature overview
        """.format(
            yellow=Fore.YELLOW,
            reset=Style.RESET_ALL
        )
        
        print(help_text)
        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
    
    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('clear' if os.name != 'nt' else 'cls')


def main():
    """Main entry point for interactive mode."""
    try:
        analyzer = InteractiveAnalyzer()
        analyzer.run()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Interrupted by user. Exiting...{Style.RESET_ALL}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
