#!/usr/bin/env python3
"""
Quick test of interactive menu imports and basic functionality
"""

import sys
import os

print("Testing interactive menu imports...")

try:
    from main_interactive import InteractiveAnalyzer
    print("✓ InteractiveAnalyzer imported successfully")
    
    from excel_exporter import export_to_excel, export_to_csv
    print("✓ Excel exporter functions imported successfully")
    
    from subdomain_enum import enum_domains
    print("✓ enum_domains imported successfully")
    
    from dns_analyzer import get_dns_records
    print("✓ get_dns_records imported successfully")
    
    from provider_detector import detect_email_providers
    print("✓ detect_email_providers imported successfully")
    
    from report_generator import generate_report
    print("✓ generate_report imported successfully")
    
    # Test creating analyzer instance
    analyzer = InteractiveAnalyzer()
    print("✓ InteractiveAnalyzer instance created")
    
    # Check configuration loaded
    print(f"✓ Config loaded with {len(analyzer.config)} settings")
    
    # Test banner display
    print("\nTesting banner display:")
    analyzer.print_banner()
    
    print("\n" + "="*70)
    print("✓ All tests passed! Interactive menu is ready to use.")
    print("="*70)
    print("\nTo run the interactive menu, use:")
    print("  python main_interactive.py")
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
