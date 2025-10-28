#!/usr/bin/env python3
"""
Phase 1 Final - With proper error handling and reporting
"""

import json
import os
from datetime import datetime
from src.scanner import CloudSecurityScanner

def main():
    print("🚀 PHASE 1: CLOUD SECURITY SCANNER")
    print("=" * 50)
    
    # Create reports directory if it doesn't exist
    os.makedirs('reports', exist_ok=True)
    
    try:
        scanner = CloudSecurityScanner(region='us-east-1')
        
        # Build inventory
        scanner.build_inventory()
        
        # Analyze exposures
        scanner.analyze_exposures()
        
        # Generate reports
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # JSON report
        report = scanner.generate_report()
        json_filename = f'reports/phase1_report_{timestamp}.json'
        with open(json_filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Simple text report
        txt_filename = f'reports/phase1_summary_{timestamp}.txt'
        with open(txt_filename, 'w') as f:
            f.write("CLOUD SECURITY SCANNER - PHASE 1 REPORT\n")
            f.write("=" * 50 + "\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write(f"Resources Scanned: {report['summary']['total_resources']}\n")
            f.write(f"Exposures Found: {report['summary']['total_findings']}\n")
            f.write(f"High Risk: {report['summary']['high_risk_findings']}\n")
            f.write(f"Medium Risk: {report['summary']['medium_risk_findings']}\n")
            f.write(f"Low Risk: {report['summary']['low_risk_findings']}\n\n")
            
            if report['findings']:
                f.write("HIGH RISK FINDINGS:\n")
                f.write("-" * 30 + "\n")
                for finding in report['findings']:
                    f.write(f"Resource: {finding['resource_name']} ({finding['resource_id']})\n")
                    f.write(f"Service: {finding['service']} on port {finding['exposed_port']}\n")
                    f.write(f"Exposed to: {finding['cidr_range']}\n")
                    f.write(f"Security Group: {finding['security_group']}\n")
                    f.write("-" * 30 + "\n")
        
        # Print summary to console
        scanner.print_summary()
        
        print(f"\n📊 REPORTS GENERATED:")
        print(f"   📄 JSON: {json_filename}")
        print(f"   📝 Text: {txt_filename}")
        print(f"\n🎉 PHASE 1 COMPLETED SUCCESSFULLY!")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
