import json
from src.scanner import CloudSecurityScanner

def main():
    # Initialize scanner
    scanner = CloudSecurityScanner(
        region='eu-north-1',
        vpc_id=None  # Set to specific VPC ID if desired
    )
    
    # Build inventory
    scanner.build_inventory()
    
    # Analyze for exposures
    scanner.analyze_exposures()
    
    # Generate reports
    scanner.print_summary()
    
    # Save detailed report to file - ONLY CHANGE THIS LINE:
    report = scanner.generate_report()
    with open('reports/phase1_report.json', 'w') as f:  # Changed to reports/ folder
        json.dump(report, f, indent=2)
    
    print(f"\n✅ Detailed report saved to 'reports/phase1_report.json'")

if __name__ == "__main__":
    main()