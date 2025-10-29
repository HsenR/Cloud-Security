# scripts/run_phase1.py

from src.scanner import CloudSecurityScanner
from src.utils.report_writer import save_reports
from src.utils import config

def main():
    print("🚀 Starting Phase 1 Scan")
    scanner = CloudSecurityScanner(region=config.AWS_REGION, vpc_id=config.VPC_ID)
    
    scanner.build_inventory()
    scanner.analyze_exposures()

    report = scanner.generate_report()
    json_file, txt_file = save_reports(report, base_name="phase1_report")

    scanner.print_summary()
    print(f"\n📄 Reports saved:\n  JSON → {json_file}\n  TXT → {txt_file}")

if __name__ == "__main__":
    main()
