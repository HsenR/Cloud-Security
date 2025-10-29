# src/utils/report_writer.py

import json
import os
from datetime import datetime

def save_reports(report_data, base_name="phase1_report"):
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_file = f"reports/{base_name}_{timestamp}.json"
    txt_file = f"reports/{base_name}_{timestamp}.txt"

    with open(json_file, "w") as f:
        json.dump(report_data, f, indent=2)

    with open(txt_file, "w") as f:
        summary = report_data["summary"]
        f.write("CLOUD SECURITY SCANNER REPORT\n")
        f.write("=" * 50 + "\n")
        f.write(f"Generated: {datetime.now()}\n")
        f.write(f"Resources Scanned: {summary['total_resources']}\n")
        f.write(f"Exposures Found: {summary['total_findings']}\n")
        f.write(f"High Risk: {summary['high_risk_findings']}\n")
        f.write(f"Medium Risk: {summary['medium_risk_findings']}\n")
        f.write(f"Low Risk: {summary['low_risk_findings']}\n")

    return json_file, txt_file
