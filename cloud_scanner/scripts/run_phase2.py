#!/usr/bin/env python3
"""
Runner for Phase 2 active scanning.
Usage examples:
  python3 scripts/run_phase2.py --masscan --nmap --nmap-timing 4 --aggressive --masscan-rate 1500 --masscan-ports 1-65535
  python3 scripts/run_phase2.py --no-masscan --nmap --nmap-timing 3
"""

import argparse
from src.active_scanner import ActiveScanner

def main():
    parser = argparse.ArgumentParser(description="Phase2 active scanner (masscan + nmap)")
    parser.add_argument("--masscan", action="store_true", help="Enable masscan discovery (default: enabled if not --no-masscan)")
    parser.add_argument("--no-masscan", action="store_true", help="Skip masscan (only nmap on Phase1 ports)")
    parser.add_argument("--masscan-rate", type=int, default=None, help="Masscan rate (packets/sec). Overrides env MASSCAN_RATE")
    parser.add_argument("--masscan-ports", default=None, help='Masscan ports string, e.g. "1-65535" or "22,80,443"')
    parser.add_argument("--nmap", action="store_true", help="Run nmap scans (default: enabled)")
    parser.add_argument("--nmap-timing", type=int, choices=range(0,6), default=3, help="Nmap timing template (0-5). Higher is faster/noisier")
    parser.add_argument("--aggressive", action="store_true", help="Enable aggressive nmap options (OS detection + vuln scripts). Use with caution.")
    parser.add_argument("--max-workers", type=int, default=None, help="Number of parallel nmap workers (default from config)")
    parser.add_argument("--report", help="Path to phase1 report (default: latest in reports/)")
    args = parser.parse_args()

    # decide masscan usage
    use_masscan = args.masscan and not args.no_masscan
    if not args.masscan and not args.no_masscan:
        # default behavior: use masscan
        use_masscan = True

    scanner = ActiveScanner(phase1_report_path=args.report)
    masscan_rate = args.masscan_rate if args.masscan_rate is not None else None
    masscan_ports = args.masscan_ports if args.masscan_ports is not None else None
    max_workers = args.max_workers if args.max_workers is not None else None

    # run with passed overrides (None values allow defaults in ActiveScanner)
    scanner.run(
        use_masscan=use_masscan,
        masscan_rate=masscan_rate or None,
        masscan_ports=masscan_ports or None,
        nmap_timing=args.nmap_timing,
        nmap_extra_args=None,  # uses default inside active_scanner unless you refactor to expose this
        aggressive=args.aggressive,
        max_workers=max_workers or None
    )

if __name__ == "__main__":
    main()
