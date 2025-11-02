#!/usr/bin/env python3
"""
Runner for Phase 2 active scanning.

Examples:
  # Use top 1000 ports for both masscan and nmap (internal scan)
  python3 scripts/run_phase2.py --targets 10.0.1.74 --top-ports 1000 --nmap-timing 4 --aggressive

  # Use nmap top ports 500, but custom masscan ports
  python3 scripts/run_phase2.py --targets 10.0.1.74 --top-ports 500 --masscan-ports "22,80,443" --nmap-timing 3

  # Skip masscan and just use nmap default ports (22,80,443)
  python3 scripts/run_phase2.py --targets 10.0.1.74 --no-masscan --nmap-timing 3
"""

import sys
import os
import argparse
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from src.active_scanner import ActiveScanner

def parse_targets(s):
    return [t.strip() for t in s.split(",") if t.strip()]

def main():
    parser = argparse.ArgumentParser(description="Phase2 active scanner")
    parser.add_argument("--targets", help="Comma-separated IPs (private IPs ok)", required=False)
    parser.add_argument("--targets-file", help="File with newline IPs", required=False)
    parser.add_argument("--masscan", action="store_true", help="Enable masscan (default ON)")
    parser.add_argument("--no-masscan", action="store_true", help="Disable masscan")
    parser.add_argument("--masscan-rate", type=int, default=None, help="Masscan rate (packets/sec)")
    parser.add_argument("--masscan-ports", default=None, help='Masscan ports string, e.g. "22,80,443" or "1-65535"')
    parser.add_argument("--top-ports", type=int, default=None, help="Scan top N ports (applies to both masscan and nmap if provided)")
    parser.add_argument("--nmap-timing", type=int, choices=range(0,6), default=3, help="Nmap timing template (0-5). Default 3.")
    parser.add_argument("--aggressive", action="store_true", help="Enable aggressive nmap options (OS detect + vuln scripts). Use with caution.")
    parser.add_argument("--max-workers", type=int, default=None, help="Parallel nmap workers")
    args = parser.parse_args()

    # build targets list
    targets = []
    if args.targets_file:
        if not os.path.exists(args.targets_file):
            print(f"Targets file not found: {args.targets_file}")
            sys.exit(1)
        with open(args.targets_file, "r") as fh:
            targets = [line.strip() for line in fh if line.strip()]
    elif args.targets:
        targets = parse_targets(args.targets)
    else:
        print("No targets provided. Use --targets or --targets-file.")
        parser.print_help()
        sys.exit(1)

    # masscan decision
    if args.no_masscan:
        use_masscan = False
    else:
        use_masscan = True if args.masscan or not args.no_masscan else False

    scanner = ActiveScanner(targets=targets)
    scanner.run(
        use_masscan=use_masscan,
        masscan_rate=args.masscan_rate,
        masscan_ports=args.masscan_ports,
        masscan_top_ports=args.top_ports,
        nmap_timing=args.nmap_timing,
        nmap_extra_args=None,
        nmap_top_ports=args.top_ports,
        aggressive=args.aggressive,
        max_workers=args.max_workers
    )

if __name__ == "__main__":
    main()
