#!/usr/bin/env python3
"""
Runner for Phase 2 active scanning.

Usage examples:
  # Scan two targets with masscan (default) and nmap timing T3 (default)
  python3 scripts/run_phase2.py --targets 1.2.3.4,5.6.7.8

  # Explicit options: masscan rate, masscan ports, nmap timing, aggressive nmap
  python3 scripts/run_phase2.py --targets 1.2.3.4 --masscan-rate 1500 --masscan-ports "1-65535" --nmap-timing 4 --aggressive

  # Skip masscan (nmap will scan default ports 22,80,443)
  python3 scripts/run_phase2.py --targets 1.2.3.4 --no-masscan --nmap-timing 3
"""

import sys
import os
import argparse

# Ensure src is importable when running script from cloud_scanner/ or repo root
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from src.active_scanner import ActiveScanner

def parse_targets(targets_str):
    if not targets_str:
        return []
    parts = [t.strip() for t in targets_str.split(",") if t.strip()]
    return parts

def main():
    parser = argparse.ArgumentParser(description="Phase2: Active masscan+nmap scanner")
    parser.add_argument("--targets", help="Comma-separated list of target IPs (required if --targets-file not provided)")
    parser.add_argument("--targets-file", help="Path to file with newline-separated IPs")
    parser.add_argument("--masscan", action="store_true", help="Enable masscan (default enabled unless --no-masscan)")
    parser.add_argument("--no-masscan", action="store_true", help="Disable masscan (only nmap)")
    parser.add_argument("--masscan-rate", type=int, default=None, help="Masscan rate (packets/sec). Default from active_scanner config.")
    parser.add_argument("--masscan-ports", default=None, help='Masscan ports string, e.g. "1-65535" or "22,80,443"')
    parser.add_argument("--nmap", action="store_true", help="Run nmap (default enabled)")
    parser.add_argument("--nmap-timing", type=int, choices=range(0,6), default=3, help="Nmap timing template (0-5). Default 3.")
    parser.add_argument("--aggressive", action="store_true", help="Enable aggressive nmap options (OS detect + vuln scripts). Use with caution.")
    parser.add_argument("--max-workers", type=int, default=None, help="Parallel nmap workers")
    args = parser.parse_args()

    # Build targets list
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

    # Decide masscan usage
    if args.no_masscan:
        use_masscan = False
    else:
        # default: use masscan when user asked --masscan or if they didn't mention no-masscan
        use_masscan = True if args.masscan or not args.no_masscan else False

    # Prepare overrides
    masscan_rate = args.masscan_rate if args.masscan_rate is not None else None
    masscan_ports = args.masscan_ports if args.masscan_ports is not None else None
    max_workers = args.max_workers if args.max_workers is not None else None

    # Initialize scanner with targets
    scanner = ActiveScanner(targets=targets)

    # Run
    scanner.run(
        use_masscan=use_masscan,
        masscan_rate=masscan_rate if masscan_rate is not None else None,
        masscan_ports=masscan_ports if masscan_ports is not None else None,
        nmap_timing=args.nmap_timing,
        nmap_extra_args=None,   # use defaults in ActiveScanner
        aggressive=args.aggressive,
        max_workers=max_workers if max_workers is not None else None
    )

if __name__ == "__main__":
    main()
