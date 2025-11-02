#!/usr/bin/env python3
"""
Single-run Phase 2 runner (masscan + nmap unified).
Run only this file to execute the full active scan pipeline.
"""

import sys
import os
import argparse
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from src.active_scanner import ActiveScanner

def parse_targets(s):
    return [t.strip() for t in s.split(",") if t.strip()]

def main():
    parser = argparse.ArgumentParser(description="Phase2: Unified active scanner (masscan -> nmap)")
    parser.add_argument("--targets", help="Comma-separated target IPs (private IPs ok)", required=True)
    parser.add_argument("--targets-file", help="File with newline IPs", required=False)
    parser.add_argument("--masscan", action="store_true", help="Enable masscan (default enabled)")
    parser.add_argument("--no-masscan", action="store_true", help="Disable masscan")
    parser.add_argument("--masscan-rate", type=int, default=None, help="Masscan rate (packets/sec). Default 1000")
    parser.add_argument("--masscan-ports", default=None, help='Masscan ports (e.g. "22,80,443" or "1-65535")')
    parser.add_argument("--masscan-top-ports", type=int, default=None, help="Masscan --top-ports N (most common N ports)")
    parser.add_argument("--adapter", default=None, help="Optional network adapter name for masscan (e.g., eth0)")
    parser.add_argument("--source-ip", default=None, help="Optional source IP for masscan (auto-detected if not provided)")
    parser.add_argument("--top-ports", type=int, default=None, help="Use nmap --top-ports N (applies to nmap)")
    parser.add_argument("--nmap-timing", type=int, choices=range(0,6), default=3, help="Nmap timing (T0..T5)")
    parser.add_argument("--aggressive", action="store_true", help="Enable aggressive nmap options (OS detection + vuln scripts). Use with caution.")
    parser.add_argument("--max-workers", type=int, default=None, help="Parallel nmap workers")
    args = parser.parse_args()

    # Build targets
    targets = []
    if args.targets_file:
        if not os.path.exists(args.targets_file):
            print(f"Targets file not found: {args.targets_file}")
            sys.exit(1)
        with open(args.targets_file, "r") as fh:
            targets = [line.strip() for line in fh if line.strip()]
    else:
        targets = parse_targets(args.targets)

    if not targets:
        print("No targets provided. Use --targets or --targets-file")
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
        masscan_top_ports=args.masscan_top_ports,
        nmap_timing=args.nmap_timing,
        nmap_extra_args=None,
        nmap_top_ports=args.top_ports,
        aggressive=args.aggressive,
        max_workers=args.max_workers,
        adapter=args.adapter,
        source_ip_override=args.source_ip
    )

if __name__ == "__main__":
    main()
