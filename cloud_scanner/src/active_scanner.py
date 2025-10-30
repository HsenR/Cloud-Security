#!/usr/bin/env python3
"""
Active scanner: masscan -> nmap pipeline with configurable nmap timing and aggressive options.
Produces reports/phase2_verified_<timestamp>.json and stores raw nmap XML files (nmap_<ip>.xml).
"""

import os
import sys
import json
import shlex
import subprocess
from datetime import datetime
from xml.etree import ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

# -----------------------
# Default configuration
# -----------------------
# You can override these with env vars or via CLI args in the runner.
DEFAULT_MASSCAN_RATE = int(os.getenv("MASSCAN_RATE", "2000"))  # packets/sec
DEFAULT_MASSCAN_PATH = os.getenv("MASSCAN_PATH", "masscan")
DEFAULT_NMAP_PATH = os.getenv("NMAP_PATH", "nmap")
DEFAULT_MAX_WORKERS = int(os.getenv("MAX_WORKERS", "6"))
# default nmap base args, -Pn avoids host discovery (useful for cloud)
DEFAULT_NMAP_BASE_ARGS = "-sV -Pn --version-intensity 5"
# extra aggressive args appended when --aggressive is used (use with caution)
AGGRESSIVE_NMAP_ARGS = "-O --script vuln --script-args=unsafe=1"

WORKDIR = os.getenv("WORKDIR", ".")
REPORTS_DIR = os.path.join(WORKDIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# -----------------------
# Helpers
# -----------------------
def find_latest_phase1_report(reports_dir=REPORTS_DIR):
    files = [f for f in os.listdir(reports_dir) if f.startswith("phase1_report")]
    if not files:
        raise FileNotFoundError("No phase1_report_*.json found in reports/")
    files.sort()
    return os.path.join(reports_dir, files[-1])

def run_subprocess(cmd, cwd=None):
    print(f"[cmd] {cmd}")
    try:
        subprocess.check_call(shlex.split(cmd), cwd=cwd)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[error] Command failed: {e}")
        return False

# -----------------------
# Masscan wrapper
# -----------------------
def run_masscan_on_targets(targets, ports="1-65535", rate=DEFAULT_MASSCAN_RATE,
                           masscan_path=DEFAULT_MASSCAN_PATH, out_file="masscan_temp.json"):
    """
    targets: list of IP addresses
    ports: string like "1-65535" or "22,80,443"
    rate: packets per second
    """
    # masscan wants targets space-separated or a file; we pass space separated
    target_arg = " ".join(targets)
    cmd = f"{masscan_path} {target_arg} --ports {ports} --rate {rate} -oJ {out_file}"
    print(f"[masscan] Running: {cmd}")
    ok = run_subprocess(cmd)
    if not ok:
        raise RuntimeError("masscan failed or was killed")
    with open(out_file, "r") as fh:
        data = json.load(fh)
    # masscan JSON schema: list of {"ip":"x.x.x.x","ports":[{"port": 22, ...},...]}
    discovered = {}
    for entry in data:
        ip = entry.get("ip")
        ports_list = [p.get("port") for p in entry.get("ports", []) if "port" in p]
        if ports_list:
            discovered[ip] = sorted(list(set(discovered.get(ip, []) + ports_list)))
    return discovered

# -----------------------
# Nmap wrapper + parser
# -----------------------
def run_nmap_on_target(ip, port_list, nmap_timing=3, nmap_extra_args=DEFAULT_NMAP_BASE_ARGS,
                       nmap_path=DEFAULT_NMAP_PATH, out_prefix=None, aggressive=False):
    """
    Run nmap on ip with ports in port_list (comma-separated string), timing template (0-5),
    and optional aggressive args.
    Returns parsed XML root element (ElementTree root).
    """
    if isinstance(port_list, (list, set)):
        port_arg = ",".join(map(str, sorted(list(port_list))))
    else:
        port_arg = port_list

    outfile_base = out_prefix or f"nmap_{ip.replace('.', '_')}"
    xml_file = f"{outfile_base}.xml"

    aggressive_part = AGGRESSIVE_NMAP_ARGS if aggressive else ""
    cmd = f"{nmap_path} -T{nmap_timing} {nmap_extra_args} {aggressive_part} -p {port_arg} -oX {xml_file} {ip}"
    print(f"[nmap] Running: {cmd}")
    ok = run_subprocess(cmd)
    if not ok:
        raise RuntimeError(f"nmap failed for {ip}")

    # parse xml
    tree = ET.parse(xml_file)
    return tree.getroot(), xml_file

def parse_nmap_xml_host(host_elem):
    host_info = {"ip": None, "ports": []}
    # address
    for addr in host_elem.findall('address'):
        if addr is not None and addr.get('addrtype') == 'ipv4':
            host_info["ip"] = addr.get('addr')
            break

    ports_elem = host_elem.find('ports')
    if ports_elem is None:
        return host_info

    for port in ports_elem.findall('port'):
        portid = int(port.get('portid'))
        state_elem = port.find('state')
        state = state_elem.get('state') if state_elem is not None else "unknown"
        service_elem = port.find('service')
        service_name = service_elem.get('name') if service_elem is not None else ""
        version = ""
        if service_elem is not None:
            product = service_elem.get('product') or ""
            ver = service_elem.get('version') or ""
            extrainfo = service_elem.get('extrainfo') or ""
            version = " ".join([v for v in [product, ver, extrainfo] if v]).strip()
        host_info["ports"].append({
            "port": portid,
            "state": state,
            "service": service_name,
            "version": version
        })
    return host_info

# -----------------------
# Active scanner class
# -----------------------
class ActiveScanner:
    def __init__(self, phase1_report_path=None):
        self.phase1_report_path = phase1_report_path or find_latest_phase1_report()
        print(f"[ActiveScanner] Using Phase1 report: {self.phase1_report_path}")
        with open(self.phase1_report_path, "r") as fh:
            self.phase1 = json.load(fh)
        self.targets = self._extract_targets()

    def _extract_targets(self):
        targets = {}
        for f in self.phase1.get("findings", []):
            ip = f.get("public_ip")
            port = f.get("exposed_port")
            if not ip or not port:
                continue
            targets.setdefault(ip, set()).add(int(port))
        return {k: sorted(list(v)) for k, v in targets.items()}

    def run(self,
            use_masscan=True,
            masscan_rate=DEFAULT_MASSCAN_RATE,
            masscan_ports="1-65535",
            nmap_timing=3,
            nmap_extra_args=DEFAULT_NMAP_BASE_ARGS,
            aggressive=False,
            max_workers=DEFAULT_MAX_WORKERS):
        results = {"scanned_at": datetime.utcnow().isoformat() + "Z", "hosts": []}
        if not self.targets:
            print("[ActiveScanner] No public targets with ports discovered in Phase1 report.")
            return results

        ips = list(self.targets.keys())
        print(f"[ActiveScanner] Targets from Phase1: {ips}")

        discovered = {}
        if use_masscan:
            print("[ActiveScanner] Running masscan for fast port discovery. This can be noisy.")
            try:
                discovered = run_masscan_on_targets(ips, ports=masscan_ports, rate=masscan_rate)
                print(f"[masscan] discovered ports for {len(discovered)} hosts")
            except Exception as e:
                print(f"[masscan] failed: {e}. Proceeding with nmap using Phase1 ports only.")
                discovered = {}

        # merge phase1 ports + discovered ports
        ip_portmap = {}
        for ip, phase_ports in self.targets.items():
            portset = set(phase_ports)
            if ip in discovered:
                portset.update(discovered[ip])
            ip_portmap[ip] = sorted(list(portset))

        # run nmap in parallel per-ip
        with ThreadPoolExecutor(max_workers=max_workers) as exe:
            futures = {}
            for ip, ports in ip_portmap.items():
                if not ports:
                    continue
                port_arg = ",".join(map(str, ports))
                futures[exe.submit(run_nmap_on_target, ip, port_arg,
                                   nmap_timing, nmap_extra_args, DEFAULT_NMAP_PATH, f"nmap_{ip.replace('.', '_')}", aggressive)] = (ip, ports)

            for fut in as_completed(futures):
                ip, ports = futures[fut]
                try:
                    xml_root, xml_file = fut.result()
                    host_entries = []
                    for he in xml_root.findall('host'):
                        parsed = parse_nmap_xml_host(he)
                        if parsed.get("ports"):
                            host_entries.append(parsed)
                    results["hosts"].append({
                        "ip": ip,
                        "ports_scanned": ports,
                        "nmap_xml": xml_file,
                        "nmap_results": host_entries
                    })
                except Exception as e:
                    print(f"[nmap] failed for {ip}: {e}")

        # save results
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        out_file = os.path.join(REPORTS_DIR, f"phase2_verified_{ts}.json")
        with open(out_file, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"[ActiveScanner] Results saved to: {out_file}")
        return results
