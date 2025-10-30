#!/usr/bin/env python3
"""
Active scanner module (masscan -> nmap pipeline).
Produces reports/phase2_report_<timestamp>.json and saves raw nmap XML files (nmap_<ip>.xml).
"""

import os
import json
import shlex
import subprocess
from datetime import datetime
from xml.etree import ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

# -----------------------
# Defaults (tweak here or via CLI)
# -----------------------
DEFAULT_MASSCAN_PATH = os.getenv("MASSCAN_PATH", "masscan")
DEFAULT_NMAP_PATH = os.getenv("NMAP_PATH", "nmap")
DEFAULT_MASSCAN_RATE = int(os.getenv("MASSCAN_RATE", "2000"))
DEFAULT_MAX_WORKERS = int(os.getenv("MAX_WORKERS", "6"))
DEFAULT_NMAP_BASE_ARGS = "-sV -Pn --version-intensity 5"
AGGRESSIVE_NMAP_ARGS = "-O --script vuln --script-args=unsafe=1"

WORKDIR = os.getenv("WORKDIR", ".")
REPORTS_DIR = os.path.join(WORKDIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


# -----------------------
# Helpers
# -----------------------
def run_cmd(cmd, cwd=None):
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
    targets: list of IPs (strings). ports: string like "1-65535" or "22,80,443"
    returns: dict mapping ip -> [ports]
    """
    if not targets:
        return {}

    target_arg = " ".join(targets)
    cmd = f"{masscan_path} {target_arg} --ports {ports} --rate {rate} -oJ {out_file}"
    print(f"[masscan] Running: {cmd}")
    ok = run_cmd(cmd)
    if not ok:
        raise RuntimeError("masscan failed")
    # read JSON
    with open(out_file, "r") as fh:
        data = json.load(fh)
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
                       aggressive=False, nmap_path=DEFAULT_NMAP_PATH, out_prefix=None):
    """
    Run nmap on ip with ports in port_list (comma-separated string or list).
    Returns (xml_root, xml_filename).
    """
    if isinstance(port_list, (list, set)):
        port_arg = ",".join(map(str, sorted(list(port_list))))
    else:
        port_arg = str(port_list)

    outfile_base = out_prefix or f"nmap_{ip.replace('.', '_')}"
    xml_file = f"{outfile_base}.xml"

    aggressive_part = AGGRESSIVE_NMAP_ARGS if aggressive else ""
    cmd = f"{nmap_path} -T{nmap_timing} {nmap_extra_args} {aggressive_part} -p {port_arg} -oX {xml_file} {ip}"
    print(f"[nmap] Running: {cmd}")
    ok = run_cmd(cmd)
    if not ok:
        raise RuntimeError(f"nmap failed for {ip}")

    tree = ET.parse(xml_file)
    return tree.getroot(), xml_file


def parse_nmap_host(elem):
    """Parse a <host> element into dict with ip and ports list."""
    host_info = {"ip": None, "ports": []}
    # address element(s)
    for addr in elem.findall("address"):
        if addr is not None and addr.get("addrtype") == "ipv4":
            host_info["ip"] = addr.get("addr")
            break

    ports_elem = elem.find("ports")
    if ports_elem is None:
        return host_info

    for p in ports_elem.findall("port"):
        portid = int(p.get("portid"))
        state_elem = p.find("state")
        state = state_elem.get("state") if state_elem is not None else "unknown"
        svc = p.find("service")
        svc_name = svc.get("name") if svc is not None else ""
        version = ""
        if svc is not None:
            product = svc.get("product") or ""
            ver = svc.get("version") or ""
            ext = svc.get("extrainfo") or ""
            version = " ".join([x for x in (product, ver, ext) if x]).strip()
        host_info["ports"].append({
            "port": portid,
            "state": state,
            "service": svc_name,
            "version": version
        })
    return host_info


# -----------------------
# ActiveScanner class
# -----------------------
class ActiveScanner:
    def __init__(self, targets=None):
        """
        targets: list of IPs (strings). If None, empty -> user must provide via runner.
        """
        self.targets = targets or []
        if not isinstance(self.targets, list):
            raise ValueError("targets must be a list of IP strings")
        print(f"[ActiveScanner] Initialized with targets: {self.targets}")

    def run(self,
            use_masscan=True,
            masscan_rate=DEFAULT_MASSCAN_RATE,
            masscan_ports="1-65535",
            nmap_timing=3,
            nmap_extra_args=DEFAULT_NMAP_BASE_ARGS,
            aggressive=False,
            max_workers=DEFAULT_MAX_WORKERS):
        """
        Orchestrates masscan discovery (optional) then nmap per-host.
        Produces a JSON report in reports/phase2_report_<timestamp>.json
        """
        report = {
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "config": {
                "use_masscan": use_masscan,
                "masscan_rate": masscan_rate,
                "masscan_ports": masscan_ports,
                "nmap_timing": nmap_timing,
                "aggressive": aggressive,
                "max_workers": max_workers
            },
            "hosts": []
        }

        if not self.targets:
            print("[ActiveScanner] No targets provided. Exiting with empty report.")
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            out_file = os.path.join(REPORTS_DIR, f"phase2_report_{ts}.json")
            with open(out_file, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"[ActiveScanner] Empty report written: {out_file}")
            return report

        # Run masscan if requested
        discovered = {}
        if use_masscan:
            try:
                discovered = run_masscan_on_targets(self.targets, ports=masscan_ports, rate=masscan_rate)
                print(f"[masscan] discovered ports for {len(discovered)} hosts")
            except Exception as e:
                print(f"[masscan] error: {e}. Proceeding using only Phase2 input ports (if any).")
                discovered = {}

        # Merge target ports: if masscan found ports use them; otherwise default ports will be scanned by nmap runner via nmap_extra_args + explicit ports below
        ip_to_ports = {}
        for ip in self.targets:
            ports_set = set()
            if ip in discovered:
                ports_set.update(discovered[ip])
            # If masscan returned nothing for this IP, we still need to pick some ports to scan.
            # For Phase2 standalone mode we expect user to provide the candidate ports via nmap_extra_args or pass masscan=False and let nmap scan default set.
            ip_to_ports[ip] = sorted(list(ports_set)) if ports_set else []

        # If no ports were discovered for an IP and ip_to_ports[ip] is empty, we will ask nmap to scan common ports (22,80,443) by default
        default_ports_if_empty = "22,80,443"

        # Run nmap per-host (parallel)
        with ThreadPoolExecutor(max_workers=max_workers) as exe:
            futures = {}
            for ip, ports in ip_to_ports.items():
                port_arg = ports if ports else default_ports_if_empty
                # ensure port_arg is string or list acceptable to run_nmap_on_target
                futures[exe.submit(run_nmap_on_target, ip, port_arg, nmap_timing, nmap_extra_args, aggressive, DEFAULT_NMAP_PATH, f"nmap_{ip.replace('.', '_')}")] = (ip, port_arg)

            for fut in as_completed(futures):
                ip, ports_scanned = futures[fut]
                try:
                    xml_root, xml_file = fut.result()
                    host_entries = []
                    for he in xml_root.findall("host"):
                        parsed = parse_nmap_host(he)
                        if parsed.get("ports"):
                            host_entries.append(parsed)
                    report["hosts"].append({
                        "ip": ip,
                        "ports_scanned": ports_scanned,
                        "nmap_xml": xml_file,
                        "nmap_results": host_entries
                    })
                except Exception as e:
                    print(f"[nmap] failed for {ip}: {e}")
                    report["hosts"].append({
                        "ip": ip,
                        "ports_scanned": ports_scanned,
                        "error": str(e)
                    })

        # Save final report
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        out_file = os.path.join(REPORTS_DIR, f"phase2_report_{ts}.json")
        with open(out_file, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"[ActiveScanner] Phase 2 report written: {out_file}")
        return report
