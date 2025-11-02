#!/usr/bin/env python3
"""
Active scanner module (masscan -> nmap pipeline) with support for --top-ports.
Saves raw outputs and writes a compact JSON report to reports/phase2_report_<ts>.json.
"""

import os
import json
import shlex
import subprocess
from datetime import datetime
from xml.etree import ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

# -----------------------
# Defaults (tweak here or via CLI/env)
# -----------------------
DEFAULT_MASSCAN_PATH = os.getenv("MASSCAN_PATH", "masscan")
DEFAULT_NMAP_PATH = os.getenv("NMAP_PATH", "nmap")
DEFAULT_MASSCAN_RATE = int(os.getenv("MASSCAN_RATE", "1000"))
DEFAULT_MAX_WORKERS = int(os.getenv("MAX_WORKERS", "4"))
DEFAULT_NMAP_BASE_ARGS = "-sV -Pn --version-intensity 5"
AGGRESSIVE_NMAP_ARGS = "-O --script vuln --script-args=unsafe=1"

WORKDIR = os.getenv("WORKDIR", ".")
REPORTS_DIR = os.path.join(WORKDIR, "reports")
RAW_DIR = os.path.join(REPORTS_DIR, "raw")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(RAW_DIR, exist_ok=True)


def run_cmd(cmd, cwd=None):
    """Run a shell command (shlex.split) and print a short status line."""
    print(f"[cmd] {cmd}")
    try:
        subprocess.check_call(shlex.split(cmd), cwd=cwd)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[error] Command failed: {e}")
        return False


# -----------------------
# Masscan wrapper (supports --top-ports)
# -----------------------
def run_masscan_on_targets(targets, ports=None, top_ports=None, rate=DEFAULT_MASSCAN_RATE,
                           masscan_path=DEFAULT_MASSCAN_PATH, out_file=None):
    """
    Run masscan.
      - targets: list of IP strings
      - ports: string like "22,80,443" or "1-65535" (mutually exclusive with top_ports)
      - top_ports: integer N to use masscan --top-ports N (if provided)
    Returns: dict ip -> [ports]
    """
    if not targets:
        return {}

    out_file = out_file or os.path.join(RAW_DIR, f"masscan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")
    target_arg = " ".join(targets)

    # build command: prefer top_ports if provided
    if top_ports:
        port_part = f"--top-ports {int(top_ports)}"
    elif ports:
        port_part = f"--ports {ports}"
    else:
        # default to top-ports 1000 for speed/signal
        port_part = f"--top-ports 1000"

    cmd = f"{masscan_path} {target_arg} {port_part} --rate {rate} -oJ {out_file}"
    print(f"[masscan] Running (may require sudo or capabilities): {cmd}")
    ok = run_cmd(cmd)
    if not ok:
        print("[masscan] failed to run -> returning empty discovery set")
        return {}

    # read JSON safely
    try:
        with open(out_file, "r") as fh:
            text = fh.read().strip()
            if not text:
                print(f"[masscan] output file {out_file} is empty")
                return {}
            data = json.loads(text)
    except Exception as e:
        print(f"[masscan] could not parse output JSON: {e}")
        return {}

    discovered = {}
    for entry in data:
        ip = entry.get("ip")
        ports_list = [p.get("port") for p in entry.get("ports", []) if "port" in p]
        if ports_list:
            discovered[ip] = sorted(list(set(discovered.get(ip, []) + ports_list)))
    return discovered


# -----------------------
# Nmap wrapper + parser (supports --top-ports)
# -----------------------
def run_nmap_on_target(ip, ports=None, top_ports=None, nmap_timing=3, nmap_extra_args=None,
                       aggressive=False, nmap_path=DEFAULT_NMAP_PATH, out_prefix=None):
    """
    Run nmap for an IP.
      - ports: comma-separated list or string like "22,80,443"
      - top_ports: integer N -> use '--top-ports N' and don't pass -p
    Returns: (xml_root, xml_filename)
    """
    outfile_base = out_prefix or os.path.join(RAW_DIR, f"nmap_{ip.replace('.', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}")
    xml_file = f"{outfile_base}.xml"

    nmap_extra_args = nmap_extra_args or DEFAULT_NMAP_BASE_ARGS
    aggressive_part = AGGRESSIVE_NMAP_ARGS if aggressive else ""

    if top_ports:
        # use --top-ports N instead of -p
        cmd = f"{nmap_path} -T{nmap_timing} {nmap_extra_args} {aggressive_part} --top-ports {int(top_ports)} -oX {xml_file} {ip}"
    else:
        # must have ports
        port_arg = ports if ports else "22,80,443"
        cmd = f"{nmap_path} -T{nmap_timing} {nmap_extra_args} {aggressive_part} -p {port_arg} -oX {xml_file} {ip}"

    print(f"[nmap] Running: {cmd}")
    ok = run_cmd(cmd)
    if not ok:
        raise RuntimeError(f"nmap failed for {ip}")

    tree = ET.parse(xml_file)
    return tree.getroot(), xml_file


def parse_nmap_host(elem):
    host = {"ip": None, "ports": []}
    for addr in elem.findall("address"):
        if addr is not None and addr.get("addrtype") == "ipv4":
            host["ip"] = addr.get("addr")
            break
    ports_elem = elem.find("ports")
    if ports_elem is None:
        return host
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
            version = " ".join([v for v in (product, ver, ext) if v]).strip()
        host["ports"].append({"port": portid, "state": state, "service": svc_name, "version": version})
    return host


# -----------------------
# ActiveScanner class
# -----------------------
class ActiveScanner:
    def __init__(self, targets=None):
        self.targets = targets or []
        if not isinstance(self.targets, list):
            raise ValueError("targets must be a list of IP strings")
        print(f"[ActiveScanner] targets: {self.targets}")

    def run(self,
            use_masscan=True,
            masscan_rate=None,
            masscan_ports=None,
            masscan_top_ports=None,
            nmap_timing=3,
            nmap_extra_args=None,
            nmap_top_ports=None,
            aggressive=False,
            max_workers=None):
        """
        Orchestrates masscan discovery (optional) then nmap per-host.
        - masscan_top_ports & nmap_top_ports: integer to use --top-ports N for respective tools.
        - masscan_ports: explicit port list/range (ignored if masscan_top_ports provided).
        - nmap_extra_args: string of extra nmap args (if None, default used).
        """
        report = {"scanned_at": datetime.utcnow().isoformat() + "Z",
                  "config": {"use_masscan": use_masscan,
                             "masscan_rate": masscan_rate or DEFAULT_MASSCAN_RATE,
                             "masscan_ports": masscan_ports,
                             "masscan_top_ports": masscan_top_ports,
                             "nmap_timing": nmap_timing,
                             "nmap_top_ports": nmap_top_ports,
                             "aggressive": aggressive,
                             "max_workers": max_workers or DEFAULT_MAX_WORKERS},
                  "hosts": []}

        if not self.targets:
            print("[ActiveScanner] no targets provided -> writing empty report")
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            out = os.path.join(REPORTS_DIR, f"phase2_report_{ts}.json")
            with open(out, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"[ActiveScanner] empty report: {out}")
            return report

        # MASSCAN (optional)
        discovered = {}
        if use_masscan:
            discovered = run_masscan_on_targets(self.targets,
                                               ports=masscan_ports,
                                               top_ports=masscan_top_ports,
                                               rate=masscan_rate or DEFAULT_MASSCAN_RATE)
            print(f"[masscan] discovered ports for {len(discovered)} hosts")

        # prepare per-ip port sets
        ip_portmap = {}
        for ip in self.targets:
            if ip in discovered and discovered[ip]:
                ip_portmap[ip] = discovered[ip]
            else:
                ip_portmap[ip] = []  # empty means fallback to nmap_top_ports or default ports

        # NMAP: run per-host (parallel)
        max_workers = max_workers or DEFAULT_MAX_WORKERS
        print(f"[ActiveScanner] running nmap -T{nmap_timing}, top_ports={nmap_top_ports}, aggressive={aggressive}, workers={max_workers}")
        with ThreadPoolExecutor(max_workers=max_workers) as exe:
            futures = {}
            for ip, ports in ip_portmap.items():
                # determine what to tell nmap: prefer nmap_top_ports if provided, else use discovered ports or fallback default ports
                if nmap_top_ports:
                    # pass top-ports to nmap; ports arg is ignored
                    futures[exe.submit(run_nmap_on_target, ip, None, nmap_top_ports, nmap_timing, nmap_extra_args, aggressive, DEFAULT_NMAP_PATH, None)] = (ip, f"top-{nmap_top_ports}")
                else:
                    port_arg = ",".join(map(str, ports)) if ports else "22,80,443"
                    futures[exe.submit(run_nmap_on_target, ip, port_arg, None, nmap_timing, nmap_extra_args, aggressive, DEFAULT_NMAP_PATH, None)] = (ip, port_arg)

            for fut in as_completed(futures):
                ip, ports_scanned = futures[fut]
                try:
                    xml_root, xml_file = fut.result()
                    host_entries = []
                    for he in xml_root.findall("host"):
                        parsed = parse_nmap_host(he)
                        if parsed.get("ports"):
                            host_entries.append(parsed)
                    report["hosts"].append({"ip": ip, "ports_scanned": ports_scanned, "nmap_xml": xml_file, "nmap_results": host_entries})
                except Exception as e:
                    print(f"[nmap] failed for {ip}: {e}")
                    report["hosts"].append({"ip": ip, "ports_scanned": ports_scanned, "error": str(e)})

        # Save final report
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        out_file = os.path.join(REPORTS_DIR, f"phase2_report_{ts}.json")
        with open(out_file, "w") as fh:
            json.dump(report, fh, indent=2)

        # concise summary
        print("\n=== Phase 2 Summary ===")
        print(f"Targets scanned: {len(report['hosts'])}")
        for h in report["hosts"]:
            if "nmap_results" in h and h["nmap_results"]:
                open_ports = []
                for he in h["nmap_results"]:
                    for p in he["ports"]:
                        if p["state"] == "open":
                            open_ports.append(p["port"])
                print(f" - {h['ip']}: open ports -> {sorted(open_ports)}")
            else:
                print(f" - {h['ip']}: no open ports found (or error)")
        print("========================\n")
        print(f"[ActiveScanner] report: {out_file}")
        return report
