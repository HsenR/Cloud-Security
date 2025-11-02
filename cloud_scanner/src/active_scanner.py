#!/usr/bin/env python3
"""
Active scanner module (masscan -> nmap) with internal-source-ip support and clean output.
Writes raw outputs to reports/raw/ and final JSON to reports/phase2_report_<ts>.json.
"""

import os
import json
import shlex
import socket
import subprocess
from datetime import datetime
from xml.etree import ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

# Nice console output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except Exception:
    Console = None

console = Console() if Console else None

# -----------------------
# Defaults (tweak here or via env)
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


def short_print(msg, style=None):
    if console:
        console.print(msg, style=style)
    else:
        print(msg)


def run_cmd(cmd, cwd=None, capture_output=False):
    """Run a command, return (ok, stdout)."""
    if console:
        console.log(f"[grey][cmd][/grey] {cmd}")
    else:
        print(f"[cmd] {cmd}")
    try:
        if capture_output:
            out = subprocess.check_output(shlex.split(cmd), cwd=cwd, stderr=subprocess.STDOUT)
            return True, out.decode(errors="ignore")
        subprocess.check_call(shlex.split(cmd), cwd=cwd)
        return True, ""
    except subprocess.CalledProcessError as e:
        return False, getattr(e, "output", str(e))


def detect_source_ip_for_target(target_ip):
    """
    Determine a usable local source IP to reach target_ip.
    Works by creating a UDP socket to target and reading the socket name.
    Returns a single IPv4 address string or None.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        # connect UDP (no packets sent) to target on arbitrary port
        s.connect((target_ip, 9))
        src = s.getsockname()[0]
        s.close()
        return src
    except Exception:
        return None


# -----------------------
# Masscan wrapper (supports --top-ports or --ports and source-ip/adapter)
# -----------------------
def run_masscan_on_targets(targets,
                           ports=None,
                           top_ports=None,
                           rate=DEFAULT_MASSCAN_RATE,
                           masscan_path=DEFAULT_MASSCAN_PATH,
                           source_ip=None,
                           adapter=None):
    """
    Run masscan for given targets.
    - targets: list of IPs (or CIDRs)
    - ports: "22,80" or "1-65535" (mutually exclusive with top_ports)
    - top_ports: integer N -> --top-ports N
    - source_ip: string (important for internal scanning)
    - adapter: interface name (optional)
    Returns: discovered dict {ip: [ports]}
    """
    if not targets:
        return {}

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(RAW_DIR, f"masscan_{ts}.json")

    # build base command
    tgt = " ".join(targets)
    cmd_parts = [masscan_path, tgt]

    if top_ports:
        cmd_parts += ["--top-ports", str(int(top_ports))]
    elif ports:
        cmd_parts += ["--ports", str(ports)]
    else:
        cmd_parts += ["--top-ports", "1000"]  # default: top 1000

    cmd_parts += ["--rate", str(rate), "-oJ", out_file]

    if source_ip:
        cmd_parts += ["--source-ip", source_ip]
    if adapter:
        cmd_parts += ["--adapter", adapter]

    cmd = " ".join(shlex.quote(p) for p in cmd_parts)

    # Run masscan (we capture output into file; suppress huge stdout)
    ok, out = run_cmd(cmd)
    if not ok:
        short_print(f"[masscan] failed to run: {out}", "bold red")
        return {}

    # try parse JSON
    try:
        with open(out_file, "r") as fh:
            content = fh.read().strip()
            if not content:
                short_print(f"[masscan] output file {out_file} empty", "yellow")
                return {}
            data = json.loads(content)
    except Exception as e:
        short_print(f"[masscan] parse error: {e}", "yellow")
        return {}

    discovered = {}
    for entry in data:
        ip = entry.get("ip")
        ports_list = [p.get("port") for p in entry.get("ports", []) if "port" in p]
        if ports_list:
            discovered[ip] = sorted(list(set(discovered.get(ip, []) + ports_list)))
    return discovered


# -----------------------
# Nmap wrapper + parser (supports top-ports)
# -----------------------
def run_nmap_on_target(ip,
                       ports=None,
                       top_ports=None,
                       nmap_timing=3,
                       nmap_extra_args=None,
                       aggressive=False,
                       nmap_path=DEFAULT_NMAP_PATH):
    """
    Run nmap for a target ip.
    - ports: comma string or list (used with -p)
    - top_ports: integer N -> use --top-ports N (no -p)
    Returns: (xml_root, xml_file)
    """
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_base = os.path.join(RAW_DIR, f"nmap_{ip.replace('.', '_')}_{ts}")
    xml_file = f"{out_base}.xml"

    nmap_extra_args = nmap_extra_args or DEFAULT_NMAP_BASE_ARGS
    aggressive_part = AGGRESSIVE_NMAP_ARGS if aggressive else ""

    if top_ports:
        cmd = f"{nmap_path} -T{nmap_timing} {nmap_extra_args} {aggressive_part} --top-ports {int(top_ports)} -oX {xml_file} {ip}"
    else:
        port_arg = ports if ports else "22,80,443"
        if isinstance(port_arg, (list, set)):
            port_arg = ",".join(map(str, sorted(list(port_arg))))
        cmd = f"{nmap_path} -T{nmap_timing} {nmap_extra_args} {aggressive_part} -p {port_arg} -oX {xml_file} {ip}"

    ok, out = run_cmd(cmd)
    if not ok:
        raise RuntimeError(out or "nmap failed")

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
# ActiveScanner orchestrator (single entrypoint)
# -----------------------
class ActiveScanner:
    def __init__(self, targets):
        if not isinstance(targets, list):
            raise ValueError("targets must be a list")
        self.targets = targets

    def run(self,
            use_masscan=True,
            masscan_rate=None,
            masscan_ports=None,
            masscan_top_ports=None,
            nmap_timing=3,
            nmap_extra_args=None,
            nmap_top_ports=None,
            aggressive=False,
            max_workers=None,
            adapter=None,
            source_ip_override=None):
        """
        Runs masscan then nmap and writes consolidated JSON report.
        - source_ip_override: if set, use as source-ip for masscan; otherwise auto-detect per-target.
        - adapter: optional interface to bind to masscan.
        """
        stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        report = {
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "config": {
                "use_masscan": use_masscan,
                "masscan_rate": masscan_rate or DEFAULT_MASSCAN_RATE,
                "masscan_ports": masscan_ports,
                "masscan_top_ports": masscan_top_ports,
                "nmap_timing": nmap_timing,
                "nmap_top_ports": nmap_top_ports,
                "aggressive": aggressive,
                "max_workers": max_workers or DEFAULT_MAX_WORKERS,
                "adapter": adapter,
                "source_ip_override": source_ip_override
            },
            "hosts": []
        }

        short_print(Panel(f"🚀 Phase 2 Active Scan — {len(self.targets)} targets", style="bold green")) if console else print(f"Phase2: {len(self.targets)} targets")

        # Run per-target masscan (we auto-detect source-ip per-target if not provided)
        discovered_total = {}
        if use_masscan:
            for t in self.targets:
                src_ip = source_ip_override or detect_source_ip_for_target(t)
                if not src_ip:
                    short_print(f"⚠️ Could not detect source IP for target {t}. Masscan may fail. Proceeding.", "yellow")
                else:
                    short_print(f"🔁 Running masscan for {t} (source-ip: {src_ip})", "cyan")
                try:
                    discovered = run_masscan_on_targets([t],
                                                       ports=masscan_ports,
                                                       top_ports=masscan_top_ports,
                                                       rate=masscan_rate or DEFAULT_MASSCAN_RATE,
                                                       masscan_path=DEFAULT_MASSCAN_PATH,
                                                       source_ip=src_ip,
                                                       adapter=adapter)
                    if discovered:
                        discovered_total.update(discovered)
                        short_print(f"✅ masscan discovered {len(discovered.get(t,[]))} ports on {t}", "green")
                    else:
                        short_print(f"ℹ️ masscan discovered 0 ports on {t}", "yellow")
                except Exception as e:
                    short_print(f"⚠️ masscan error for {t}: {e}", "red")

        # Prepare nmap port lists: prefer discovered ports; empty list will mean fallback to top-ports or default ports
        ip_portmap = {}
        for ip in self.targets:
            if ip in discovered_total and discovered_total[ip]:
                ip_portmap[ip] = discovered_total[ip]
            else:
                ip_portmap[ip] = []  # empty -> fallback

        # Run nmap per-host in parallel
        max_workers = max_workers or DEFAULT_MAX_WORKERS
        short_print(f"🔎 Running nmap (T{nmap_timing}) on {len(ip_portmap)} hosts (workers={max_workers})", "cyan")
        with ThreadPoolExecutor(max_workers=max_workers) as exe:
            futures = {}
            for ip, ports in ip_portmap.items():
                if nmap_top_ports:
                    # pass top-ports to nmap
                    futures[exe.submit(run_nmap_on_target, ip, None, nmap_top_ports, nmap_timing, nmap_extra_args, aggressive, DEFAULT_NMAP_PATH)] = (ip, f"top-{nmap_top_ports}")
                else:
                    port_arg = ports if ports else "22,80,443"
                    futures[exe.submit(run_nmap_on_target, ip, port_arg, None, nmap_timing, nmap_extra_args, aggressive, DEFAULT_NMAP_PATH)] = (ip, port_arg)

            for fut in as_completed(futures):
                ip, ports_scanned = futures[fut]
                try:
                    xmlroot, xmlfile = fut.result()
                    host_entries = []
                    for he in xmlroot.findall("host"):
                        parsed = parse_nmap_host(he)
                        if parsed.get("ports"):
                            host_entries.append(parsed)
                    report["hosts"].append({"ip": ip, "ports_scanned": ports_scanned, "nmap_xml": xmlfile, "nmap_results": host_entries})
                    short_print(f"✅ nmap finished {ip}", "green")
                except Exception as e:
                    short_print(f"❌ nmap failed for {ip}: {e}", "red")
                    report["hosts"].append({"ip": ip, "ports_scanned": ports_scanned, "error": str(e)})

        # Save final report
        out_file = os.path.join(REPORTS_DIR, f"phase2_report_{stamp}.json")
        with open(out_file, "w") as fh:
            json.dump(report, fh, indent=2)

        # Clean concise summary
        if console:
            table = Table(title="Phase 2 Summary", show_lines=False)
            table.add_column("IP", style="cyan")
            table.add_column("Open Ports", style="magenta")
            table.add_column("Services / Version", style="green")

            for host in report["hosts"]:
                open_ports = []
                svc_lines = []
                for he in host.get("nmap_results", []):
                    for p in he.get("ports", []):
                        if p["state"] == "open":
                            open_ports.append(str(p["port"]))
                            svc_lines.append(f"{p['port']}/{p.get('service','')} {p.get('version','')}".strip())
                table.add_row(host["ip"], ", ".join(sorted(open_ports)) if open_ports else "-", "\n".join(svc_lines) if svc_lines else "-")
            console.print(table)
            console.print(Panel(f"Report saved: {out_file}", style="bold blue"))
        else:
            print("=== Phase 2 Summary ===")
            for host in report["hosts"]:
                open_ports = []
                for he in host.get("nmap_results", []):
                    for p in he.get("ports", []):
                        if p["state"] == "open":
                            open_ports.append(p["port"])
                print(f" - {host['ip']}: open ports -> {sorted(open_ports)}")
            print(f"Report saved: {out_file}")

        return report
