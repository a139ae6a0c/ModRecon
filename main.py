#!/usr/bin/env python3
"""
Network Discovery & Modbus/ICS Scanner
---------------------------------------
1. Prompts for a target IP address or subnet.
2. Detects the active network interface automatically.
3. Runs netdiscover (ARP scan) on the detected interface.
4. Runs a quick Nmap check to see if Modbus (TCP 502) is open.
5. Runs a full Nmap scan targeting common ICS/SCADA/Modbus ports & scripts.
6. Prints a final summary report of all findings.

Requirements:
    - Python 3.8+
    - netdiscover  (apt install netdiscover)
    - nmap         (apt install nmap)
    - Must be run as root / with sudo (ARP scanning requires raw sockets)
"""

import subprocess
import sys
import os
import re
import shutil
import ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional


# ──────────────────────────────────────────────
#  Colour helpers (ANSI)
# ──────────────────────────────────────────────
class Colors:
    HEADER  = "\033[95m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"
    # Fish-specific
    ORANGE  = "\033[38;5;208m"
    GOLD    = "\033[38;5;220m"
    FISH_BODY = "\033[38;5;209m"   # salmon/orange
    FISH_FIN  = "\033[38;5;214m"   # golden fin
    FISH_EYE  = "\033[38;5;15m"    # bright white eye
    FISH_TAIL = "\033[38;5;202m"   # deep orange tail
    WATER     = "\033[38;5;39m"    # blue water / bubbles
    DARK_FIN  = "\033[38;5;166m"   # darker orange accent


def banner():
    R  = Colors.RESET
    B  = Colors.FISH_BODY    # salmon body
    F  = Colors.FISH_FIN     # golden fins/spines
    E  = Colors.FISH_EYE     # bright white eye
    T  = Colors.FISH_TAIL    # deep orange tail
    W  = Colors.WATER        # blue water
    D  = Colors.DARK_FIN     # darker accent lines
    BLD = Colors.BOLD
    CY = Colors.CYAN

    whale = f"""{BLD}
           .
          ":"
        ___:____     |"\/"|
      ,'        `.    \  /
      |  O        \___/  |
    ~^~^~^~^~^~^~^~^~^~^~^~^~

    """
    print(whale)


def stage_header(number: int, title: str):
    width = 54
    print(f"\n{Colors.BLUE}{Colors.BOLD}{'═' * width}")
    print(f"  Stage {number} — {title}")
    print(f"{'═' * width}{Colors.RESET}\n")


def info(msg: str):
    print(f"  {Colors.CYAN}[i]{Colors.RESET} {msg}")


def success(msg: str):
    print(f"  {Colors.GREEN}[✓]{Colors.RESET} {msg}")


def warning(msg: str):
    print(f"  {Colors.YELLOW}[!]{Colors.RESET} {msg}")


def error(msg: str):
    print(f"  {Colors.RED}[✗]{Colors.RESET} {msg}")


def result_line(label: str, value: str):
    print(f"  {Colors.BOLD}{label:.<30}{Colors.RESET} {value}")


# ──────────────────────────────────────────────
#  Data classes for collected results
# ──────────────────────────────────────────────
@dataclass
class DiscoveredHost:
    ip: str
    mac: str
    vendor: str = ""


@dataclass
class PortResult:
    port: int
    proto: str
    state: str
    service: str = ""
    version: str = ""
    scripts: dict = field(default_factory=dict)


@dataclass
class ScanReport:
    target: str = ""
    interface: str = ""
    start_time: str = ""
    end_time: str = ""
    discovered_hosts: list = field(default_factory=list)
    modbus_open: Optional[bool] = None
    modbus_banner: str = ""
    port_results: list = field(default_factory=list)
    nmap_output_file: str = ""


# ──────────────────────────────────────────────
#  Pre-flight checks
# ──────────────────────────────────────────────
def check_root():
    if os.geteuid() != 0:
        error("This script must be run as root (sudo).")
        sys.exit(1)
    success("Running as root.")


def check_tool(name: str):
    if shutil.which(name) is None:
        error(f"'{name}' not found. Install it (e.g. sudo apt install {name}).")
        sys.exit(1)
    success(f"Found '{name}' at {shutil.which(name)}")


# ──────────────────────────────────────────────
#  Network helpers
# ──────────────────────────────────────────────
def get_interface_for_target(target_ip: str) -> str:
    probe_ip = target_ip.split("/")[0]
    try:
        ipaddress.ip_address(probe_ip)
    except ValueError:
        probe_ip = "8.8.8.8"

    try:
        result = subprocess.run(
            ["ip", "route", "get", probe_ip],
            capture_output=True, text=True, timeout=5,
        )
        match = re.search(r"dev\s+(\S+)", result.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        match = re.search(r"dev\s+(\S+)", result.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass

    error("Could not detect a network interface.")
    sys.exit(1)


def get_interface_details(iface: str) -> dict:
    """Return IP and MAC of the given interface."""
    details = {"ip": "unknown", "mac": "unknown"}
    try:
        res = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        m = re.search(r"inet\s+(\S+)", res.stdout)
        if m:
            details["ip"] = m.group(1)
    except Exception:
        pass
    try:
        res = subprocess.run(
            ["ip", "link", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        m = re.search(r"link/ether\s+(\S+)", res.stdout)
        if m:
            details["mac"] = m.group(1)
    except Exception:
        pass
    return details


def validate_target(target: str) -> str:
    target = target.strip()
    try:
        if "/" in target:
            ipaddress.ip_network(target, strict=False)
        else:
            ipaddress.ip_address(target)
        return target
    except ValueError:
        error(f"Invalid IP / subnet: {target}")
        sys.exit(1)


# ──────────────────────────────────────────────
#  Stage 0 — Pre-flight & Environment
# ──────────────────────────────────────────────
def stage0_preflight(report: ScanReport):
    stage_header(0, "Pre-flight Checks & Environment")

    check_root()
    check_tool("netdiscover")
    check_tool("nmap")

    print()
    result_line("Target", report.target)
    result_line("Interface", report.interface)

    details = get_interface_details(report.interface)
    result_line("Interface IP", details["ip"])
    result_line("Interface MAC", details["mac"])
    result_line("Scan started", report.start_time)

    success("Pre-flight checks passed.\n")


# ──────────────────────────────────────────────
#  Stage 1 — ARP Discovery (netdiscover)
# ──────────────────────────────────────────────
def stage1_netdiscover(report: ScanReport):
    stage_header(1, "ARP Discovery (netdiscover)")

    scan_range = report.target if "/" in report.target else f"{report.target}/24"
    info(f"Scanning range : {scan_range}")
    info(f"Interface      : {report.interface}")

    cmd = [
        "netdiscover",
        "-i", report.interface,
        "-r", scan_range,
        "-P",          # parsable (non-interactive) output
        "-c", "3",     # 3 ARP requests per host
    ]
    info(f"Command        : {' '.join(cmd)}\n")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout.strip()

        if output:
            print(f"{Colors.DIM}  {'—' * 50}{Colors.RESET}")
            for line in output.splitlines():
                print(f"  {line}")
                parts = line.split()
                if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    host = DiscoveredHost(
                        ip=parts[0],
                        mac=parts[1] if len(parts) > 1 else "",
                        vendor=" ".join(parts[4:]) if len(parts) > 4 else "",
                    )
                    report.discovered_hosts.append(host)
            print(f"{Colors.DIM}  {'—' * 50}{Colors.RESET}")
        else:
            warning("No hosts discovered via ARP.")

    except subprocess.TimeoutExpired:
        warning("netdiscover timed out (120 s).")
    except Exception as exc:
        error(f"netdiscover error: {exc}")

    print()
    success(f"Discovered {len(report.discovered_hosts)} host(s) via ARP.")

    if report.discovered_hosts:
        print(f"\n  {Colors.BOLD}{'IP':<18} {'MAC':<20} {'Vendor'}{Colors.RESET}")
        print(f"  {'─' * 56}")
        for h in report.discovered_hosts:
            print(f"  {h.ip:<18} {h.mac:<20} {h.vendor}")
    print()


# ──────────────────────────────────────────────
#  Stage 2 — Modbus TCP 502 Open Check
# ──────────────────────────────────────────────
def stage2_modbus_check(report: ScanReport):
    stage_header(2, "Modbus Port Check (TCP 502)")

    scan_target = report.target.split("/")[0] if "/" not in report.target else report.target

    cmd = [
        "nmap",
        "-sS",
        "-Pn",
        "-p", "502",
        "-sV",
        "--script", "modbus-discover",
        "-oX", "-",
        scan_target,
    ]
    info(f"Command : {' '.join(cmd)}\n")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        raw_output = result.stdout

        readable_cmd = [
            "nmap", "-sS", "-Pn", "-p", "502", "-sV",
            "--script", "modbus-discover", scan_target,
        ]
        readable = subprocess.run(
            readable_cmd, capture_output=True, text=True, timeout=60,
        )
        print(f"{Colors.DIM}  {'—' * 50}{Colors.RESET}")
        for line in readable.stdout.strip().splitlines():
            print(f"  {line}")
        print(f"{Colors.DIM}  {'—' * 50}{Colors.RESET}\n")

        try:
            root = ET.fromstring(raw_output)
            for host_el in root.findall(".//host"):
                for port_el in host_el.findall(".//port"):
                    if port_el.get("portid") == "502":
                        state_el = port_el.find("state")
                        state = state_el.get("state", "unknown") if state_el is not None else "unknown"

                        svc_el = port_el.find("service")
                        svc_name = svc_el.get("name", "") if svc_el is not None else ""
                        svc_product = svc_el.get("product", "") if svc_el is not None else ""
                        svc_version = svc_el.get("version", "") if svc_el is not None else ""
                        banner_str = f"{svc_name} {svc_product} {svc_version}".strip()

                        report.modbus_open = (state == "open")
                        report.modbus_banner = banner_str

                        for script_el in port_el.findall(".//script"):
                            sid = script_el.get("id", "")
                            sout = script_el.get("output", "")
                            if sid and sout:
                                report.modbus_banner += f" | {sid}: {sout.strip()}"
        except ET.ParseError:
            warning("Could not parse Nmap XML; falling back to text analysis.")
            report.modbus_open = "502/tcp open" in readable.stdout

    except subprocess.TimeoutExpired:
        warning("Modbus check timed out (60 s).")
        report.modbus_open = None
    except Exception as exc:
        error(f"Modbus check error: {exc}")
        report.modbus_open = None

    # ── Verdict ──
    if report.modbus_open is True:
        print(f"  {Colors.RED}{Colors.BOLD}╔══════════════════════════════════════════╗")
        print(f"  ║  ⚠  MODBUS PORT 502 IS OPEN ⚠           ║")
        print(f"  ║  Target is exposing Modbus/TCP!          ║")
        print(f"  ╚══════════════════════════════════════════╝{Colors.RESET}")
        if report.modbus_banner:
            info(f"Banner / Script output: {report.modbus_banner}")
    elif report.modbus_open is False:
        print(f"  {Colors.GREEN}{Colors.BOLD}╔══════════════════════════════════════════╗")
        print(f"  ║  ✓  MODBUS PORT 502 IS CLOSED/FILTERED  ║")
        print(f"  ╚══════════════════════════════════════════╝{Colors.RESET}")
    else:
        warning("Modbus port status could not be determined.")
    print()


# ──────────────────────────────────────────────
#  Stage 3 — Full ICS / SCADA Nmap Scan
# ──────────────────────────────────────────────
ICS_PORTS = {
    102:   "Siemens S7comm (ISO-TSAP)",
    502:   "Modbus/TCP",
    789:   "Red Lion Crimson v3",
    1911:  "Niagara Fox",
    2404:  "IEC 60870-5-104",
    4840:  "OPC-UA",
    20000: "DNP3",
    44818: "EtherNet/IP (CIP)",
    47808: "BACnet",
}


def stage3_full_scan(report: ScanReport):
    stage_header(3, "Full ICS / SCADA Nmap Scan")

    ports_str = ",".join(str(p) for p in sorted(ICS_PORTS))
    nse_scripts = ",".join([
        "modbus-discover",
        "s7-info",
        "enip-info",
        "bacnet-info",
        "fox-info",
    ])

    info("Target ports:")
    for port, desc in sorted(ICS_PORTS.items()):
        print(f"      {port:>5}/tcp  —  {desc}")
    print()

    outfile = f"nmap_ics_scan_{datetime.now():%Y%m%d_%H%M%S}.txt"
    xml_outfile = outfile.replace(".txt", ".xml")
    report.nmap_output_file = outfile

    cmd = [
        "nmap",
        "-sS",
        "-sV",
        "-Pn",
        "-p", ports_str,
        "--script", nse_scripts,
        "--script-args", "modbus-discover.aggressive=true",
        "-T4",
        "-oN", outfile,
        "-oX", xml_outfile,
        report.target,
    ]

    info(f"Command : {' '.join(cmd)}\n")
    print(f"{Colors.DIM}  {'—' * 50}{Colors.RESET}")

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        for line in iter(proc.stdout.readline, ""):
            stripped = line.rstrip()
            print(f"  {stripped}")
        proc.wait()
        print(f"{Colors.DIM}  {'—' * 50}{Colors.RESET}\n")

        if proc.returncode == 0:
            success(f"Nmap scan complete. Results saved to:")
            info(f"  Normal : {outfile}")
            info(f"  XML    : {xml_outfile}")
        else:
            warning(f"Nmap exited with code {proc.returncode}")

        try:
            tree = ET.parse(xml_outfile)
            root = tree.getroot()
            for host_el in root.findall(".//host"):
                for port_el in host_el.findall(".//port"):
                    portid = int(port_el.get("portid", 0))
                    proto = port_el.get("protocol", "tcp")
                    state_el = port_el.find("state")
                    state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                    svc_el = port_el.find("service")
                    svc_name = svc_el.get("name", "") if svc_el is not None else ""
                    svc_product = svc_el.get("product", "") if svc_el is not None else ""
                    svc_version = svc_el.get("version", "") if svc_el is not None else ""

                    scripts = {}
                    for script_el in port_el.findall(".//script"):
                        sid = script_el.get("id", "")
                        sout = script_el.get("output", "")
                        if sid:
                            scripts[sid] = sout.strip()

                    pr = PortResult(
                        port=portid,
                        proto=proto,
                        state=state,
                        service=f"{svc_name} {svc_product}".strip(),
                        version=svc_version,
                        scripts=scripts,
                    )
                    report.port_results.append(pr)
        except (ET.ParseError, FileNotFoundError):
            warning("Could not parse XML results for summary.")

    except Exception as exc:
        error(f"Nmap error: {exc}")

    print()


# ──────────────────────────────────────────────
#  Stage 4 — Summary Report
# ──────────────────────────────────────────────
def stage4_summary(report: ScanReport):
    report.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    stage_header(4, "Final Summary Report")

    print(f"  {Colors.BOLD}General{Colors.RESET}")
    result_line("Target", report.target)
    result_line("Interface", report.interface)
    result_line("Scan started", report.start_time)
    result_line("Scan finished", report.end_time)
    print()

    # -- ARP hosts --
    print(f"  {Colors.BOLD}ARP Discovery{Colors.RESET}")
    result_line("Hosts found", str(len(report.discovered_hosts)))
    if report.discovered_hosts:
        for h in report.discovered_hosts:
            print(f"      {h.ip:<18} {h.mac:<20} {h.vendor}")
    print()

    # -- Modbus verdict --
    print(f"  {Colors.BOLD}Modbus Check (TCP 502){Colors.RESET}")
    if report.modbus_open is True:
        print(f"      {Colors.RED}{Colors.BOLD}STATUS : OPEN — Modbus is exposed!{Colors.RESET}")
        if report.modbus_banner:
            print(f"      Banner : {report.modbus_banner}")
    elif report.modbus_open is False:
        print(f"      {Colors.GREEN}STATUS : CLOSED / FILTERED{Colors.RESET}")
    else:
        print(f"      {Colors.YELLOW}STATUS : UNKNOWN{Colors.RESET}")
    print()

    # -- Full port table --
    print(f"  {Colors.BOLD}ICS / SCADA Port Results{Colors.RESET}")
    if report.port_results:
        print(f"  {'Port':>7}  {'State':<12} {'Service':<22} {'Version'}")
        print(f"  {'─' * 60}")
        for pr in sorted(report.port_results, key=lambda p: p.port):
            state_color = Colors.RED if pr.state == "open" else Colors.GREEN
            ics_label = ICS_PORTS.get(pr.port, "")
            svc_display = pr.service or ics_label
            print(
                f"  {pr.port:>5}/{pr.proto:<3} "
                f"{state_color}{pr.state:<12}{Colors.RESET} "
                f"{svc_display:<22} {pr.version}"
            )
            for sid, sout in pr.scripts.items():
                for sline in sout.splitlines():
                    print(f"          {Colors.CYAN}↳ {sid}: {sline}{Colors.RESET}")
    else:
        warning("No port results were collected.")
    print()

    # -- Open ports summary --
    open_ports = [pr for pr in report.port_results if pr.state == "open"]
    if open_ports:
        print(f"  {Colors.RED}{Colors.BOLD}⚠  {len(open_ports)} open ICS port(s) detected!{Colors.RESET}")
        for pr in sorted(open_ports, key=lambda p: p.port):
            label = ICS_PORTS.get(pr.port, pr.service)
            print(f"      {Colors.RED}→ {pr.port}/tcp  {label}{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}{Colors.BOLD}✓  No open ICS ports detected.{Colors.RESET}")
    print()

    if report.nmap_output_file:
        info(f"Full Nmap output : {report.nmap_output_file}")
        info(f"Full Nmap XML    : {report.nmap_output_file.replace('.txt', '.xml')}")
    print()


# ──────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────
def main():
    banner()

    report = ScanReport()
    report.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    target = input(
        f"{Colors.BOLD}  [?] Enter target IP or subnet "
        f"(e.g. 192.168.1.10 or 10.0.0.0/24): {Colors.RESET}"
    )
    report.target = validate_target(target)
    report.interface = get_interface_for_target(report.target)

    # --- Run all stages ---
    stage0_preflight(report)
    stage1_netdiscover(report)
    stage2_modbus_check(report)
    stage3_full_scan(report)
    stage4_summary(report)

    print(f"  {Colors.GREEN}{Colors.BOLD}[✓] All stages finished.{Colors.RESET}\n")


if __name__ == "__main__":
    main()