#!/usr/bin/env python3
"""
ModRecon — Advanced ICS/SCADA Network Reconnaissance Tool

Stages:
    0  Pre-flight Checks & Environment
    1  ARP Discovery (netdiscover)
    2  Modbus Port Check (TCP 502)
    3  OS & Service Fingerprinting (nmap -O -sV)
    4  Full ICS/SCADA Nmap Scan (25+ ports)
    5  ICS Vulnerability Scan (nmap vuln scripts)  [--full only]
    6  SNMP Enumeration (UDP 161/162)              [--full only]
    7  TCP Banner Grabbing (raw sockets)           [--full only]
    8  Final Summary Report (risk score, JSON export, CVE table)

Requirements:
    - Python 3.8+
    - netdiscover  (apt install netdiscover)
    - nmap         (apt install nmap)
    - Must be run as root / with sudo (ARP scanning requires raw sockets)

Optional:
    - snmpwalk     (apt install snmp)  — used in Stage 6 if available
"""

import argparse
import json
import socket
import subprocess
import sys
import os
import re
import shutil
import ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime
from dataclasses import dataclass, field, asdict
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
    # Fish/Whale-specific
    ORANGE  = "\033[38;5;208m"
    GOLD    = "\033[38;5;220m"
    WHALE_EYE = "\033[38;5;15m"    # bright white eye
    WATER     = "\033[38;5;39m"    # blue water / waves
    WHALE_BDY = "\033[38;5;33m"    # deep blue whale body
    SPOUT     = "\033[38;5;87m"    # light cyan water spout


def banner():
    R = Colors.RESET
    BLD = Colors.BOLD
    CY = Colors.CYAN

    W = Colors.WATER  # waves
    B = Colors.WHALE_BDY  # whale body
    S = Colors.SPOUT  # water spout
    E = Colors.WHALE_EYE  # eye

    # Note: Backslashes (\) are escaped as \\ in f-strings
    whale = f"""{BLD}
           {S}.{R}
          {S}":"{R}
        {B}___{S}:{B}____{R}     {B}|"\\/"|{R}
      {B},'{R}        {B}`.{R}    {B}\\  /{R}
      {B}|{R}  {E}O{R}        {B}\\___/  |{R}
    {W}~^~^~^~^~^~^~^~^~^~^~^~^~{R}

{CY}{BLD}  ≋≋≋  Modbus / ICS Network Scanner  ≋≋≋{R}
{W}  ≋≋≋  netdiscover  +  nmap  +  modbus  ≋≋≋{R}
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
    os_name: str = ""
    os_accuracy: str = ""
    os_family: str = ""
    port_results: list = field(default_factory=list)
    vulnerabilities: list = field(default_factory=list)
    snmp_results: list = field(default_factory=list)
    banners: dict = field(default_factory=dict)
    risk_level: str = ""
    nmap_output_file: str = ""
    json_report_file: str = ""


@dataclass
class VulnResult:
    port: int
    script_id: str
    output: str
    cve_ids: list = field(default_factory=list)


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


def check_tool_optional(name: str) -> bool:
    """Check for an optional tool; warn but do not exit if missing."""
    if shutil.which(name) is None:
        warning(f"Optional tool '{name}' not found. Some features will be skipped.")
        return False
    success(f"Found '{name}' at {shutil.which(name)}")
    return True


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
    check_tool_optional("snmpwalk")

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
#  Stage 3 — OS & Service Fingerprinting (NEW)
# ──────────────────────────────────────────────
def stage3_os_fingerprint(report: ScanReport):
    stage_header(3, "OS & Service Fingerprinting")

    scan_target = report.target.split("/")[0] if "/" not in report.target else report.target
    xml_outfile = f"nmap_os_scan_{datetime.now():%Y%m%d_%H%M%S}.xml"

    cmd = [
        "nmap",
        "-O",
        "-sV",
        "--version-intensity", "9",
        "-Pn",
        "-oX", xml_outfile,
        scan_target,
    ]
    info(f"Command : {' '.join(cmd)}\n")
    print(f"{Colors.DIM}  {'—' * 50}{Colors.RESET}")

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        for line in iter(proc.stdout.readline, ""):
            print(f"  {line.rstrip()}")
        proc.wait()
        print(f"{Colors.DIM}  {'—' * 50}{Colors.RESET}\n")

        try:
            tree = ET.parse(xml_outfile)
            root = tree.getroot()

            for host_el in root.findall(".//host"):
                # OS detection
                os_el = host_el.find(".//os")
                if os_el is not None:
                    best_match = None
                    best_accuracy = 0
                    for osmatch in os_el.findall("osmatch"):
                        acc = int(osmatch.get("accuracy", "0"))
                        if acc > best_accuracy:
                            best_accuracy = acc
                            best_match = osmatch
                    if best_match is not None:
                        report.os_name = best_match.get("name", "")
                        report.os_accuracy = best_match.get("accuracy", "")
                        osclass = best_match.find("osclass")
                        if osclass is not None:
                            report.os_family = osclass.get("osfamily", "")

                # Service versions on open ports
                print(f"\n  {Colors.BOLD}{'Port':>7}  {'State':<10} {'Service':<20} {'Version'}{Colors.RESET}")
                print(f"  {'─' * 62}")
                for port_el in host_el.findall(".//port"):
                    state_el = port_el.find("state")
                    state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                    svc_el = port_el.find("service")
                    svc_name = svc_el.get("name", "") if svc_el is not None else ""
                    svc_product = svc_el.get("product", "") if svc_el is not None else ""
                    svc_version = svc_el.get("version", "") if svc_el is not None else ""
                    portid = port_el.get("portid", "?")
                    proto = port_el.get("protocol", "tcp")
                    state_color = Colors.RED if state == "open" else Colors.GREEN
                    print(
                        f"  {portid:>5}/{proto:<3} "
                        f"{state_color}{state:<10}{Colors.RESET} "
                        f"{svc_name + ' ' + svc_product:<20} {svc_version}"
                    )

            print()
            if report.os_name:
                success(f"OS detected  : {report.os_name} (accuracy: {report.os_accuracy}%)")
                if report.os_family:
                    info(f"OS family    : {report.os_family}")
            else:
                warning("OS could not be determined.")
        except (ET.ParseError, FileNotFoundError) as exc:
            warning(f"Could not parse OS fingerprint XML: {exc}")

    except Exception as exc:
        error(f"OS fingerprint error: {exc}")

    print()


# ──────────────────────────────────────────────
#  Stage 4 — Full ICS / SCADA Nmap Scan
# ──────────────────────────────────────────────
ICS_PORTS = {
    102:   "Siemens S7comm (ISO-TSAP)",
    502:   "Modbus/TCP",
    789:   "Red Lion Crimson v3",
    1911:  "Niagara Fox",
    1962:  "PCWorx (Phoenix Contact)",
    2222:  "EtherNet/IP (implicit messaging)",
    2404:  "IEC 60870-5-104",
    4000:  "Emerson ROC",
    4840:  "OPC-UA",
    5006:  "Mitsubishi MELSEC-Q",
    5007:  "Mitsubishi MELSEC-Q",
    5094:  "HART-IP",
    9600:  "OMRON FINS",
    11001: "ROS (Robot Operating System)",
    18245: "GE SRTP",
    18246: "GE SRTP",
    20000: "DNP3",
    34962: "Profinet RT",
    34963: "Profinet CM",
    34964: "Profinet",
    44818: "EtherNet/IP (CIP)",
    47808: "BACnet",
    55000: "FL-net",
    55003: "FL-net",
}


def stage4_full_scan(report: ScanReport):
    stage_header(4, "Full ICS / SCADA Nmap Scan")

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
#  Stage 5 — ICS Vulnerability Scan (NEW)
# ──────────────────────────────────────────────
def stage5_vuln_scan(report: ScanReport):
    stage_header(5, "ICS Vulnerability Scan")

    open_ports = [pr for pr in report.port_results if pr.state == "open"]
    if not open_ports:
        warning("No open ports from Stage 4 to scan. Skipping vulnerability scan.")
        print()
        return

    ports_str = ",".join(str(pr.port) for pr in open_ports)
    scan_target = report.target.split("/")[0] if "/" not in report.target else report.target

    vuln_scripts = ",".join([
        "vuln",
        "vulners",
        "ssl-heartbleed",
        "smb-vuln*",
        "http-vuln*",
    ])

    info(f"Scanning open ports: {ports_str}")
    cmd = [
        "nmap",
        "-sV",
        "-Pn",
        "-p", ports_str,
        "--script", vuln_scripts,
        "-oX", "-",
        scan_target,
    ]
    info(f"Command : {' '.join(cmd)}\n")
    print(f"{Colors.DIM}  {'—' * 50}{Colors.RESET}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        for line in result.stdout.splitlines():
            print(f"  {line}")
        print(f"{Colors.DIM}  {'—' * 50}{Colors.RESET}\n")

        try:
            root = ET.fromstring(result.stdout)
            cve_pattern = re.compile(r"CVE-\d{4}-\d+")
            for host_el in root.findall(".//host"):
                for port_el in host_el.findall(".//port"):
                    portid = int(port_el.get("portid", 0))
                    for script_el in port_el.findall(".//script"):
                        sid = script_el.get("id", "")
                        sout = script_el.get("output", "")
                        if sid and sout and sout.strip():
                            cves = cve_pattern.findall(sout)
                            vuln = VulnResult(
                                port=portid,
                                script_id=sid,
                                output=sout.strip(),
                                cve_ids=list(set(cves)),
                            )
                            report.vulnerabilities.append(vuln)
        except ET.ParseError:
            warning("Could not parse vulnerability scan XML output.")

    except subprocess.TimeoutExpired:
        warning("Vulnerability scan timed out (300 s).")
    except Exception as exc:
        error(f"Vulnerability scan error: {exc}")

    if report.vulnerabilities:
        print(f"  {Colors.RED}{Colors.BOLD}Found {len(report.vulnerabilities)} vulnerability finding(s):{Colors.RESET}")
        for v in report.vulnerabilities:
            print(f"    {Colors.YELLOW}[{v.port}/tcp] {v.script_id}{Colors.RESET}")
            for line in v.output.splitlines()[:3]:
                print(f"      {line}")
            if v.cve_ids:
                print(f"      {Colors.RED}CVEs: {', '.join(v.cve_ids)}{Colors.RESET}")
    else:
        success("No vulnerability findings recorded.")
    print()


# ──────────────────────────────────────────────
#  Stage 6 — SNMP Enumeration (NEW)
# ──────────────────────────────────────────────
def stage6_snmp_enum(report: ScanReport):
    stage_header(6, "SNMP Enumeration")

    has_snmpwalk = shutil.which("snmpwalk") is not None
    if not has_snmpwalk:
        warning("snmpwalk not found — using nmap SNMP scripts only.")

    scan_target = report.target.split("/")[0] if "/" not in report.target else report.target

    snmp_scripts = ",".join([
        "snmp-info",
        "snmp-interfaces",
        "snmp-sysdescr",
        "snmp-brute",
    ])

    cmd = [
        "nmap",
        "-sU",
        "-p", "161,162",
        "-sV",
        "--script", snmp_scripts,
        "-oX", "-",
        scan_target,
    ]
    info(f"Command : {' '.join(cmd)}\n")
    print(f"{Colors.DIM}  {'—' * 50}{Colors.RESET}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        for line in result.stdout.splitlines():
            print(f"  {line}")
        print(f"{Colors.DIM}  {'—' * 50}{Colors.RESET}\n")

        try:
            root = ET.fromstring(result.stdout)
            for host_el in root.findall(".//host"):
                for port_el in host_el.findall(".//port"):
                    portid = port_el.get("portid", "?")
                    proto = port_el.get("protocol", "udp")
                    state_el = port_el.find("state")
                    state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                    for script_el in port_el.findall(".//script"):
                        sid = script_el.get("id", "")
                        sout = script_el.get("output", "")
                        if sid and sout and sout.strip():
                            entry = {
                                "port": portid,
                                "proto": proto,
                                "state": state,
                                "script": sid,
                                "output": sout.strip(),
                            }
                            report.snmp_results.append(entry)
        except ET.ParseError:
            warning("Could not parse SNMP scan XML output.")

    except subprocess.TimeoutExpired:
        warning("SNMP scan timed out (120 s).")
    except Exception as exc:
        error(f"SNMP scan error: {exc}")

    if report.snmp_results:
        success(f"SNMP: {len(report.snmp_results)} script result(s) collected.")
        print(f"\n  {Colors.BOLD}{'Script':<25} {'Port':<8} {'Output (truncated)'}{Colors.RESET}")
        print(f"  {'─' * 60}")
        for entry in report.snmp_results:
            short_out = entry["output"].replace("\n", " ")[:60]
            print(f"  {entry['script']:<25} {entry['port']}/{entry['proto']:<5} {short_out}")
    else:
        warning("No SNMP results found (port may be closed or filtered).")
    print()


# ──────────────────────────────────────────────
#  Stage 7 — TCP Banner Grabbing (NEW)
# ──────────────────────────────────────────────
def stage7_banner_grab(report: ScanReport):
    stage_header(7, "TCP Banner Grabbing")

    open_ports = [pr for pr in report.port_results if pr.state == "open"]
    if not open_ports:
        warning("No open ports to grab banners from. Skipping.")
        print()
        return

    scan_target = report.target.split("/")[0] if "/" not in report.target else report.target
    info(f"Attempting banner grab on {len(open_ports)} open port(s)...")
    print(f"\n  {Colors.BOLD}{'Port':<8} {'Banner (first 80 chars)'}{Colors.RESET}")
    print(f"  {'─' * 62}")

    for pr in sorted(open_ports, key=lambda p: p.port):
        banner_text = ""
        try:
            with socket.create_connection((scan_target, pr.port), timeout=5) as s:
                s.sendall(b"\r\n")
                data = s.recv(1024)
                banner_text = data.decode("utf-8", errors="replace").strip()
        except (socket.timeout, ConnectionRefusedError, OSError):
            banner_text = "(no banner)"
        except Exception as exc:
            banner_text = f"(error: {exc})"

        report.banners[pr.port] = banner_text
        short = banner_text.replace("\n", " ").replace("\r", "")[:80]
        color = Colors.CYAN if banner_text != "(no banner)" and not banner_text.startswith("(error") else Colors.DIM
        print(f"  {pr.port:<8} {color}{short}{Colors.RESET}")

    print()
    success(f"Banner grabbing complete. {len(report.banners)} port(s) probed.")
    print()


# ──────────────────────────────────────────────
#  Stage 8 — Final Summary Report (enhanced)
# ──────────────────────────────────────────────
def _compute_risk(report: ScanReport) -> str:
    open_ics = [pr for pr in report.port_results if pr.state == "open" and pr.port in ICS_PORTS]
    has_vulns = len(report.vulnerabilities) > 0

    if report.modbus_open and has_vulns:
        return "CRITICAL"
    if open_ics and has_vulns:
        return "HIGH"
    if open_ics:
        return "MEDIUM"
    return "LOW"


def _risk_color(level: str) -> str:
    return {
        "CRITICAL": Colors.RED,
        "HIGH":     Colors.ORANGE,
        "MEDIUM":   Colors.YELLOW,
        "LOW":      Colors.GREEN,
    }.get(level, Colors.RESET)


def stage8_summary(report: ScanReport):
    report.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report.risk_level = _compute_risk(report)

    stage_header(8, "Final Summary Report")

    print(f"  {Colors.BOLD}General{Colors.RESET}")
    result_line("Target", report.target)
    result_line("Interface", report.interface)
    result_line("Scan started", report.start_time)
    result_line("Scan finished", report.end_time)
    print()

    # -- Risk badge --
    rc = _risk_color(report.risk_level)
    print(f"  {Colors.BOLD}Risk Level{Colors.RESET}")
    print(f"  {rc}{Colors.BOLD}  ╔══════════════════════════╗")
    print(f"  ║  RISK : {report.risk_level:<16}  ║")
    print(f"  ╚══════════════════════════╝{Colors.RESET}")
    print()

    # -- ARP hosts --
    print(f"  {Colors.BOLD}ARP Discovery{Colors.RESET}")
    result_line("Hosts found", str(len(report.discovered_hosts)))
    if report.discovered_hosts:
        for h in report.discovered_hosts:
            print(f"      {h.ip:<18} {h.mac:<20} {h.vendor}")
    print()

    # -- OS detection --
    if report.os_name:
        print(f"  {Colors.BOLD}OS Detection{Colors.RESET}")
        result_line("OS Name", report.os_name)
        result_line("OS Accuracy", f"{report.os_accuracy}%")
        if report.os_family:
            result_line("OS Family", report.os_family)
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

    # -- CVE summary table --
    all_cves = []
    for v in report.vulnerabilities:
        for cve in v.cve_ids:
            all_cves.append((cve, v.port, v.script_id))
    if all_cves:
        print(f"  {Colors.BOLD}CVE Summary{Colors.RESET}")
        print(f"  {Colors.RED}{Colors.BOLD}{'CVE ID':<20} {'Port':<8} {'Script'}{Colors.RESET}")
        print(f"  {'─' * 50}")
        for cve, port, script in sorted(all_cves):
            print(f"  {Colors.RED}{cve:<20}{Colors.RESET} {port:<8} {script}")
        print()

    # -- SNMP summary --
    if report.snmp_results:
        print(f"  {Colors.BOLD}SNMP Results{Colors.RESET}")
        result_line("SNMP findings", str(len(report.snmp_results)))
        print()

    # -- Banner summary --
    if report.banners:
        print(f"  {Colors.BOLD}Banner Grab Summary{Colors.RESET}")
        print(f"  {'Port':<8} {'Banner (truncated)'}")
        print(f"  {'─' * 50}")
        for port in sorted(report.banners):
            short = report.banners[port].replace("\n", " ")[:60]
            print(f"  {port:<8} {short}")
        print()

    # -- Recommendations --
    print(f"  {Colors.BOLD}Hardening Recommendations{Colors.RESET}")
    recs = []
    if report.modbus_open:
        recs.append("Firewall port 502 (Modbus/TCP) — restrict access to trusted hosts only.")
    if any(pr.port == 4840 and pr.state == "open" for pr in report.port_results):
        recs.append("Enable TLS on OPC-UA (port 4840) to prevent plaintext communication.")
    if any(pr.port in (161, 162) for pr in report.port_results if pr.state == "open") or report.snmp_results:
        recs.append("Disable SNMP public community string or upgrade to SNMPv3 with auth/encryption.")
    if any(pr.port == 102 and pr.state == "open" for pr in report.port_results):
        recs.append("Restrict S7comm (port 102) access — Siemens S7 PLCs have no built-in authentication.")
    if any(pr.port == 44818 and pr.state == "open" for pr in report.port_results):
        recs.append("Restrict EtherNet/IP (port 44818) to the OT network segment.")
    if any(pr.port == 47808 and pr.state == "open" for pr in report.port_results):
        recs.append("Restrict BACnet (port 47808) and disable unnecessary BACnet services.")
    if report.vulnerabilities:
        recs.append("Apply vendor patches for all identified CVEs as a priority.")
    if not recs:
        recs.append("No open ICS ports detected. Maintain current network segmentation.")

    for i, rec in enumerate(recs, 1):
        print(f"  {Colors.YELLOW}{i:>2}.{Colors.RESET} {rec}")
    print()

    # -- File output summary --
    if report.nmap_output_file:
        info(f"Full Nmap output : {report.nmap_output_file}")
        info(f"Full Nmap XML    : {report.nmap_output_file.replace('.txt', '.xml')}")

    # -- JSON export --
    json_file = f"modrecon_report_{datetime.now():%Y%m%d_%H%M%S}.json"
    report.json_report_file = json_file
    try:
        report_dict = asdict(report)
        with open(json_file, "w") as fh:
            json.dump(report_dict, fh, indent=2, default=str)
        success(f"JSON report saved: {json_file}")
    except Exception as exc:
        warning(f"Could not write JSON report: {exc}")

    print()


# ──────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="ModRecon — Advanced ICS/SCADA Network Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target", nargs="?", default=None,
        help="Target IP address or subnet (e.g. 192.168.1.10 or 10.0.0.0/24)",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--fast", action="store_true",
        help="Fast mode: skip vulnerability scan (Stage 5), SNMP (Stage 6), and banner grabbing (Stage 7)",
    )
    mode_group.add_argument(
        "--full", action="store_true",
        help="Full mode (default): run all stages including vuln scan, SNMP, and banner grabbing",
    )
    args = parser.parse_args()

    # --fast skips extended stages; default (neither flag) also runs all stages
    run_extended = not args.fast

    banner()

    report = ScanReport()
    report.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if args.target:
        target = args.target
    else:
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
    stage3_os_fingerprint(report)
    stage4_full_scan(report)

    if run_extended:
        stage5_vuln_scan(report)
        stage6_snmp_enum(report)
        stage7_banner_grab(report)

    stage8_summary(report)

    print(f"  {Colors.GREEN}{Colors.BOLD}[✓] All stages finished.{Colors.RESET}\n")


if __name__ == "__main__":
    main()

