#!/usr/bin/env python3
"""
Network Vulnerability Scanner & Security Audit Tool
Author: Aldo Pilers
Description: Scans a target host for open ports, identifies running services,
             flags misconfigurations against common security baselines, and
             generates a structured JSON audit report.
"""

import json
import socket
import subprocess
import datetime
import sys
import os

# ── Risky port definitions ────────────────────────────────────────────────────
RISKY_PORTS = {
    21:   {"service": "FTP",        "risk": "HIGH",   "reason": "Transmits credentials in plaintext. Replace with SFTP/SCP."},
    23:   {"service": "Telnet",     "risk": "CRITICAL","reason": "Unencrypted remote access. Replace with SSH (port 22)."},
    25:   {"service": "SMTP",       "risk": "MEDIUM",  "reason": "Open relay may allow spam. Restrict to authenticated users."},
    53:   {"service": "DNS",        "risk": "MEDIUM",  "reason": "Recursive DNS can be abused for amplification attacks."},
    80:   {"service": "HTTP",       "risk": "LOW",     "reason": "Unencrypted web traffic. Enforce HTTPS redirect."},
    110:  {"service": "POP3",       "risk": "HIGH",    "reason": "Plaintext email retrieval. Use POP3S (port 995)."},
    135:  {"service": "MS-RPC",     "risk": "HIGH",    "reason": "Common attack vector. Block externally with firewall."},
    139:  {"service": "NetBIOS",    "risk": "HIGH",    "reason": "Legacy Windows file sharing. Disable if not needed."},
    143:  {"service": "IMAP",       "risk": "HIGH",    "reason": "Plaintext email. Use IMAPS (port 993)."},
    445:  {"service": "SMB",        "risk": "CRITICAL","reason": "EternalBlue/ransomware target. Patch and restrict externally."},
    1433: {"service": "MSSQL",      "risk": "HIGH",    "reason": "Database exposed. Restrict to trusted IPs only."},
    1521: {"service": "Oracle DB",  "risk": "HIGH",    "reason": "Database exposed. Never expose to public internet."},
    3306: {"service": "MySQL",      "risk": "HIGH",    "reason": "Database exposed. Bind to localhost or restrict by IP."},
    3389: {"service": "RDP",        "risk": "CRITICAL","reason": "Remote Desktop exposed. Use VPN + NLA, limit source IPs."},
    5432: {"service": "PostgreSQL", "risk": "HIGH",    "reason": "Database exposed. Restrict with pg_hba.conf rules."},
    5900: {"service": "VNC",        "risk": "HIGH",    "reason": "Remote desktop often lacks strong auth. Use SSH tunnel."},
    6379: {"service": "Redis",      "risk": "CRITICAL","reason": "Often runs with no auth. Bind to localhost only."},
    8080: {"service": "HTTP-Alt",   "risk": "LOW",     "reason": "Common dev server port left open in production."},
    8443: {"service": "HTTPS-Alt",  "risk": "LOW",     "reason": "Alternate HTTPS. Verify certificate is valid."},
    27017:{"service": "MongoDB",    "risk": "CRITICAL","reason": "Often unauthenticated. Bind to localhost and enable auth."},
}

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ── Port scanner (no root required) ──────────────────────────────────────────
def scan_ports(host: str, ports: list[int], timeout: float = 1.0) -> list[dict]:
    """Connect-scan a list of ports. Returns list of open port info dicts."""
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                info = {"port": port, "state": "open"}
                if port in RISKY_PORTS:
                    info.update(RISKY_PORTS[port])
                else:
                    info.update({"service": "Unknown", "risk": "INFO", "reason": "Port is open; verify if expected."})
                open_ports.append(info)
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
    return open_ports


# ── Banner grabbing ───────────────────────────────────────────────────────────
def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to read a service banner from an open port."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(b"\r\n")
            banner = s.recv(256).decode(errors="replace").strip()
            return banner[:120] if banner else ""
    except Exception:
        return ""


# ── Remediation recommendations ───────────────────────────────────────────────
def build_recommendations(findings: list[dict]) -> list[str]:
    recs = []
    seen_risks = {f["risk"] for f in findings}
    if "CRITICAL" in seen_risks or "HIGH" in seen_risks:
        recs.append("Immediately review firewall rules — critical/high-risk services should not be internet-facing.")
    if any(f["port"] in (21, 23, 110, 143) for f in findings):
        recs.append("Replace plaintext protocols (FTP, Telnet, POP3, IMAP) with encrypted alternatives (SFTP, SSH, POP3S, IMAPS).")
    if any(f["port"] in (3306, 5432, 1433, 1521, 27017, 6379) for f in findings):
        recs.append("Databases detected on network-accessible ports. Bind to localhost and restrict access by IP using firewall rules.")
    if any(f["port"] == 3389 for f in findings):
        recs.append("RDP exposed: enforce Network Level Authentication (NLA), deploy behind VPN, and restrict source IPs.")
    if any(f["port"] == 445 for f in findings):
        recs.append("SMB exposed: ensure all patches (MS17-010) are applied and block port 445 at the network perimeter.")
    if any(f["port"] == 80 for f in findings):
        recs.append("HTTP detected: configure server to redirect all traffic to HTTPS (301 redirect + HSTS header).")
    recs.append("Review all open ports against a documented service inventory — close anything not explicitly required.")
    recs.append("Schedule recurring scans (weekly/monthly) to catch newly exposed services after config changes.")
    return recs


# ── Risk summary ──────────────────────────────────────────────────────────────
def summarize(findings: list[dict]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f["risk"]] = counts.get(f["risk"], 0) + 1
    if counts["CRITICAL"] > 0:
        overall = "CRITICAL"
    elif counts["HIGH"] > 0:
        overall = "HIGH"
    elif counts["MEDIUM"] > 0:
        overall = "MEDIUM"
    elif counts["LOW"] > 0:
        overall = "LOW"
    else:
        overall = "CLEAN"
    return {"overall_risk": overall, "by_severity": counts, "open_ports_total": len(findings)}


# ── Main ──────────────────────────────────────────────────────────────────────
def run_scan(target: str, port_list: list[int] | None = None) -> dict:
    if port_list is None:
        port_list = sorted(RISKY_PORTS.keys()) + [22, 443, 8080, 8443]
        port_list = sorted(set(port_list))

    print(f"[*] Resolving {target}...")
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        print(f"[!] Could not resolve host: {e}")
        sys.exit(1)

    print(f"[*] Target: {target} ({resolved_ip})")
    print(f"[*] Scanning {len(port_list)} ports...\n")

    findings = scan_ports(resolved_ip, port_list)

    # Grab banners for open ports
    for f in findings:
        banner = grab_banner(resolved_ip, f["port"])
        if banner:
            f["banner"] = banner

    # Sort by severity
    findings.sort(key=lambda x: RISK_ORDER.get(x["risk"], 99))

    summary = summarize(findings)
    recommendations = build_recommendations(findings)

    report = {
        "scan_metadata": {
            "tool": "Network Vulnerability Scanner v1.0",
            "author": "Aldo Pilers",
            "target_input": target,
            "resolved_ip": resolved_ip,
            "scan_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "ports_scanned": len(port_list),
        },
        "summary": summary,
        "findings": findings,
        "recommendations": recommendations,
    }
    return report


def print_report(report: dict):
    s = report["summary"]
    meta = report["scan_metadata"]
    print("=" * 60)
    print("  VULNERABILITY SCAN REPORT")
    print("=" * 60)
    print(f"  Target   : {meta['target_input']} ({meta['resolved_ip']})")
    print(f"  Scanned  : {meta['scan_timestamp']}")
    print(f"  Ports    : {meta['ports_scanned']} checked | {s['open_ports_total']} open")
    print(f"  Overall  : {s['overall_risk']}")
    print()
    sev = s["by_severity"]
    print(f"  CRITICAL:{sev['CRITICAL']}  HIGH:{sev['HIGH']}  MEDIUM:{sev['MEDIUM']}  LOW:{sev['LOW']}  INFO:{sev['INFO']}")
    print("=" * 60)

    if not report["findings"]:
        print("\n  [✓] No open risky ports detected.\n")
    else:
        print("\n  OPEN PORTS\n")
        for f in report["findings"]:
            banner = f.get("banner", "")
            banner_str = f"  ↳ Banner: {banner}" if banner else ""
            print(f"  [{f['risk']:8s}] Port {f['port']:5d}  {f['service']}")
            print(f"             {f['reason']}")
            if banner_str:
                print(f"             {banner_str}")
            print()

    print("  RECOMMENDATIONS\n")
    for i, rec in enumerate(report["recommendations"], 1):
        print(f"  {i}. {rec}")
    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <host> [output.json]")
        print("Example: python scanner.py 192.168.1.1")
        print("         python scanner.py scanme.nmap.org report.json")
        sys.exit(1)

    target = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    report = run_scan(target)
    print_report(report)

    if output_file:
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  [✓] JSON report saved to: {output_file}\n")
    else:
        print("  Tip: Pass a filename as the second argument to save a JSON report.")
        print("  Example: python scanner.py 192.168.1.1 report.json\n")
