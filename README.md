# Network Vulnerability Scanner & Security Audit Tool

**Author:** Aldo Pilers  
**Stack:** Python 3.10+, Bash  
**Purpose:** Scan a host for open ports, identify risky services, flag misconfigurations against security baselines, and generate a structured JSON audit report. Includes a companion Bash script for live auth log monitoring.

---

## What This Does

| Component | File | What it does |
|-----------|------|--------------|
| Port Scanner | `scanner.py` | Scans target for open ports, identifies services, flags risks against CIS/NIST baselines, grabs banners, outputs JSON report |
| Log Monitor | `log_monitor.sh` | Watches system auth logs for failed SSH logins, brute force patterns, sudo abuse, new user creation |

---

## Quick Start

### 1. Scanner

```bash
# Scan a host and print results to terminal
python scanner.py 192.168.1.1

# Scan and save JSON report
python scanner.py 192.168.1.1 report.json

# Scan a public test host (Nmap's official test server)
python scanner.py scanme.nmap.org report.json
```

No external libraries needed — uses Python's built-in `socket` module.

### 2. Log Monitor

```bash
# Test mode (no root needed — runs against sample data)
bash log_monitor.sh --test

# Live mode (monitors real auth log — requires sudo on Linux)
sudo bash log_monitor.sh
```

---

## Sample Output

```
============================================================
  VULNERABILITY SCAN REPORT
============================================================
  Target   : 192.168.1.1 (192.168.1.1)
  Scanned  : 2024-11-15T14:32:01Z
  Ports    : 27 checked | 3 open
  Overall  : HIGH

  CRITICAL:0  HIGH:2  MEDIUM:0  LOW:1  INFO:0
============================================================

  OPEN PORTS

  [HIGH    ] Port    21  FTP
             Transmits credentials in plaintext. Replace with SFTP/SCP.

  [HIGH    ] Port  3306  MySQL
             Database exposed. Bind to localhost or restrict by IP.

  [LOW     ] Port    80  HTTP
             Unencrypted web traffic. Enforce HTTPS redirect.

  RECOMMENDATIONS

  1. Immediately review firewall rules — critical/high-risk services should not be internet-facing.
  2. Replace plaintext protocols (FTP, Telnet, POP3, IMAP) with encrypted alternatives.
  3. Databases detected on network-accessible ports. Bind to localhost.
  ...
```

---

## Risk Levels

| Level | Meaning |
|-------|---------|
| CRITICAL | Immediate action required — common attack vector or unauthenticated access |
| HIGH | Significant risk — often exploited, plaintext protocols, or exposed databases |
| MEDIUM | Should be reviewed — may be acceptable depending on context |
| LOW | Minor issue — best practice improvement |
| INFO | Open port with no known risk profile |

---

## Ports Checked

The scanner checks 27 ports including:

- **Remote access:** SSH (22), Telnet (23), RDP (3389), VNC (5900)
- **File transfer:** FTP (21)
- **Databases:** MySQL (3306), PostgreSQL (5432), MSSQL (1433), Oracle (1521), MongoDB (27017), Redis (6379)
- **Web:** HTTP (80), HTTPS (443), alt ports (8080, 8443)
- **Email:** SMTP (25), POP3 (110), IMAP (143)
- **Windows:** NetBIOS (139), SMB (445), MS-RPC (135)
- **DNS:** 53

---

## Practical Use Cases

- **Home lab auditing** — scan your router or VMs to learn what services are exposed
- **Pre-deployment checklist** — verify a server is locked down before going live
- **Compliance evidence** — JSON reports can be attached to audit documentation
- **School/small business** — run with permission to assess network posture before an IT review

---

## Legal Notice

Only scan hosts you own or have explicit written permission to test. Unauthorized port scanning may violate computer fraud laws in your jurisdiction.

---

## Future Improvements

- [ ] Add SSL/TLS certificate expiry checking
- [ ] CVE lookup for detected service versions
- [ ] HTML report generation
- [ ] Scheduled scan + email alerting
- [ ] Docker container for easy deployment
