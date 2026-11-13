# Incident Investigation Report: IR-2026-001

## Incident Overview

| Field | Details |
| :--- | :--- |
| Incident ID | IR-2026-001 |
| Alert Title | Suspicious Outbound Connection via curl.exe |
| Severity | Medium |
| Status | Closed (Authorized Lab Simulation) |
| Date & Time | 2026-11-13 12:11:19 UTC |
| Hostname | DESKTOP-GBS8LIH |
| User Account | DESKTOP-GBS8LIH\user |
| MITRE ATT&CK | T1105 (Ingress Tool Transfer), T1071.004 (DNS) |

## Forensic Evidence

### 1. Process Execution (Sysmon Event ID 1)
Splunk detected `curl.exe` running with silent flags (`-s`) and redirecting output to `NUL`, a common technique used to test outbound connectivity without writing files to disk.

| Field | Value |
| :--- | :--- |
| Timestamp | 2026-11-13 12:11:19.291 |
| Process Path | C:\Windows\System32\curl.exe |
| Command Line | `"C:\Windows\system32\curl.exe" -s http://example.com -o NUL` |
| User | DESKTOP-GBS8LIH\user |

### 2. DNS Resolution (Sysmon Event ID 22)
Two seconds after execution, the process initiated an outbound DNS query for an external domain.

| Field | Value |
| :--- | :--- |
| Timestamp | 2026-11-13 12:11:21.316 |
| Process | C:\Windows\System32\curl.exe |
| Queried Domain | example.com |
| Resolved IPs | 104.20.23.154, 172.66.147.243 |

### 3. SPL Hunting Query
```spl
index=endpoint sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (Image="*\\curl.exe" OR Image="*\\whoami.exe" OR Image="*\\ping.exe")
| table _time, User, Image, CommandLine
```

## Triage & Root Cause Analysis
- **Binary Integrity:** Verified that `curl.exe` executed from the legitimate Windows System32 directory.
- **Domain Reputation:** The target domain (`example.com`) and resolved Cloudflare IP addresses are benign test infrastructure.
- **Conclusion:** The activity was confirmed as a controlled SOC Tier 1 detection exercise on `DESKTOP-GBS8LIH`.

## Containment & Recommendations
- **Containment:** No host isolation required; traffic verified as benign simulation.
- **Detection Tuning:** Continue monitoring native utilities (`curl.exe`, `certutil.exe`, `bitsadmin.exe`) and correlate Process Creation (Event ID 1) with DNS Queries (Event ID 22) to flag connections to unknown domains or raw IPs.

**Analyst:** Omar Said Taha Bashir
