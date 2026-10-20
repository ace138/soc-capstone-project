# Part 2: Alert Triage & Incident Escalation Reports

## 1. SOC Alert Queue Triage Log
All triggered alerts from the Splunk SIEM (`192.168.120.149`) were reviewed, correlated by host and timestamp, and classified prior to escalation.

| Alert ID | Rule Triggered | Host (`ComputerName`) | Source IP | Classification | Action Taken |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ALT-001** | Rule 01: Suspicious PowerShell (`EventCode=4688` / `4104`) | `DESKTOP-DTUQ6D4` | `192.168.120.150` | **True Positive** | Escalated to **Incident A** |
| **ALT-002** | Rule 02: Scheduled Task Creation (`schtasks.exe` / `4698`) | `DESKTOP-DTUQ6D4` | `192.168.120.150` | **True Positive** | Correlated with **Incident A** |
| **ALT-003** | Rule 03: Service Creation (`sc.exe` / `7045`) | `DESKTOP-DTUQ6D4` | `192.168.120.150` | **True Positive** | Correlated with **Incident A** |
| **ALT-004** | Rule 04 & 07: Rundll32 & LSASS Dump (`comsvcs.dll`) | `DESKTOP-DTUQ6D4` | `192.168.120.150` | **True Positive** | Escalated to **Incident A** (Critical) |
| **ALT-005** | Rule 08: Ingress Tool Transfer (`certutil.exe`) | `DESKTOP-DTUQ6D4` | `192.168.120.150` | **True Positive** | Correlated with **Incident A** |
| **ALT-006** | Rule 05: Brute Force Logon (`EventCode=4625` -> `4624`) | `DESKTOP-DTUQ6D4` | `192.168.120.150` | **True Positive** | Escalated to **Incident B** |
| **ALT-007** | Rule 06: Audit Log Cleared (`wevtutil.exe` / `1102` / `104`) | `DESKTOP-DTUQ6D4` | `192.168.120.150` | **True Positive** | Correlated with **Incident B** |
| **ALT-008** | Benign Admin Test (`Get-Process`, `Get-Service`) | `DESKTOP-DTUQ6D4` | `192.168.120.150` | **Benign / Authorized** | Closed (No escalation required) |

---

## 2. Escalated Incident Report A: Multi-Stage Endpoint Compromise & Credential Dumping

### Executive Summary
* **Incident ID:** INC-2026-001 (Incident A)
* **Severity:** Critical
* **Status:** Contained & Eradicated
* **Affected Endpoint:** `DESKTOP-DTUQ6D4` (`192.168.120.150`)
* **Log Source:** `WinEventLog:Security` (`sourcetype="WinEventLog:Security"`)
* **MITRE ATT&CK Techniques Observed:**
  * `T1059.001` – Command and Scripting Interpreter: PowerShell
  * `T1105` – Ingress Tool Transfer (`certutil.exe`)
  * `T1053.005` – Scheduled Task/Job: Scheduled Task (`schtasks.exe`)
  * `T1543.003` – Create or Modify System Process: Windows Service (`sc.exe`)
  * `T1218.011` – System Binary Proxy Execution: Rundll32
  * `T1003.001` – OS Credential Dumping: LSASS Memory (`comsvcs.dll`)

### Attack Timeline & Forensic Evidence (Splunk SPL Reconstruction)
Using the Splunk investigation query:
```spl
index=* sourcetype="WinEventLog:Security" host="DESKTOP-DTUQ6D4" EventCode=4688 | table _time, Account_Name, Creator_Process_Name, New_Process_Name, Process_Command_Line | sort _time