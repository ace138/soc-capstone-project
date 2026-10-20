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
| **ALT-008** | Rule 09 & 10: Linux Cron & SSH Key Persistence (`linux:audit`) | `web` | `192.168.120.149` | **True Positive** | Correlated with **Incident B** |
| **ALT-009** | Benign Admin Test (`Get-Process`, `splunk-powershell.exe`) | `DESKTOP-DTUQ6D4` | `192.168.120.150` | **Benign / Authorized** | Closed & Tuned (`NOT Account_Name="SYSTEM"`) |

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
index=* sourcetype="WinEventLog:*" host="DESKTOP-DTUQ6D4" (EventCode=4688 OR EventCode=4625 OR EventCode=4624 OR EventCode=4698 OR EventCode=7045 OR EventCode=104) | table _time, EventCode, Account_Name, Creator_Process_Name, New_Process_Name
```

1. **Initial Execution (`15:10:01 EDT`):** PowerShell was invoked with `IEX` (Invoke-Expression) and `-EncodedCommand` generating `EventCode=4688` under `New_Process_Name=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`.
2. **Tool Transfer (`15:10:01 EDT`):** `certutil.exe -urlcache -f http://127.0.0.1/test.txt test.txt` was executed to stage an external payload onto the host filesystem.
3. **Persistence Established (`15:10:02 EDT`):** The attacker created a scheduled task (`SOC_Test_Task` running `notepad.exe`, `EventCode=4698`) and registered a custom Windows service (`SOC_Test_Svc`, `EventCode=7045`) via `sc.exe`.
4. **Defense Evasion & Credential Access (`15:10:02 EDT`):** `rundll32.exe` and `comsvcs.dll MiniDump` indicators were observed targeting LSASS process memory.

### Root Cause & Impact Analysis
* **Root Cause:** An administrative session on `DESKTOP-DTUQ6D4` executed untrusted PowerShell commands and living-off-the-land binaries (LOLBins) without Application Whitelisting (AppLocker) or Constrained Language Mode enforced.
* **Impact:** Local persistence was achieved via both Task Scheduler and the Service Control Manager, and local credential material in LSASS was exposed.

### Recommended Remediation
1. Isolate `192.168.120.150` using host firewall rules (`SOC_Contain_Outbound_C2`).
2. Delete the rogue scheduled task (`SOC_Test_Task`) and service (`SOC_Test_Svc`).
3. Rotate local administrator credentials on `DESKTOP-DTUQ6D4` and enable Windows Defender Credential Guard / LSA Protection (`RunAsPPL`).

---

## 3. Escalated Incident Report B: Brute-Force Authentication, Linux Persistence & Defense Evasion

### Executive Summary
* **Incident ID:** INC-2026-002 (Incident B)
* **Severity:** High
* **Status:** Contained & Remediated
* **Affected Endpoints:** `DESKTOP-DTUQ6D4` (`192.168.120.150`) and Linux Server `web` (`192.168.120.149`)
* **MITRE ATT&CK Techniques Observed:**
  * `T1110` – Brute Force (`EventCode=4625` Failed Logon followed by `EventCode=4624` Successful Logon)
  * `T1053.003` – Scheduled Task/Job: Cron (`key="cron_persistence"`)
  * `T1098.004` – Account Manipulation: SSH Authorized Keys (`key="ssh_keys"`)
  * `T1070.001` / `T1685.005` – Indicator Removal: Clear Windows Event Logs (`wevtutil cl Application` / `EventCode=104` / `1102`)

### Attack Timeline & Forensic Evidence
Using the Splunk authentication and audit trail query:
```spl
index=* host="DESKTOP-DTUQ6D4" (EventCode=4625 OR EventCode=4624 OR EventCode=1102 OR EventCode=104 OR *wevtutil*) | table _time, EventCode, Account_Name, Logon_Type, Message | sort _time
```

1. **Credential Stuffing / Brute Force (`15:10:02 EDT`):** Multiple failed network authentication attempts (`EventCode=4625`, `Logon_Type=3`) targeted `\\127.0.0.1\ipc$` under `FakeAdmin`, followed by successful session activity (`EventCode=4624`).
2. **Linux Persistence Correlation (`15:10:01 EDT`):** Concurrent `auditd` alerts fired on Linux host `web` for `/etc/crontab` modification (`key="cron_persistence"`) and `~/.ssh/authorized_keys` modification (`key="ssh_keys"`).
3. **Anti-Forensics / Defense Evasion (`15:10:01 EDT`):** The attacker ran `wevtutil cl Application` on `DESKTOP-DTUQ6D4` to purge event history and cover tracks. Because logs were already forwarded in real time to the Splunk SIEM (`192.168.120.149:9997`), all prior attack telemetry remained intact in Splunk.

### Recommended Remediation
1. Enforce account lockout policies (lock account after 5 failed `EventCode=4625` attempts within 15 minutes).
2. Restrict `wevtutil.exe` execution and audit log clearing permissions to strict break-glass accounts.
3. Revert `/etc/crontab` and `~/.ssh/authorized_keys` on the Linux `web` server and enforce SSH key-only authentication with immutable file attributes (`chattr +i`).
