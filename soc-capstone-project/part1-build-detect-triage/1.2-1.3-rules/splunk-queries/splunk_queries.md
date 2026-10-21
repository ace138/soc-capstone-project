# Step 1.2 & 1.3: 10 Detection Rules That Fire (SPL Queries, Attack Tests & Stored Alert Timestamps)

All 10 behavioral Sigma rules (`../sigma/*.yml`) were translated into Splunk Processing Language (SPL), configured as scheduled alerts (`*/1 * * * *`) with **Add to Triggered Alerts** enabled, and validated using live attack simulations across **Windows (`DESKTOP-DTUQ6D4` / `192.168.120.150`)** and **Linux (`web` / `192.168.120.151`)**.

---

## 1. Master Coverage Matrix (10 Techniques, 6 MITRE ATT&CK Tactics, 2 Linux Rules, 1 Correlation Rule)
* **Tactics Covered (6 Tactics — Requirement: 5+ Tactics):**
  1. `TA0002` — **Execution** (Rule 01 `T1059.001`)
  2. `TA0003` — **Persistence** (Rule 02 `T1053.005`, Rule 03 `T1543.003`, Rule 09 `T1053.003`, Rule 10 `T1098.004`)
  3. `TA0004` — **Privilege Escalation** (Rule 02 `T1053.005`, Rule 03 `T1543.003`, Rule 09 `T1053.003`, Rule 10 `T1098.004`)
  4. `TA0005` — **Defense Evasion** (Rule 06 `T1070.001`, Rule 07 `T1218.011`)
  5. `TA0006` — **Credential Access** (Rule 04 `T1003.001`, Rule 05 `T1110` Correlation)
  6. `TA0011` — **Command and Control** (Rule 08 `T1105`)
* **Linux Rules (2 Rules — Requirement: 2+ Linux):** Rule 09 (`T1053.003`) & Rule 10 (`T1098.004`).
* **Correlation Rule (Requirement: 1+ Correlation Rule):** Rule 05 (`T1110` — $\ge 3$ Failed Logons `4625` followed by Successful Logon `4624` within 10 minutes).

| Rule # | Rule Name | ATT&CK ID | Primary Tactic(s) | Platform | Rule Owner | Stored Alert Timestamp(s) in Splunk (`EDT`) | Evidence Screenshot |
| :---: | :--- | :---: | :--- | :---: | :--- | :--- | :--- |
| **01** | Suspicious PowerShell Execution (`T1059.001`) | `T1059.001` | Execution (`TA0002`) | Windows | Member 1 | `2026-10-19 15:10:01 EDT`, `15:11:00 EDT`, `15:15:00 EDT` | `triggered_alerts_batch1.png` & `batch2.png` |
| **02** | Scheduled Task Creation (`T1053.005`) | `T1053.005` | Persistence (`TA0003`), PrivEsc (`TA0004`) | Windows | Member 2 | `2026-10-19 15:10:02 EDT`, `15:15:01 EDT` | `triggered_alerts_batch1.png` & `batch2.png` |
| **03** | New Windows Service Created (`T1543.003`) | `T1543.003` | Persistence (`TA0003`), PrivEsc (`TA0004`) | Windows | Member 2 | `2026-10-19 15:10:02 EDT`, `15:15:01 EDT` | `triggered_alerts_batch1.png` & `batch2.png` |
| **04** | LSASS Memory Credential Dumping (`T1003.001`) | `T1003.001` | Credential Access (`TA0006`) | Windows | Member 1 | `2026-10-19 15:10:01 EDT`, `15:15:00 EDT` | `triggered_alerts_batch1.png` & `batch2.png` |
| **05** | Brute Force Followed by Success (`T1110` Correlation) | `T1110` | Credential Access (`TA0006`) | Windows | Member 2 | `2026-10-19 15:10:02 EDT`, `15:15:00 EDT` | `triggered_alerts_batch1.png` & `batch2.png` |
| **06** | Clearing Windows Event Logs (`T1070.001` / `T1685.005`) | `T1070.001` | Defense Evasion (`TA0005`) | Windows | Member 4 | `2026-10-19 15:10:01 EDT`, `15:15:00 EDT` | `triggered_alerts_batch1.png` & `batch2.png` |
| **07** | Rundll32 Proxy Execution (`T1218.011`) | `T1218.011` | Defense Evasion (`TA0005`) | Windows | Member 1 | `2026-10-19 15:10:02 EDT`, `15:15:01 EDT` | `triggered_alerts_batch1.png` & `batch2.png` |
| **08** | Ingress Tool Transfer (`T1105`) | `T1105` | Command and Control (`TA0011`) | Windows / Web | Member 4 | `2026-10-19 15:10:01 EDT`, `15:15:02 EDT` | `triggered_alerts_batch1.png` & `batch2.png` |
| **09** | Linux Cron Job Persistence (`T1053.003`) | `T1053.003` | Persistence (`TA0003`), Execution (`TA0002`) | **Linux** (`web`) | Member 3 | `2026-10-19 15:10:02 EDT` | `triggered_alerts_batch1.png` |
| **10** | Linux SSH Authorized Keys Modification (`T1098.004`) | `T1098.004` | Persistence (`TA0003`), PrivEsc (`TA0004`) | **Linux** (`web`) | Member 3 | `2026-10-19 15:10:01 EDT`, `15:15:01 EDT` | `triggered_alerts_batch1.png` & `batch2.png` |

---

## 2. Production SPL Queries, Attack Test Commands & Stored Alert Verification

### Rule 01 — Suspicious PowerShell Execution (`T1059.001`)
* **Owner:** Member 1 | **Organisational Severity:** `P2` (High — Escalates to `P1` when paired with credential dumping or persistence)
* **Production SPL Query (Tuned):**
  ```spl
  index=* sourcetype="WinEventLog:*" (EventCode=4688 OR EventCode=4104) (*powershell* OR *IEX* OR *-enc* OR *-EncodedCommand* OR *DownloadString*) NOT Account_Name="SYSTEM" NOT New_Process_Name="*splunk-powershell.exe*"
  ```
* **Attack Simulation Command (`DESKTOP-DTUQ6D4` / `192.168.120.150`):**
  ```powershell
  powershell.exe "IEX 'Write-Host Test'"
  powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAVABlAHMAdAAnAA==
  ```
* **Stored Alert Fired:** `2026-10-19 15:10:01 EDT` & `15:11:00 EDT` (Shown in `../alert-screenshots/triggered_alerts_batch1.png`).

### Rule 02 — Scheduled Task Creation (`T1053.005`)
* **Owner:** Member 2 | **Organisational Severity:** `P2` (High)
* **Production SPL Query (Tuned):**
  ```spl
  index=* sourcetype="WinEventLog:*" (*schtasks* OR EventCode=4698) NOT Account_Name="SYSTEM"
  ```
* **Attack Simulation Command:**
  ```powershell
  schtasks /create /tn "SOC_Test_Task" /tr "notepad.exe" /sc once /st 23:59 /f
  ```
* **Stored Alert Fired:** `2026-10-19 15:10:02 EDT` & `15:15:01 EDT` (Shown in `../alert-screenshots/triggered_alerts_batch1.png`).

### Rule 03 — New Windows Service Created (`T1543.003`)
* **Owner:** Member 2 | **Organisational Severity:** `P2` (High)
* **Production SPL Query:**
  ```spl
  index=* sourcetype="WinEventLog:*" (EventCode=7045 OR EventCode=4697 OR (*sc.exe* AND *create*))
  ```
* **Attack Simulation Command:**
  ```powershell
  sc.exe create "SOC_Test_Svc" binPath= "C:\Windows\System32\calc.exe"
  ```
* **Stored Alert Fired:** `2026-10-19 15:10:02 EDT` & `15:15:01 EDT` (Shown in `../alert-screenshots/triggered_alerts_batch1.png`).

### Rule 04 — LSASS Memory Credential Dumping (`T1003.001`)
* **Owner:** Member 1 | **Organisational Severity:** `P1` (Critical)
* **Production SPL Query:**
  ```spl
  index=* (sourcetype="WinEventLog:*" OR sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational") (*lsass* OR *comsvcs* OR *MiniDump* OR GrantedAccess="0x1fffff")
  ```
* **Attack Simulation Command:**
  ```powershell
  rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Windows\Temp\lsass.dmp full
  ```
* **Stored Alert Fired:** `2026-10-19 15:10:01 EDT` & `15:15:00 EDT` (Shown in `../alert-screenshots/triggered_alerts_batch1.png`).

### Rule 05 — Brute Force Followed by Success (Correlation Rule) (`T1110`)
* **Owner:** Member 2 | **Organisational Severity:** `P2` (High)
* **Production SPL Query:**
  ```spl
  index=* sourcetype="WinEventLog:*" EventCode IN (4625, 4624)
  | bucket _time span=10m
  | stats count(eval(EventCode=4625)) as Failed_Logons, count(eval(EventCode=4624)) as Success_Logons by _time, Account_Name, host
  | where Failed_Logons >= 3 AND Success_Logons >= 1
  ```
* **Attack Simulation Command:**
  ```powershell
  1..3 | % { net use \\127.0.0.1\ipc$ /user:FakeAdmin WrongPassword123 2>$null }
  ```
* **Stored Alert Fired:** `2026-10-19 15:10:02 EDT` & `15:15:00 EDT` (Shown in `../alert-screenshots/triggered_alerts_batch1.png`).

### Rule 06 — Clearing Windows Event Logs (`T1070.001` / `T1685.005`)
* **Owner:** Member 4 | **Organisational Severity:** `P2` (High)
* **Production SPL Query:**
  ```spl
  index=* sourcetype="WinEventLog:*" (EventCode=1102 OR EventCode=104 OR (*wevtutil* AND (*cl* OR *clear-log*)))
  ```
* **Attack Simulation Command:**
  ```powershell
  wevtutil cl Application
  ```
* **Stored Alert Fired:** `2026-10-19 15:10:01 EDT` & `15:15:00 EDT` (Shown in `../alert-screenshots/triggered_alerts_batch1.png`).

### Rule 07 — Rundll32 Proxy Execution (`T1218.011`)
* **Owner:** Member 1 | **Organisational Severity:** `P3` (Medium — Escalates to `P1` when invoking `comsvcs.dll MiniDump`)
* **Production SPL Query:**
  ```spl
  index=* sourcetype="WinEventLog:*" EventCode=4688 *rundll32* (*comsvcs* OR *Control_RunDLL* OR *javascript:* OR *Temp*)
  ```
* **Attack Simulation Command:**
  ```powershell
  rundll32.exe shell32.dll,Control_RunDLL
  ```
* **Stored Alert Fired:** `2026-10-19 15:10:02 EDT` & `15:15:01 EDT` (Shown in `../alert-screenshots/triggered_alerts_batch1.png`).

### Rule 08 — Ingress Tool Transfer (`T1105`)
* **Owner:** Member 4 | **Organisational Severity:** `P2` (High)
* **Production SPL Query:**
  ```spl
  index=* (sourcetype="WinEventLog:*" EventCode=4688 (*certutil* OR *Invoke-WebRequest* OR *curl*)) OR (sourcetype="access_combined" "CertUtil URL Agent")
  ```
* **Attack Simulation Command:**
  ```powershell
  certutil.exe -urlcache -f http://192.168.120.151/test.txt test.txt
  ```
* **Stored Alert Fired:** `2026-10-19 15:10:01 EDT` & `15:15:02 EDT` (Shown in `../alert-screenshots/triggered_alerts_batch1.png` & `batch2.png`).

### Rule 09 — Linux Cron Job Persistence (`T1053.003`)
* **Owner:** Member 3 | **Organisational Severity:** `P2` (High)
* **Production SPL Query:**
  ```spl
  index=linux_logs sourcetype="linux:audit" "cron_persistence"
  ```
* **Attack Simulation Command (Linux `web` / `192.168.120.151`):**
  ```bash
  echo "* * * * * root /bin/sh -c 'id > /tmp/pwn'" | sudo tee -a /etc/crontab
  ```
* **Stored Alert Fired:** `2026-10-19 15:10:02 EDT` (Shown in `../alert-screenshots/triggered_alerts_batch1.png`).

### Rule 10 — Linux SSH Authorized Keys Modification (`T1098.004`)
* **Owner:** Member 3 | **Organisational Severity:** `P2` (High)
* **Production SPL Query:**
  ```spl
  index=linux_logs sourcetype="linux:audit" "ssh_keys"
  ```
* **Attack Simulation Command (Linux `web` / `192.168.120.151`):**
  ```bash
  mkdir -p ~/.ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... test@attack" >> ~/.ssh/authorized_keys
  ```
* **Stored Alert Fired:** `2026-10-19 15:10:01 EDT` & `15:15:01 EDT` (Shown in `../alert-screenshots/triggered_alerts_batch1.png` & `batch2.png`).
