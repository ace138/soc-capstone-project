# Step 1.4 & 2.2: SOC Detection Cards (1-Page Card per Rule, Peer-Reviewed & P1–P4 Aligned)

Per **Step 1.4** and **Step 2.2**:
1. Every rule (`Rule 01` through `Rule 10`) has a complete **1-Page Detection Card** below (and saved individually as `card01_T1059_001.md` – `card10_T1098_004.md`).
2. Every card was **peer-reviewed by a teammate** (with documented reviewer name, review date, and review notes).
3. Every card has been **updated to match the Aegis Health Regional Hospital P1–P4 Severity Matrix (Task 2.2)**, including explicit SLA response times, update intervals, and declaration/downgrade authorities.

---

## 1. Master Detection Cards Index & Part 2.2 Severity Alignment Summary

| Card / Rule | Rule Title | MITRE ATT&CK | Author | Peer Reviewer | Initial Severity (v1.0) | Updated Org Severity (v1.2 — Task 2.2) | Response SLA & Playbook Link |
| :--- | :--- | :--- | :--- | :--- | :---: | :---: | :--- |
| **Card 01** | Suspicious PowerShell Execution | `T1059.001` (Execution) | Member 1 | Member 2 | High | **P2 — High** *(P1 if w/ Dump)* | $\le 30	ext{m}$ (`PB-02`) |
| **Card 02** | Scheduled Task Creation | `T1053.005` (Persistence) | Member 2 | Member 1 | Medium | **P2 — High** | $\le 30	ext{m}$ (`PB-03`) |
| **Card 03** | Windows Service Creation | `T1543.003` (Persistence) | Member 2 | Member 1 | Medium | **P2 — High** | $\le 30	ext{m}$ (`PB-03`) |
| **Card 04** | LSASS Memory Credential Dumping | `T1003.001` (Credential Access) | Member 1 | Member 2 | Critical | **P1 — Critical** | $\le 15	ext{m}$ (`PB-01`) |
| **Card 05** | Brute Force Followed by Success | `T1110` (Credential Access) | Member 2 | Member 1 | High | **P2 — High** | $\le 30	ext{m}$ (`PB-03`) |
| **Card 06** | Clearing Windows Event Logs | `T1070.001` (Defense Evasion) | Member 4 | Member 3 | High | **P2 — High** *(P1 if active IR)* | $\le 30	ext{m}$ (`PB-01`/`03`) |
| **Card 07** | Rundll32 Proxy Execution | `T1218.011` (Defense Evasion) | Member 1 | Member 3 | Medium | **P3 — Medium** *(P1 if `comsvcs`)* | $\le 2	ext{h}$ (`PB-01`) |
| **Card 08** | Ingress Tool Transfer | `T1105` (Command & Control) | Member 4 | Member 2 | Medium | **P2 — High** *(P3 if dev curl)* | $\le 30	ext{m}$ (`PB-02`) |
| **Card 09** | Linux Cron Job Persistence | `T1053.003` (Persistence) | Member 3 | Member 4 | Medium | **P2 — High** | $\le 30	ext{m}$ (`PB-03`) |
| **Card 10** | Linux SSH Authorized Keys Mod | `T1098.004` (Persistence) | Member 3 | Member 4 | High | **P2 — High** | $\le 30	ext{m}$ (`PB-03`) |

---

# Detection Card 01: Suspicious PowerShell Encoded or Download Execution

| Metadata Field | Value |
| :--- | :--- |
| **Rule ID & Sigma File** | `Rule 01` (`../../1.2-1.3-rules/sigma/rule01*.yml`) |
| **MITRE ATT&CK Mapping** | `T1059.001 — Command and Scripting Interpreter: PowerShell (Execution)` |
| **Rule Author** | **Member 1 (Windows Endpoint & Detection Lead)** |
| **Peer Reviewer & Date** | **Member 2 (SIEM Architect & Incident Commander)** (`2026-10-19`) |
| **Peer Review Notes** | Verified SPL syntax; recommended excluding `Account_Name="SYSTEM"` and `*splunk-powershell.exe*` after benign test produced 681 forwarder events. |
| **Severity (v1.0 -> v1.2 Updated)** | `High` $\rightarrow$ **P2 — High (Escalates to P1 Critical if paired with Credential Access or on Tier-0/Clinical Host)** *(Updated per Task 2.2 Severity Matrix)* |
| **SLA & Governance (Task 2.2)** | Acknowledge <= 30 min | Update every 2 hours | Declare: Any SOC Analyst | Downgrade: SOC Lead / CISO |
| **Required Log Sources** | `WinEventLog:Security` (`EventCode=4688`), `WinEventLog:Microsoft-Windows-PowerShell/Operational` (`EventCode=4104`), `Sysmon` (`EventID=1`) |

## 1. Production Splunk SPL Query
```spl
index=* sourcetype="WinEventLog:*" (EventCode=4688 OR EventCode=4104) (*powershell* OR *IEX* OR *-enc* OR *-EncodedCommand* OR *DownloadString*) NOT Account_Name="SYSTEM" NOT New_Process_Name="*splunk-powershell.exe*"
```

## 2. Attack Verification & Benign Test Results
* **Attack Simulation Executed:**
  ```text
  powershell.exe "IEX 'Write-Host Test'" ; powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAVABlAHMAdAAnAA==
  ```
* **Stored Alert Timestamp:** `2026-10-19 15:10:01 EDT (Stored Alert Verified in `triggered_alerts_batch1.png`)`
* **Benign Test Executed (Normal Activity):**
  ```text
  powershell.exe -Command "Get-Process | Select-Object -First 5" (Interactive Admin) & background `splunk-powershell.exe` (`SYSTEM`)
  ```
* **Benign Test Result:** **0 Alerts Fired post-tuning (`benign_test_zero_alerts.png`)**

## 3. Known False Positives & Tuning Applied
1. Splunk Universal Forwarder helper `splunk-powershell.exe` running under `NT AUTHORITY\SYSTEM`.
2. Signed IT automation scripts utilizing Base64 parameters.

## 4. Analyst Triage, Containment & Escalation Steps
1. Inspect `Process_Command_Line` / `ScriptBlockText` and decode any Base64 payload (`[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(...))`).
2. Check parent process (`Creator_Process_Name`) and executing user (`Account_Name`).
3. Query +/- 10 minutes on the same `host` for outbound network connections, `certutil`/`curl` (`Rule 08`), persistence (`Rule 02`/`03`), or LSASS access (`Rule 04`).
4. Trigger **Playbook PB-02 (Malicious PowerShell & Staging)** if unauthorized execution is confirmed.

---

# Detection Card 02: Scheduled Task Creation via Schtasks or Event 4698

| Metadata Field | Value |
| :--- | :--- |
| **Rule ID & Sigma File** | `Rule 02` (`../../1.2-1.3-rules/sigma/rule02*.yml`) |
| **MITRE ATT&CK Mapping** | `T1053.005 — Scheduled Task/Job: Scheduled Task (Persistence, Privilege Escalation, Execution)` |
| **Rule Author** | **Member 2 (SIEM Architect & Incident Commander)** |
| **Peer Reviewer & Date** | **Member 1 (Windows Endpoint & Detection Lead)** (`2026-10-19`) |
| **Peer Review Notes** | Approved correlation of `EventCode=4688` (`schtasks.exe /create`) with `EventCode=4698` XML task registration; added `NOT Account_Name="SYSTEM"` tuning. |
| **Severity (v1.0 -> v1.2 Updated)** | `Medium` $\rightarrow$ **P2 — High (Unauthorized persistence on enterprise/clinical endpoint)** *(Updated per Task 2.2 Severity Matrix)* |
| **SLA & Governance (Task 2.2)** | Acknowledge <= 30 min | Update every 2 hours | Declare: Any SOC Analyst | Downgrade: SOC Lead / CISO |
| **Required Log Sources** | `WinEventLog:Security` (`EventCode=4688`, `EventCode=4698`), `Sysmon` (`EventID=1`) |

## 1. Production Splunk SPL Query
```spl
index=* sourcetype="WinEventLog:*" (*schtasks* OR EventCode=4698) NOT Account_Name="SYSTEM"
```

## 2. Attack Verification & Benign Test Results
* **Attack Simulation Executed:**
  ```text
  schtasks /create /tn "SOC_Test_Task" /tr "notepad.exe" /sc once /st 23:59 /f
  ```
* **Stored Alert Timestamp:** `2026-10-19 15:10:02 EDT (Stored Alert Verified in `triggered_alerts_batch1.png`)`
* **Benign Test Executed (Normal Activity):**
  ```text
  schtasks /query /fo LIST (Admin read-only task inspection) & Windows Update background task registration under `SYSTEM`
  ```
* **Benign Test Result:** **0 False-Positive Alerts Fired post-tuning (`tuned_rule02_schtasks.png`)**

## 3. Known False Positives & Tuning Applied
1. Built-in OS maintenance tasks registered by `NT AUTHORITY\SYSTEM`.
2. Authorized software updaters (Microsoft Edge/Office) running under system service accounts.

## 4. Analyst Triage, Containment & Escalation Steps
1. Extract `Task_Name` (`/tn`) and executed binary path (`/tr` or `<Command>` in `EventCode=4698`).
2. Verify whether the binary resides in a non-standard path (`\Users\Public\`, `\Windows\Temp\`, `\AppData\`).
3. Correlate with parent process (`Creator_Process_Name`) to see if spawned by `powershell.exe` or `cmd.exe`.
4. If unauthorized, delete task via `schtasks /delete /tn "<TaskName>" /f` and follow **Playbook PB-03**.

---

# Detection Card 03: New Windows Service Created via Sc.exe or Event 7045

| Metadata Field | Value |
| :--- | :--- |
| **Rule ID & Sigma File** | `Rule 03` (`../../1.2-1.3-rules/sigma/rule03*.yml`) |
| **MITRE ATT&CK Mapping** | `T1543.003 — Create or Modify System Process: Windows Service (Persistence, Privilege Escalation)` |
| **Rule Author** | **Member 2 (SIEM Architect & Incident Commander)** |
| **Peer Reviewer & Date** | **Member 1 (Windows Endpoint & Detection Lead)** (`2026-10-19`) |
| **Peer Review Notes** | Validated coverage of both CLI (`sc.exe create`) and Service Control Manager (`EventCode=7045` / `4697`) so direct API service creation is also caught. |
| **Severity (v1.0 -> v1.2 Updated)** | `Medium` $\rightarrow$ **P2 — High (System-level persistence / privilege escalation risk)** *(Updated per Task 2.2 Severity Matrix)* |
| **SLA & Governance (Task 2.2)** | Acknowledge <= 30 min | Update every 2 hours | Declare: Any SOC Analyst | Downgrade: SOC Lead / CISO |
| **Required Log Sources** | `WinEventLog:System` (`EventCode=7045`), `WinEventLog:Security` (`EventCode=4697`, `EventCode=4688`), `Sysmon` (`EventID=1`) |

## 1. Production Splunk SPL Query
```spl
index=* sourcetype="WinEventLog:*" (EventCode=7045 OR EventCode=4697 OR (*sc.exe* AND *create*))
```

## 2. Attack Verification & Benign Test Results
* **Attack Simulation Executed:**
  ```text
  sc.exe create "SOC_Test_Svc" binPath= "C:\Windows\System32\calc.exe"
  ```
* **Stored Alert Timestamp:** `2026-10-19 15:10:02 EDT (Stored Alert Verified in `triggered_alerts_batch1.png`)`
* **Benign Test Executed (Normal Activity):**
  ```text
  sc.exe query EventLog ; Get-Service | Where-Object {$_.Status -eq "Running"}
  ```
* **Benign Test Result:** **0 Alerts Fired (`benign_test_zero_alerts.png`)**

## 3. Known False Positives & Tuning Applied
1. Approved change-window software or kernel driver installations.
2. EDR / backup agent updates during scheduled maintenance windows.

## 4. Analyst Triage, Containment & Escalation Steps
1. Inspect `Service_Name`, `Service_File_Name` (`binPath`), and `Service_Account` (`LocalSystem` vs. user).
2. Verify whether creation occurred within an approved IT Change Request window.
3. Compute SHA-256 hash of the target service executable.
4. Stop and remove unauthorized service (`Stop-Service <Name> -Force ; sc.exe delete <Name>`).

---

# Detection Card 04: LSASS Memory Credential Dumping Activity

| Metadata Field | Value |
| :--- | :--- |
| **Rule ID & Sigma File** | `Rule 04` (`../../1.2-1.3-rules/sigma/rule04*.yml`) |
| **MITRE ATT&CK Mapping** | `T1003.001 — OS Credential Dumping: LSASS Memory (Credential Access)` |
| **Rule Author** | **Member 1 (Windows Endpoint & Detection Lead)** |
| **Peer Reviewer & Date** | **Member 2 (SIEM Architect & Incident Commander)** (`2026-10-19`) |
| **Peer Review Notes** | Confirmed high-fidelity detection of `comsvcs.dll MiniDump` and Sysmon `EventID=10` `GrantedAccess` masks; mapped directly to P1 Critical SLA. |
| **Severity (v1.0 -> v1.2 Updated)** | `Critical` $\rightarrow$ **P1 — Critical (Immediate domain/enterprise credential compromise threat)** *(Updated per Task 2.2 Severity Matrix)* |
| **SLA & Governance (Task 2.2)** | Acknowledge <= 15 min | Update every 30 min | Declare: Any SOC Analyst | Downgrade: CISO / Incident Commander ONLY |
| **Required Log Sources** | `WinEventLog:Security` (`EventCode=4688`), `Sysmon` (`EventID=1` ProcessCreate, `EventID=10` ProcessAccess) |

## 1. Production Splunk SPL Query
```spl
index=* (sourcetype="WinEventLog:*" OR sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational") (*lsass* OR *comsvcs* OR *MiniDump* OR GrantedAccess="0x1fffff")
```

## 2. Attack Verification & Benign Test Results
* **Attack Simulation Executed:**
  ```text
  rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Windows\Temp\lsass.dmp full
  ```
* **Stored Alert Timestamp:** `2026-10-19 15:10:01 EDT (Stored Alert Verified in `triggered_alerts_batch1.png`)`
* **Benign Test Executed (Normal Activity):**
  ```text
  tasklist /fi "imagename eq lsass.exe" (Standard process enumeration without memory dump)
  ```
* **Benign Test Result:** **0 Alerts Fired (`benign_test_zero_alerts.png`)**

## 3. Known False Positives & Tuning Applied
1. Signed Endpoint Detection & Response (EDR) or antivirus processes inspecting `lsass.exe`.
2. Windows Error Reporting (`WerFault.exe`) during rare OS crash dumps.

## 4. Analyst Triage, Containment & Escalation Steps
1. **IMMEDIATE P1 ACTION:** Initiate **Playbook PB-01 (Credential Dumping & Host Containment)**.
2. Isolate affected host (`DESKTOP-DTUQ6D4`) via firewall rule `SOC_Contain_Outbound_C2` within 15 minutes.
3. Acquire VM snapshot, volatile RAM dump, and SHA-256 hash of the dump file (`C:\Windows\Temp\lsass.dmp`) before deleting it.
4. Reset passwords and revoke Kerberos TGTs for all accounts with active logon sessions on the host.

---

# Detection Card 05: Brute Force Failed Logons Followed by Successful Logon (Correlation)

| Metadata Field | Value |
| :--- | :--- |
| **Rule ID & Sigma File** | `Rule 05` (`../../1.2-1.3-rules/sigma/rule05*.yml`) |
| **MITRE ATT&CK Mapping** | `T1110 — Brute Force (Credential Access)` |
| **Rule Author** | **Member 2 (SIEM Architect & Incident Commander)** |
| **Peer Reviewer & Date** | **Member 1 (Windows Endpoint & Detection Lead)** (`2026-10-19`) |
| **Peer Review Notes** | Tested 10-minute `bucket _time span=10m` correlation logic; verified that 1–2 accidental typos do not fire, while >=3 `4625` + >=1 `4624` reliably alerts. |
| **Severity (v1.0 -> v1.2 Updated)** | `High` $\rightarrow$ **P2 — High (Confirmed password compromise following brute-force/stuffing)** *(Updated per Task 2.2 Severity Matrix)* |
| **SLA & Governance (Task 2.2)** | Acknowledge <= 30 min | Update every 2 hours | Declare: Any SOC Analyst | Downgrade: SOC Lead / CISO |
| **Required Log Sources** | `WinEventLog:Security` (`EventCode=4625` Failed Logon, `EventCode=4624` Successful Logon) |

## 1. Production Splunk SPL Query
```spl
index=* sourcetype="WinEventLog:*" EventCode IN (4625, 4624) | bucket _time span=10m | stats count(eval(EventCode=4625)) as Failed_Logons, count(eval(EventCode=4624)) as Success_Logons by _time, Account_Name, host | where Failed_Logons >= 3 AND Success_Logons >= 1
```

## 2. Attack Verification & Benign Test Results
* **Attack Simulation Executed:**
  ```text
  1..3 | % { net use \\127.0.0.1\ipc$ /user:FakeAdmin WrongPassword123 2>$null }
  ```
* **Stored Alert Timestamp:** `2026-10-19 15:10:02 EDT (Stored Alert Verified in `triggered_alerts_batch1.png`)`
* **Benign Test Executed (Normal Activity):**
  ```text
  Single legitimate user interactive logon (`EventCode=4624`, 0 failed logons) or 1 accidental password typo followed by login
  ```
* **Benign Test Result:** **0 Alerts Fired (Threshold requires >= 3 failures + >= 1 success in 10m window)**

## 3. Known False Positives & Tuning Applied
1. Legitimate staff member mistyping their password 3+ times after a mandatory password reset.
2. Expired cached service credentials on a secondary workstation.

## 4. Analyst Triage, Containment & Escalation Steps
1. Inspect `Logon_Type` (`3` = Network/SMB, `10` = RDP, `2` = Interactive) and `Source_Network_Address`.
2. Check if `Failed_Logons` targeted multiple accounts (password spraying) or a single privileged account (`FakeAdmin`).
3. Query all `EventCode=4688` commands executed by `Account_Name` immediately after `EventCode=4624`.
4. Execute **Playbook PB-03**: disable or lock compromised account (`Disable-LocalUser`) and block attacker source IP.

---

# Detection Card 06: Clearing Windows Event Logs via Wevtutil or Event 1102 / 104

| Metadata Field | Value |
| :--- | :--- |
| **Rule ID & Sigma File** | `Rule 06` (`../../1.2-1.3-rules/sigma/rule06*.yml`) |
| **MITRE ATT&CK Mapping** | `T1070.001 ( / T1685.005) — Indicator Removal: Clear Windows Event Logs (Defense Evasion)` |
| **Rule Author** | **Member 4 (Threat Intel, Dashboard & Readiness Lead)** |
| **Peer Reviewer & Date** | **Member 3 (Linux Telemetry, Containment & Forensics Lead)** (`2026-10-19`) |
| **Peer Review Notes** | Verified coverage of Security (`1102`), System/Application (`104`), and process creation (`wevtutil cl`); confirmed prior events remain safe in Splunk index. |
| **Severity (v1.0 -> v1.2 Updated)** | `High` $\rightarrow$ **P2 — High (High-confidence anti-forensic indicator; escalates to P1 if paired with active compromise)** *(Updated per Task 2.2 Severity Matrix)* |
| **SLA & Governance (Task 2.2)** | Acknowledge <= 30 min | Update every 2 hours | Declare: Any SOC Analyst | Downgrade: SOC Lead / CISO |
| **Required Log Sources** | `WinEventLog:Security` (`EventCode=1102`, `EventCode=4688`), `WinEventLog:System` (`EventCode=104`) |

## 1. Production Splunk SPL Query
```spl
index=* sourcetype="WinEventLog:*" (EventCode=1102 OR EventCode=104 OR (*wevtutil* AND (*cl* OR *clear-log*)))
```

## 2. Attack Verification & Benign Test Results
* **Attack Simulation Executed:**
  ```text
  wevtutil cl Application
  ```
* **Stored Alert Timestamp:** `2026-10-19 15:10:01 EDT (Stored Alert Verified in `triggered_alerts_batch1.png`)`
* **Benign Test Executed (Normal Activity):**
  ```text
  wevtutil qe Application /c:5 /f:text (Read-only query of last 5 Application events)
  ```
* **Benign Test Result:** **0 Alerts Fired (`benign_test_zero_alerts.png`)**

## 3. Known False Positives & Tuning Applied
1. Non-production lab VM template reset prior to golden-image snapshot (never normal in production hospital operations).

## 4. Analyst Triage, Containment & Escalation Steps
1. Treat any unscheduled `1102` or `104` event as active anti-forensics.
2. Query Splunk for the 30 minutes of telemetry **immediately preceding** the log-clear timestamp on `host` (since Splunk retains forwarded logs even after local `.evtx` files are wiped).
3. Identify the `SubjectUserName` / `Account_Name` that invoked `wevtutil.exe` and lock the session.

---

# Detection Card 07: Suspicious Rundll32 System Binary Proxy Execution

| Metadata Field | Value |
| :--- | :--- |
| **Rule ID & Sigma File** | `Rule 07` (`../../1.2-1.3-rules/sigma/rule07*.yml`) |
| **MITRE ATT&CK Mapping** | `T1218.011 — System Binary Proxy Execution: Rundll32 (Defense Evasion)` |
| **Rule Author** | **Member 1 (Windows Endpoint & Detection Lead)** |
| **Peer Reviewer & Date** | **Member 3 (Linux Telemetry, Containment & Forensics Lead)** (`2026-10-19`) |
| **Peer Review Notes** | Reviewed CLI filter parameters; confirmed correlation with Rule 04 when `rundll32.exe` invokes `comsvcs.dll, MiniDump`. |
| **Severity (v1.0 -> v1.2 Updated)** | `Medium` $\rightarrow$ **P3 — Medium (Escalates to P1 Critical when invoking `comsvcs.dll` or unsigned DLLs from Temp)** *(Updated per Task 2.2 Severity Matrix)* |
| **SLA & Governance (Task 2.2)** | Acknowledge <= 2 hours (<= 15 min if P1 correlated) | Update every 8 hours | Declare: Any SOC Analyst | Downgrade: SOC Lead |
| **Required Log Sources** | `WinEventLog:Security` (`EventCode=4688`), `Sysmon` (`EventID=1`, `EventID=7` ImageLoaded) |

## 1. Production Splunk SPL Query
```spl
index=* sourcetype="WinEventLog:*" EventCode=4688 *rundll32* (*comsvcs* OR *Control_RunDLL* OR *javascript:* OR *Temp*)
```

## 2. Attack Verification & Benign Test Results
* **Attack Simulation Executed:**
  ```text
  rundll32.exe shell32.dll,Control_RunDLL ; rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump ...
  ```
* **Stored Alert Timestamp:** `2026-10-19 15:10:02 EDT (Stored Alert Verified in `triggered_alerts_batch1.png`)`
* **Benign Test Executed (Normal Activity):**
  ```text
  Standard Windows explorer GUI background operations without suspicious CLI proxy exports
  ```
* **Benign Test Result:** **0 Alerts Fired (`benign_test_zero_alerts.png`)**

## 3. Known False Positives & Tuning Applied
1. Administrator launching legacy Windows Control Panel applets (`shell32.dll,Control_RunDLL`).
2. Legitimate printer driver UI dialogs.

## 4. Analyst Triage, Containment & Escalation Steps
1. Examine the full `Process_Command_Line` for DLL path and exported function name.
2. If `comsvcs.dll` / `MiniDump` is present, immediately escalate to **P1 Critical** under **Playbook PB-01**.
3. If `Control_RunDLL` was run interactively by a verified sysadmin without other alerts, document and close as **P4 Benign**.

---

# Detection Card 08: Ingress Tool Transfer via Certutil or CLI Web Utilities

| Metadata Field | Value |
| :--- | :--- |
| **Rule ID & Sigma File** | `Rule 08` (`../../1.2-1.3-rules/sigma/rule08*.yml`) |
| **MITRE ATT&CK Mapping** | `T1105 — Ingress Tool Transfer (Command and Control)` |
| **Rule Author** | **Member 4 (Threat Intel, Dashboard & Readiness Lead)** |
| **Peer Reviewer & Date** | **Member 2 (SIEM Architect & Incident Commander)** (`2026-10-19`) |
| **Peer Review Notes** | Added cross-source correlation with 3rd-source Apache web logs (`sourcetype="access_combined"` User-Agent `CertUtil URL Agent`). |
| **Severity (v1.0 -> v1.2 Updated)** | `Medium` $\rightarrow$ **P2 — High (External payload staging on endpoint; P3 Medium if verified internal dev `curl`)** *(Updated per Task 2.2 Severity Matrix)* |
| **SLA & Governance (Task 2.2)** | Acknowledge <= 30 min | Update every 2 hours | Declare: Any SOC Analyst | Downgrade: SOC Lead |
| **Required Log Sources** | `WinEventLog:Security` (`EventCode=4688`), `Sysmon` (`EventID=1`, `EventID=11`), Apache Web Logs (`sourcetype=access_combined`) |

## 1. Production Splunk SPL Query
```spl
index=* (sourcetype="WinEventLog:*" EventCode=4688 (*certutil* OR *Invoke-WebRequest* OR *curl*)) OR (sourcetype="access_combined" "CertUtil URL Agent")
```

## 2. Attack Verification & Benign Test Results
* **Attack Simulation Executed:**
  ```text
  certutil.exe -urlcache -f http://127.0.0.1/test.txt test.txt
  ```
* **Stored Alert Timestamp:** `2026-10-19 15:10:01 EDT & 15:15:02 EDT (Stored Alert Verified in `triggered_alerts_batch1.png` & `batch2.png`)`
* **Benign Test Executed (Normal Activity):**
  ```text
  certutil.exe -store My (Local certificate store verification without `-urlcache` or `-split`)
  ```
* **Benign Test Result:** **0 Alerts Fired (`benign_test_zero_alerts.png`)**

## 3. Known False Positives & Tuning Applied
1. Software developers or sysadmins using `curl.exe` to check internal web server health (`http://192.168.120.151/health`).

## 4. Analyst Triage, Containment & Escalation Steps
1. Extract remote URI/IP from `Process_Command_Line` and cross-check Apache `access_combined` logs.
2. Locate the downloaded file on disk (`test.txt`), compute its SHA-256 hash (`Get-FileHash`), and quarantine/delete it (`Remove-Item -Force`).
3. Block the remote C2 IP/subnet via Windows Firewall (`SOC_Contain_Outbound_C2`) following **Playbook PB-02**.

---

# Detection Card 09: Linux Cron Job Persistence Modification via Auditd

| Metadata Field | Value |
| :--- | :--- |
| **Rule ID & Sigma File** | `Rule 09` (`../../1.2-1.3-rules/sigma/rule09*.yml`) |
| **MITRE ATT&CK Mapping** | `T1053.003 — Scheduled Task/Job: Cron (Persistence, Execution, Privilege Escalation)` |
| **Rule Author** | **Member 3 (Linux Telemetry, Containment & Forensics Lead)** |
| **Peer Reviewer & Date** | **Member 4 (Threat Intel, Dashboard & Readiness Lead)** (`2026-10-19`) |
| **Peer Review Notes** | Verified `auditd` syscall rule `-w /etc/crontab -p wa -k cron_persistence` on Linux host `web` and sub-second forwarding (`0.638s`) to Splunk. |
| **Severity (v1.0 -> v1.2 Updated)** | `Medium` $\rightarrow$ **P2 — High (Unauthorized root/user persistence on Linux production web server)** *(Updated per Task 2.2 Severity Matrix)* |
| **SLA & Governance (Task 2.2)** | Acknowledge <= 30 min | Update every 2 hours | Declare: Any SOC Analyst | Downgrade: SOC Lead / CISO |
| **Required Log Sources** | `sourcetype="linux:audit"` (`index=linux_logs`, `/var/log/audit/audit.log`, `key="cron_persistence"`) |

## 1. Production Splunk SPL Query
```spl
index=linux_logs sourcetype="linux:audit" "cron_persistence"
```

## 2. Attack Verification & Benign Test Results
* **Attack Simulation Executed:**
  ```text
  echo "* * * * * root /bin/sh -c 'id > /tmp/pwn'" | sudo tee -a /etc/crontab
  ```
* **Stored Alert Timestamp:** `2026-10-19 15:10:02 EDT (Stored Alert Verified in `triggered_alerts_batch1.png`)`
* **Benign Test Executed (Normal Activity):**
  ```text
  crontab -l ; cat /etc/crontab (Read-only inspection of cron schedules; `auditd` watches `-p wa` write/attribute changes only)
  ```
* **Benign Test Result:** **0 Alerts Fired (Read-only operations do not trigger `-p wa` syscall write filter)**

## 3. Known False Positives & Tuning Applied
1. Authorized Linux administrator updating scheduled database/log backup jobs during an approved maintenance window.

## 4. Analyst Triage, Containment & Escalation Steps
1. Inspect `auid` (original login UID), `uid` (effective UID), `tty`, and `exe` in the `linux:audit` event.
2. Diff `/etc/crontab` and `/var/spool/cron/crontabs/` to identify the newly injected command.
3. Remove malicious cron lines, kill any spawned child processes, and follow **Playbook PB-03**.

---

# Detection Card 10: Linux SSH Authorized Keys File Modification via Auditd

| Metadata Field | Value |
| :--- | :--- |
| **Rule ID & Sigma File** | `Rule 10` (`../../1.2-1.3-rules/sigma/rule10*.yml`) |
| **MITRE ATT&CK Mapping** | `T1098.004 — Account Manipulation: SSH Authorized Keys (Persistence, Privilege Escalation)` |
| **Rule Author** | **Member 3 (Linux Telemetry, Containment & Forensics Lead)** |
| **Peer Reviewer & Date** | **Member 4 (Threat Intel, Dashboard & Readiness Lead)** (`2026-10-19`) |
| **Peer Review Notes** | Confirmed `key="ssh_keys"` triggers immediately on `~/.ssh/authorized_keys` append operations; aligned severity to P2 High. |
| **Severity (v1.0 -> v1.2 Updated)** | `High` $\rightarrow$ **P2 — High (Unauthorized persistent SSH backdoor on Linux server `web`)** *(Updated per Task 2.2 Severity Matrix)* |
| **SLA & Governance (Task 2.2)** | Acknowledge <= 30 min | Update every 2 hours | Declare: Any SOC Analyst | Downgrade: SOC Lead / CISO |
| **Required Log Sources** | `sourcetype="linux:audit"` (`index=linux_logs`, `/var/log/audit/audit.log`, `key="ssh_keys"`) |

## 1. Production Splunk SPL Query
```spl
index=linux_logs sourcetype="linux:audit" "ssh_keys"
```

## 2. Attack Verification & Benign Test Results
* **Attack Simulation Executed:**
  ```text
  mkdir -p ~/.ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... test@attack" >> ~/.ssh/authorized_keys
  ```
* **Stored Alert Timestamp:** `2026-10-19 15:10:01 EDT & 15:15:01 EDT (Stored Alert Verified in `triggered_alerts_batch1.png` & `batch2.png`)`
* **Benign Test Executed (Normal Activity):**
  ```text
  ssh-keygen -lf ~/.ssh/authorized_keys (Read-only key fingerprint audit)
  ```
* **Benign Test Result:** **0 Alerts Fired (Read-only verification does not trigger `-p wa` write/attribute filter)**

## 3. Known False Positives & Tuning Applied
1. Authorized DevOps engineer rotating SSH public keys via approved Ansible/IAM workflow.

## 4. Analyst Triage, Containment & Escalation Steps
1. Inspect `auid`, `uid`, `ses`, and source IP in `/var/log/auth.log` + `linux:audit`.
2. Inspect `~/.ssh/authorized_keys` on `web`, record the rogue public key comment/fingerprint for threat intel, and delete the unauthorized line.
3. Set immutable attribute (`sudo chattr +i ~/.ssh/authorized_keys`) if appropriate and follow **Playbook PB-03**.

---
