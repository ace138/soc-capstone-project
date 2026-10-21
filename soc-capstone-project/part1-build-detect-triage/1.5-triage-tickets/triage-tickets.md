# Step 1.5: SOC Alert Queue & Triage Tickets (Incidents A & B, 6-Field Escalation & 4 Member Tickets)

## 1. Compliance with Step 1.5 Mandatory Rubric Requirements
1. **Queue of 4+ Alerts:** The SOC alert queue captured **9 distinct alert batches (`ALT-001` through `ALT-009`)** across all 10 rules (`../1.2-1.3-rules/alert-screenshots/triggered_alerts_batch1.png` & `batch2.png`).
2. **Every Member Writes 1+ Ticket:** All **4 team members** authored a complete triage ticket below (`#SOC-2026-101` by Member 2, `#SOC-2026-102` by Member 3, `#SOC-2026-103` by Member 1, `#SOC-2026-104` by Member 4).
3. **Incident A (`INC-2026-001` — True Positive Multi-Stage Compromise):**
   * **Separation of Duties:** **Member 1** acted as the Red-Team attacker executing **6 techniques** (requirement: 3+ techniques) on `DESKTOP-DTUQ6D4` and **did NOT triage Incident A**.
   * **Detection, Ticket & P1–P4 Severity with Reason:** **Member 2** detected and ticketed the alert chain (`#SOC-2026-101`), assigning **Severity `P1 (Critical)`** with explicit justification mapped to the Task 2.2 Severity Matrix.
   * **6-Field Escalation Call:** Executed and logged in Section 3.1 below by **Member 2** to On-Call Incident Commander **Member 3**.
   * **Host Containment & Forensic Evidence (Snapshot, Memory, Logs) with Hashes:** **Member 3** isolated `DESKTOP-DTUQ6D4` via `SOC_Contain_Outbound_C2` (`../../part3-proof/screenshots/proof for part 3.png`), removed persistence, and preserved the **VM Snapshot, Full RAM Dump + LSASS Dump, and Raw Event Logs** with SHA-256 hashes in `evidence-hashes/evidence-hashes.md`.
4. **Incident B (`INC-2026-002` — Harmless Admin Action Closed as False Positive):**
   * **Harmless Admin Action:** **Member 2** executed routine administrative checks (`Get-Process`, `Get-Service`, and Splunk Universal Forwarder `splunk-powershell.exe` health check) which triggered Rule 01 (`T1059.001`) and Rule 02 (`T1053.005`).
   * **Closed by Another Member with Reason + Tuning Suggestion:** **Member 1** triaged Ticket `#SOC-2026-103`, verified the benign parent process (`splunkd.exe` running under `NT AUTHORITY\SYSTEM`), closed it as **False Positive (`P4`)**, and documented the exact SPL exclusion tuning suggestion (`NOT Account_Name="SYSTEM" NOT New_Process_Name="*splunk-powershell.exe*"`).

---

## 2. Master SOC Alert Queue (`ALT-001` – `ALT-009` — Requirement: 4+ Alerts)

| Alert ID | Timestamp (`EDT`) | Rule Triggered | Target Host | Initiated By (Lab Role) | Triaged By & Ticket # | Severity & Classification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **ALT-001** | `2026-10-19 15:10:01` | Rule 01: Suspicious PowerShell (`T1059.001`) | `DESKTOP-DTUQ6D4` | Member 1 *(Red Team)* | **Member 2** (`#SOC-2026-101`) | **P1 Critical** — True Positive (**Incident A**) |
| **ALT-002** | `2026-10-19 15:10:02` | Rule 02: Scheduled Task Creation (`T1053.005`) | `DESKTOP-DTUQ6D4` | Member 1 *(Red Team)* | **Member 2** (`#SOC-2026-101`) | **P1 Critical** — True Positive (**Incident A**) |
| **ALT-003** | `2026-10-19 15:10:02` | Rule 03: Windows Service Creation (`T1543.003`) | `DESKTOP-DTUQ6D4` | Member 1 *(Red Team)* | **Member 2** (`#SOC-2026-101`) | **P1 Critical** — True Positive (**Incident A**) |
| **ALT-004** | `2026-10-19 15:10:01` | Rule 04 & 07: Rundll32 & LSASS Dump (`T1003.001`) | `DESKTOP-DTUQ6D4` | Member 1 *(Red Team)* | **Member 2** (`#SOC-2026-101`) | **P1 Critical** — True Positive (**Incident A**) |
| **ALT-005** | `2026-10-19 15:10:01` | Rule 08: Ingress Tool Transfer (`T1105` `certutil`) | `DESKTOP-DTUQ6D4` | Member 1 *(Red Team)* | **Member 4** (`#SOC-2026-104`) | **P1 Critical** — Correlated w/ **Incident A** |
| **ALT-006** | `2026-10-19 15:10:02` | Rule 05: Brute Force Correlation (`T1110`) | `DESKTOP-DTUQ6D4` | Attack Simulation | **Member 3** (`#SOC-2026-102`) | **P2 High** — True Positive (Auth Attack) |
| **ALT-007** | `2026-10-19 15:10:01` | Rule 06: Clear Windows Event Logs (`T1070.001`) | `DESKTOP-DTUQ6D4` | Attack Simulation | **Member 3** (`#SOC-2026-102`) | **P2 High** — True Positive (Defense Evasion) |
| **ALT-008** | `2026-10-19 15:10:01` | Rule 09 & 10: Linux Cron & SSH Keys (`linux:audit`) | `web` (`192.168.120.151`) | Attack Simulation | **Member 3** (`#SOC-2026-102`) | **P2 High** — True Positive (Linux Persistence) |
| **ALT-009** | `2026-10-19 15:20:24` | Rule 01 & 02: Harmless Admin / UF PowerShell Check | `DESKTOP-DTUQ6D4` | Member 2 *(Admin Action)* | **Member 1** (`#SOC-2026-103`) | **P4 Low** — **False Positive (Incident B)** |

---

## 3. Individual SOC Triage Tickets (4 Tickets — 1 Written by Each Team Member)

### 3.1 Ticket `#SOC-2026-101` — Incident A (`INC-2026-001`): Multi-Stage Compromise & LSASS Credential Dump
* **Ticket Author (Triage Analyst):** **Member 2** *(SIEM Architect & Incident Commander)*
* **Responder / Forensics Support:** **Member 3** & **Member 4** *(Note: **Member 1** executed the attack simulation and was strictly excluded from triaging this incident)*
* **Correlated Alerts:** `ALT-001`, `ALT-002`, `ALT-003`, `ALT-004`, `ALT-005` (`2026-10-19 15:10:01 EDT` – `15:18:00 EDT`)
* **Affected Host:** `DESKTOP-DTUQ6D4` (`192.168.120.150` — Clinical Administrative Workstation)
* **Triggered Rules (6 Techniques — Exceeds 3+ Requirement):**
  1. **Rule 01 (`T1059.001`):** `powershell.exe -EncodedCommand ...` and `IEX` execution (`EventCode=4688`, `4104`)
  2. **Rule 08 (`T1105`):** `certutil.exe -urlcache -f http://127.0.0.1/test.txt test.txt` payload staging
  3. **Rule 02 (`T1053.005`):** `schtasks /create /tn "SOC_Test_Task" /tr "notepad.exe"` (`EventCode=4698`)
  4. **Rule 03 (`T1543.003`):** `sc.exe create "SOC_Test_Svc" binPath= "C:\Windows\System32\calc.exe"` (`EventCode=7045`)
  5. **Rule 07 (`T1218.011`):** `rundll32.exe` proxy execution
  6. **Rule 04 (`T1003.001`):** `rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Windows\Temp\lsass.dmp full`
* **Assigned Severity & Reason (P1–P4 Matrix):**
  * **Severity:** **P1 (Critical)**
  * **Reason:** Confirmed execution of 6 chained MITRE ATT&CK techniques culminating in **OS Credential Dumping of `lsass.exe` memory (`T1003.001`)** and dual persistence (`T1053.005`, `T1543.003`) on an active domain/hospital workstation. Per the Task 2.2 Severity Matrix, any active LSASS dump poses an immediate risk of lateral movement to Tier-0 Active Directory and EHR systems (Max Downtime: 15 min) and requires `< 15 min` P1 response.

#### Mandatory 6-Field Escalation Call Log (`INC-2026-001`)
| Field # | Escalation Call Field | Recorded Value During Live Escalation (`2026-10-19 15:14:30 EDT`) |
| :---: | :--- | :--- |
| **1** | **Incident ID & Call Timestamp** | `INC-2026-001` — Called at `2026-10-19 15:14:30 EDT` (4m 29s after first alert — well within 15m P1 SLA) |
| **2** | **Caller & Recipient (Roles)** | **Caller:** Member 2 (Tier-1 Triage Analyst) $ightarrow$ **Recipient:** Member 3 (On-Call Tier-2 IR Lead) & CISO |
| **3** | **Affected Host / Asset & Criticality** | `DESKTOP-DTUQ6D4` (`192.168.120.150`) — Windows 10 Clinical Admin Workstation (MTD: 4 Hours; connected to clinical VLAN) |
| **4** | **Observed Attack Summary & ATT&CK IDs** | 6-stage attack chain: Encoded PowerShell (`T1059.001`) $ightarrow$ Certutil ingress transfer (`T1105`) $ightarrow$ Scheduled Task `SOC_Test_Task` (`T1053.005`) & Service `SOC_Test_Svc` (`T1543.003`) $ightarrow$ `rundll32`/`comsvcs.dll` LSASS memory dump (`T1003.001`) |
| **5** | **Assigned Severity & Justification** | **P1 (Critical)** — Local administrator credential material exposed in `C:\Windows\Temp\lsass.dmp` with active host persistence |
| **6** | **Containment Executed & Action Requested** | **Executed:** Blocked outbound C2 (`SOC_Contain_Outbound_C2`). **Requested:** Approval for full host isolation, VM snapshot, RAM capture, and persistence eradication |

* **Containment, Evidence Preservation & Closure Summary:**
  1. **Host Contained:** Applied Windows Firewall rule `New-NetFirewallRule -DisplayName "SOC_Contain_Outbound_C2" -Direction Outbound -Action Block -RemoteAddress 198.51.100.0/24` (`../../part3-proof/screenshots/proof for part 3.png`).
  2. **Evidence Saved with SHA-256 Hashes:** Captured full VMware snapshot (`DESKTOP-DTUQ6D4_INC-2026-001_Snapshot.vmsn`), volatile RAM image (`DESKTOP-DTUQ6D4_RAM_20261019.raw`), `lsass.dmp`, staged `test.txt`, and exported `.evtx` logs (`evidence-hashes/evidence-hashes.md`).
  3. **Eradication & Clean Recovery Verified:** Deleted `SOC_Test_Task`, `SOC_Test_Svc`, `test.txt`, and `lsass.dmp`; verified `0 events` in post-recovery Splunk check (`../../part3-proof/screenshots/recovery_verification_0_events.png`).

---

### 3.2 Ticket `#SOC-2026-102` — Brute-Force Authentication, Linux Persistence & Event Log Clearing
* **Ticket Author (Triage Analyst):** **Member 3** *(Linux Telemetry, Containment & Forensics Lead)*
* **Correlated Alerts:** `ALT-006`, `ALT-007`, `ALT-008` (`2026-10-19 15:10:01 EDT` – `15:15:01 EDT`)
* **Affected Hosts:** `DESKTOP-DTUQ6D4` (`192.168.120.150`) & Linux Web Server `web` (`192.168.120.151`)
* **Triggered Rules:** Rule 05 (`T1110` Correlation), Rule 06 (`T1070.001` Clear Logs), Rule 09 (`T1053.003` Linux Cron), Rule 10 (`T1098.004` Linux SSH Keys)
* **Assigned Severity & Reason (P1–P4 Matrix):**
  * **Severity:** **P2 (High)**
  * **Reason:** Multi-attempt SMB brute force (`>=3 EventCode=4625` against `FakeAdmin` followed by `4624`), accompanied by `wevtutil cl Application` (`EventCode=104`) anti-forensics and Linux `auditd` persistence modifications (`/etc/crontab` and `~/.ssh/authorized_keys` on `web`). Categorized as **P2 High** under Task 2.2 Matrix (active single-server persistence & authentication compromise without confirmed PHI database exfiltration; SLA $\le 30$ min).
* **Containment & Eradication Taken:**
  1. Disabled targeted local account (`Disable-LocalUser -Name "FakeAdmin"`).
  2. Reverted rogue `/etc/crontab` entry and removed unauthorized `test@attack` public key from `~/.ssh/authorized_keys` on `web`, then applied `chattr +i`.
  3. Exported intact pre-clear logs from Splunk index (`audit_web_20261019.log` & `System_DESKTOP-DTUQ6D4_20261019.evtx`) and recorded SHA-256 hashes.

---

### 3.3 Ticket `#SOC-2026-103` — Incident B (`INC-2026-002`): Harmless Admin Action Closed as False Positive + Tuning Suggestion
* **Ticket Author (Triage Analyst):** **Member 1** *(Windows Endpoint & Detection Lead)*
* **Admin Action Initiated By:** **Member 2** *(Executed harmless routine admin commands `Get-Process`, `Get-Service`, and Splunk UF health check on `DESKTOP-DTUQ6D4`)*
* **Alert ID & Timestamp:** `ALT-009` — `2026-10-19 15:20:24 EDT` (Shown in `../1.4-cards-and-tuning/tuning-and-benign-tests/tuned_rule01_powershell.png`)
* **Affected Host:** `DESKTOP-DTUQ6D4` (`192.168.120.150`)
* **Triggered Rules:** Rule 01 (`T1059.001` Suspicious PowerShell) & Rule 02 (`T1053.005` Scheduled Task)
* **Assigned Severity & Triage Determination:**
  * **Severity:** **P4 (Low / Informational — Benign Administrative Activity)**
  * **Triage Determination:** **Closed as False Positive**
* **Detailed Reason for Closure:**
  * Inspection of raw `EventCode=4688` fields in Splunk revealed:
    * `Account_Name = SYSTEM` (`NT AUTHORITY\SYSTEM`)
    * `Creator_Process_Name = C:\Program Files\SplunkUniversalForwarder\bin\splunkd.exe`
    * `New_Process_Name = C:\Program Files\SplunkUniversalForwarder\bin\splunk-powershell.exe`
    * Concurrent interactive session ran read-only `Get-Process` and `schtasks /query` health checks by an authorized administrator during scheduled lab verification. No encoded payloads, network downloads, or malicious child processes were spawned.
* **Mandatory Tuning Suggestion (Implemented in Step 1.4):**
  1. **Rule 01 Tuning:** Append `NOT Account_Name="SYSTEM" NOT New_Process_Name="*splunk-powershell.exe*"` to the production SPL query and add a `filter_system_splunk` block to `rule01_T1059_001_powershell.yml`.
  2. **Rule 02 Tuning:** Append `NOT Account_Name="SYSTEM"` and restrict `schtasks.exe` matching strictly to `/create` so read-only `schtasks /query` checks and OS maintenance tasks never alert.
  * **Verification:** Post-tuning re-test confirmed **0 false-positive alerts** (`../1.4-cards-and-tuning/tuning-and-benign-tests/benign_test_zero_alerts.png`).

---

### 3.4 Ticket `#SOC-2026-104` — Ingress Tool Transfer & Web Server Probe Correlation
* **Ticket Author (Triage Analyst):** **Member 4** *(Threat Intelligence, Dashboard & Readiness Lead)*
* **Alert ID & Timestamp:** `ALT-005` — `2026-10-19 15:10:01 EDT` & `15:15:02 EDT`
* **Affected Hosts:** `DESKTOP-DTUQ6D4` (`192.168.120.150`) & Apache Web Server `web` (`192.168.120.151`)
* **Triggered Rule:** Rule 08 (`T1105` — Ingress Tool Transfer via `certutil.exe -urlcache -f`)
* **Assigned Severity & Reason (P1–P4 Matrix):**
  * **Severity:** **P2 (High)** standalone $ightarrow$ **Merged/Escalated into P1 Incident A (`INC-2026-001`)**
  * **Reason:** Cross-source correlation between Windows `EventCode=4688` (`certutil.exe -urlcache -f http://127.0.0.1/test.txt test.txt`) and 3rd-source Apache HTTP logs (`sourcetype="access_combined"`, User-Agent `"CertUtil URL Agent"`) confirmed unauthorized LOLBin payload staging during the Incident A attack window.
* **Actions Taken:**
  1. Computed SHA-256 hash of staged file `C:\Windows\System32\test.txt` (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
  2. Linked artifact to Master Incident `INC-2026-001` and removed staged payload via `Remove-Item -Path ".\test.txt" -Force` (`../../part3-proof/screenshots/proof for part 3.png`).
