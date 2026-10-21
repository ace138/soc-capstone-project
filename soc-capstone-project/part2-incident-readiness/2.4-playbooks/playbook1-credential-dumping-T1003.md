# Playbook PB-01: OS Credential Dumping & Privileged Account Compromise (`T1003.001`)
**Target Top-3 Risk:** `Risk R-01` (Credential Theft from Clinical Workstations — Score: 20/25 Critical)  
**Triggering Part 1 Rule(s):** **Rule 04** (`LSASS Memory Credential Dumping` — `T1003.001`) & **Rule 07** (`Rundll32 Proxy Execution` — `T1218.011`)  
**Organisational Severity & SLA:** **P1 — Critical** | Acknowledge $\le 15\text{ min}$ | First Containment $\le 15\text{ min}$ | Length: **2 Pages (Max 3 Pages)** | Version: `v1.2` *(Updated post-Cold Test 2.5 & Tabletop 2.7)*

---

## 1. End-to-End 8-Stage Operational Flowchart
```text
+---------------------------------------------------------------------------------------------------+
| 1. TRIGGER: Part 1 Rule 04 Fires in Splunk (comsvcs.dll MiniDump / lsass.exe / GrantedAccess)     |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 2. TRIAGE (<= 5 min): Query WinEventLog:Security (EventCode=4688) & Sysmon (EventID=1/10)         |
|    Inspect New_Process_Name, Process_Command_Line, Creator_Process_Name, Account_Name on host     |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 3. DECISIONS (<= 8 min): Is the process a verified signed EDR/AV sensor in an approved path?      |
+-----------------------+---------------------------------------------------+-----------------------+
                        | YES (Benign EDR Scan)                             | NO (True Positive P1)
                        v                                                   v
+-----------------------------------------------+   +-----------------------------------------------+
| Downgrade request to CISO -> Close as P4 FP   |   | 4. CONTAINMENT (<= 15 min):                   |
| Document exclusion in Detection Card 04       |   | • Block outbound C2 (SOC_Contain_Outbound_C2) |
+-----------------------------------------------+   | • Disable compromised Account_Name in AD/Local|
                                                    | • Notify Ward Supervisor if clinical terminal |
                                                    +-----------------------+-----------------------+
                                                                            v
+---------------------------------------------------------------------------------------------------+
| 5. EVIDENCE (<= 20 min): Take VM Snapshot (.vmsn), RAM Dump (winpmem .raw), export .evtx logs,    |
|    and compute SHA-256 hash of C:\Windows\Temp\lsass.dmp BEFORE deleting any files                |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 6. RECOVERY (<= 45 min): Delete lsass.dmp & rogue tasks/services; rotate all cached credentials & |
|    Kerberos krbtgt/session tickets; enable RunAsPPL=1; verify 0 alerts in Splunk for 15+ minutes  |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 7. COMMUNICATION: Execute 6-Field Call (Step 1.5/2.3) -> Issue P1 Staff Advisory (Template 1) &   |
|    NCSC-JO Notification (Template 3) with CISO + Legal + CEO sign-off                             |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 8. CLOSURE: Attach SHA-256 Evidence Register, update Ticket #SOC-2026-101, conduct Post-Incident  |
|    Review within 48 hours, and obtain CISO formal sign-off to close P1 incident                   |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Step-by-Step Analyst Execution Checklist (Stages 1 to 8)

### Stage 1 — Trigger
* **Alert Condition:** Splunk Scheduled Alert **Rule 04 (`LSASS Memory Credential Dumping`)** fires on `comsvcs.dll`, `MiniDump`, `lsass.dmp`, or Sysmon `EventID=10` (`TargetImage="*\lsass.exe"` with `GrantedAccess="0x1fffff"` / `0x143a`).

### Stage 2 — Triage (Target Time: `00:00 – 03:00`)
* Run the exact triage query in Splunk (`http://192.168.120.149:8000`) *(Note added in v1.1 after Cold Test: use raw field names `New_Process_Name` and `Process_Command_Line` alongside `CommandLine`)*:
  ```spl
  index=* sourcetype="WinEventLog:*" host="DESKTOP-DTUQ6D4" (EventCode=4688 OR EventCode=4698 OR EventCode=7045) (*lsass* OR *comsvcs* OR *MiniDump* OR *rundll32*)
  | table _time, host, Account_Name, Creator_Process_Name, New_Process_Name, Process_Command_Line
  | sort _time
  ```
* Identify: (a) Target `host` (`DESKTOP-DTUQ6D4`), (b) `Account_Name`, (c) Dump file output path (`C:\Windows\Temp\lsass.dmp`), and (d) Any accompanying persistence (`EventCode=4698` / `7045`).

### Stage 3 — Decisions (Target Time: `03:00 – 04:00`)
* **Decision Gate A (True vs. False Positive):**
  * **IF** `New_Process_Name` is a known, digitally signed EDR agent and no dump file is written to `\Temp\`: Request CISO review to downgrade to **P4 Benign**.
  * **IF** `rundll32.exe`, `procdump.exe`, `powershell.exe`, or an unknown binary accessed `lsass.exe`: **Confirm P1 Critical True Positive** and proceed immediately to **Stage 4**.
* **Decision Gate B (Clinical Impact Check — Added post-Tabletop 2.7):**
  * Check if the host is an active ICU/ER workstation (`SYS-01`/`SYS-02`). If isolating the host disrupts bedside care, notify the **Night Nursing Supervisor (`Ext. 1111`)** to switch the bay to the spare terminal before cutting LAN access.

### Stage 4 — Containment (Target Time: `04:00 – 07:00` — First Action Pass Benchmark)
1. **Isolate Host Outbound C2 Traffic (Execute via Admin PowerShell on `DESKTOP-DTUQ6D4`):**
   ```powershell
   New-NetFirewallRule -DisplayName "SOC_Contain_Outbound_C2" -Direction Outbound -Action Block -RemoteAddress 198.51.100.0/24
   Get-NetFirewallRule -DisplayName "SOC_Contain_Outbound_C2" | Select-Object DisplayName, Enabled, Direction, Action
   ```
2. **Disable Compromised / Suspicious Account:**
   ```powershell
   Disable-LocalUser -Name "<Compromised_Account_Name>" -ErrorAction SilentlyContinue
   ```

### Stage 5 — Evidence Preservation (Target Time: `07:00 – 10:00`)
* **CRITICAL RULE:** Compute SHA-256 hashes and preserve volatile evidence **BEFORE** deleting any attacker artifacts:
  1. Take VMware Host Snapshot: `DESKTOP-DTUQ6D4_INC-2026-001_Snapshot_YYYYMMDD.vmsn`.
  2. Capture RAM dump via `winpmem_mini_x64.exe DESKTOP-DTUQ6D4_RAM.raw`.
  3. Hash the credential dump file and exported logs:
     ```powershell
     wevtutil epl Security C:\Forensics\Security_DESKTOP-DTUQ6D4.evtx
     Get-FileHash -Algorithm SHA256 C:\Windows\Temp\lsass.dmp, C:\Forensics\Security_DESKTOP-DTUQ6D4.evtx
     ```

### Stage 6 — Recovery & Eradication (Target Time: `10:00 – 14:00`)
1. **Remove Credential Dump File & Any Associated Persistence:**
   ```powershell
   Remove-Item -Path "C:\Windows\Temp\lsass.dmp" -Force -ErrorAction SilentlyContinue
   schtasks /delete /tn "SOC_Test_Task" /f 2>$null
   Stop-Service -Name "SOC_Test_Svc" -Force -ErrorAction SilentlyContinue ; sc.exe delete "SOC_Test_Svc" 2>$null
   ```
2. **Harden LSASS & Rotate Credentials:** Enable LSA Protection (`reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f`) and rotate passwords for all accounts active on `DESKTOP-DTUQ6D4`.
3. **Verify Clean State in Splunk:** Run `index=* host="DESKTOP-DTUQ6D4" (*lsass* OR *comsvcs* OR EventCode=4698 OR EventCode=7045)` over `Last 15 minutes` and confirm **`0 events`** (`recovery_verification_0_events.png`).

### Stage 7 — Communication
* Complete **6-Field Escalation Call** to Tier-2 IR Lead & CISO within 15 minutes (`Task 1.5` & `Task 2.3`).
* Issue **P1 Internal Staff Advisory (`Template 1`)** and prepare **NCSC-JO / Regulator Notification (`Template 3`)** per `Task 2.6`.

### Stage 8 — Closure
* Verify all SHA-256 hashes are logged in `evidence-hashes.md`, attach recovery screenshot (`0 events`), complete Post-Incident Review (`Task 1.6`), and obtain **CISO signature** to close the P1 ticket.
