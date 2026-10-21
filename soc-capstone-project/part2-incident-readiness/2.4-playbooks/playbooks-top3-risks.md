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


---

# Playbook PB-02: Malicious PowerShell Execution & Ingress Tool Staging (`T1059.001` & `T1105`)
**Target Top-3 Risk:** `Risk R-02` (Malicious Script Execution & Ransomware Staging via LOLBins — Score: 20/25 Critical)  
**Triggering Part 1 Rule(s):** **Rule 01** (`Suspicious PowerShell Execution` — `T1059.001`) & **Rule 08** (`Ingress Tool Transfer` — `T1105`)  
**Organisational Severity & SLA:** **P2 — High** *(Escalates to **P1 Critical** if paired with payload execution/persistence)* | Acknowledge $\le 30\text{ min}$ | Length: **2 Pages (Max 3 Pages)** | Version: `v1.2`

---

## 1. End-to-End 8-Stage Operational Flowchart
```text
+---------------------------------------------------------------------------------------------------+
| 1. TRIGGER: Part 1 Rule 01 (PowerShell -enc/IEX) or Rule 08 (certutil -urlcache / curl) Fires     |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 2. TRIAGE (<= 5 min): Inspect EventCode=4688 / 4104 & Apache access_combined logs in Splunk       |
|    Decode Base64 command line; identify remote URI/IP and local staged file path (e.g., test.txt) |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 3. DECISIONS (<= 8 min): Is the command a verified SYSTEM forwarder script or approved dev check? |
+-----------------------+---------------------------------------------------+-----------------------+
                        | YES (Benign Admin / Incident B)                   | NO (Malicious Staging)
                        v                                                   v
+-----------------------------------------------+   +-----------------------------------------------+
| Close Ticket as P4 False Positive             |   | 4. CONTAINMENT (<= 15 min):                   |
| Add exclusion filter (NOT Account_Name=SYSTEM)|   | • Kill rogue powershell.exe / certutil.exe PID|
+-----------------------------------------------+   | • Block remote C2 IP/subnet via Host Firewall |
                                                    +-----------------------+-----------------------+
                                                                            v
+---------------------------------------------------------------------------------------------------+
| 5. EVIDENCE (<= 20 min): Compute SHA-256 hash of staged payload (test.txt), export PowerShell     |
|    ScriptBlock logs (EventCode=4104), and capture VM snapshot if P1 escalation occurred           |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 6. RECOVERY (<= 35 min): Delete staged file (Remove-Item -Force), purge Certutil URLCache,        |
|    enforce PowerShell Constrained Language Mode, and verify 0 new alerts in Splunk (15m window)   |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 7. COMMUNICATION: Escalate to Tier-2 IR Lead (or CISO if P1); notify IT Helpdesk & Clinical Staff |
|    if workstation replacement is needed (Task 2.6 Communication Plan)                             |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 8. CLOSURE: Document decoded payload, C2 URI, and SHA-256 hash in Ticket (#SOC-2026-101 / 104);   |
|    update firewall blocklist and obtain SOC Lead / CISO closure sign-off                          |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Step-by-Step Analyst Execution Checklist (Stages 1 to 8)

### Stage 1 — Trigger
* **Alert Condition:** **Rule 01 (`T1059.001`)** fires on `EventCode=4688` / `4104` containing `-enc`, `-EncodedCommand`, `IEX`, or `DownloadString`, OR **Rule 08 (`T1105`)** fires on `certutil.exe -urlcache`, `curl.exe`, or `Invoke-WebRequest`.

### Stage 2 — Triage (Target Time: `00:00 – 03:00`)
* Query Splunk for process creation and web logs across `DESKTOP-DTUQ6D4` and `web`:
  ```spl
  index=* (host="DESKTOP-DTUQ6D4" OR host="web") (EventCode=4688 OR EventCode=4104 OR sourcetype="access_combined")
  | table _time, host, sourcetype, Account_Name, Creator_Process_Name, New_Process_Name, Process_Command_Line, uri_path, status
  | sort _time
  ```
* Decode any Base64 `-EncodedCommand` string to inspect the cleartext commands.

### Stage 3 — Decisions (Target Time: `03:00 – 04:00`)
* **IF** `Account_Name="SYSTEM"` and `New_Process_Name="*splunk-powershell.exe*"` (as in **Incident B / Ticket `#SOC-2026-103`**): Classify as **P4 False Positive**, close ticket with reason, and apply tuning filter `NOT Account_Name="SYSTEM"`.
* **IF** an interactive user/admin session executed `IEX` or downloaded an external payload via `certutil -urlcache`: Classify as **P2 High** (or **P1 Critical** if chained with persistence/credential dump) and proceed to **Stage 4**.

### Stage 4 — Containment (Target Time: `04:00 – 07:00`)
1. **Terminate Active Malicious PowerShell / LOLBin Processes & Block C2 Subnet:**
   ```powershell
   Stop-Process -Name "powershell" -Force -ErrorAction SilentlyContinue
   New-NetFirewallRule -DisplayName "SOC_Contain_Outbound_C2" -Direction Outbound -Action Block -RemoteAddress 198.51.100.0/24
   ```

### Stage 5 — Evidence Preservation (Target Time: `07:00 – 10:00`)
* Hash the staged payload on disk and export PowerShell operational logs before eradication:
  ```powershell
  Get-FileHash -Algorithm SHA256 C:\Windows\System32\test.txt, C:\Windows\Temp\test.txt -ErrorAction SilentlyContinue
  wevtutil epl "Microsoft-Windows-PowerShell/Operational" C:\Forensics\PowerShell_DESKTOP-DTUQ6D4.evtx
  ```

### Stage 6 — Recovery & Eradication (Target Time: `10:00 – 13:00`)
1. **Delete Staged Payload & Clear Certutil Cache:**
   ```powershell
   Remove-Item -Path "C:\Windows\System32\test.txt", "C:\Windows\Temp\test.txt" -Force -ErrorAction SilentlyContinue
   certutil.exe -urlcache * delete
   ```
2. **Verify Clean State in Splunk:** Confirm `0 events` over a 15-minute post-remediation window (`recovery_verification_0_events.png`).

### Stage 7 — Communication & Stage 8 — Closure
* Notify Tier-2 IR Lead per **Task 2.3 Escalation Tree**; if promoted to P1, issue **P1 Staff Advisory (`Template 1`)**. Record the decoded command, C2 IP, and SHA-256 hash (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`) in the ticket and close.


---

# Playbook PB-03: Brute-Force Account Compromise & Cross-Platform Persistence (`T1110`, `T1053`, `T1098`)
**Target Top-3 Risk:** `Risk R-03` (Brute-Force Account Takeover & Persistent Backdoors on Hospital Servers — Score: 16/25 High)  
**Triggering Part 1 Rule(s):** **Rule 05** (`Brute Force Correlation` — `T1110`), **Rule 02/03** (`Windows Task/Service` — `T1053.005`/`T1543.003`), **Rule 09/10** (`Linux Cron & SSH Keys` — `T1053.003`/`T1098.004`)  
**Organisational Severity & SLA:** **P2 — High** *(Escalates to **P1 Critical** if Patient Portal `web` or EHR is breached)* | Acknowledge $\le 30\text{ min}$ | Length: **2 Pages (Max 3 Pages)** | Version: `v1.2`

---

## 1. End-to-End 8-Stage Operational Flowchart
```text
+---------------------------------------------------------------------------------------------------+
| 1. TRIGGER: Rule 05 (>=3 4625 + >=1 4624 in 10m) OR Rule 02/03/09/10 Persistence Alert Fires      |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 2. TRIAGE (<= 5 min): Inspect Account_Name, Logon_Type, Source IP on Windows (DESKTOP-DTUQ6D4)    |
|    and auditd SYSCALL/EXECVE events (key=cron_persistence / ssh_keys) on Linux server (web)       |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 3. DECISIONS (<= 8 min): Was it a legitimate user password typo / approved change window?         |
+-----------------------+---------------------------------------------------+-----------------------+
                        | YES (Verified User Typo / Change Ticket)          | NO (Confirmed Compromise)
                        v                                                   v
+-----------------------------------------------+   +-----------------------------------------------+
| Close as P4 Benign after user phone check     |   | 4. CONTAINMENT (<= 15 min):                   |
+-----------------------------------------------+   | • Disable compromised account (FakeAdmin)     |
                                                    | • Block attacker Source IP at host firewall   |
                                                    | • Lock rogue SSH session on Linux `web`       |
                                                    +-----------------------+-----------------------+
                                                                            v
+---------------------------------------------------------------------------------------------------+
| 5. EVIDENCE (<= 20 min): Preserve /var/log/audit/audit.log, /etc/crontab, ~/.ssh/authorized_keys, |
|    and Windows Security.evtx; compute SHA-256 hashes (check Rule 06 EventCode 1102/104 log clear) |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 6. RECOVERY (<= 35 min): Remove rogue Windows Task/Service (schtasks /delete, sc.exe delete);     |
|    clean Linux /etc/crontab & ~/.ssh/authorized_keys + set chattr +i; verify 0 alerts in Splunk   |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 7. COMMUNICATION: Escalate to Tier-2 IR Lead; if Patient Portal (`web`) is impacted, issue        |
|    Customer/Patient Maintenance Notification (Template 2) with CMIO/CEO approval                  |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 8. CLOSURE: Enforce 5-attempt account lockout policy + MFA; attach SHA-256 evidence table to      |
|    Ticket #SOC-2026-102 and sign off closure with SOC Lead                                        |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Step-by-Step Analyst Execution Checklist (Stages 1 to 8)

### Stage 1 — Trigger
* **Alert Condition:** **Rule 05 (`T1110` Correlation)** fires when an account records $\ge 3$ `EventCode=4625` failed logons followed by $\ge 1$ `EventCode=4624` success within 10 minutes, OR **Rules 02/03/09/10** fire on Windows task/service creation or Linux `/etc/crontab` / `~/.ssh/authorized_keys` modification.

### Stage 2 — Triage (Target Time: `00:00 – 03:30`)
* Run the cross-platform authentication and persistence triage query in Splunk:
  ```spl
  index=* (host="DESKTOP-DTUQ6D4" AND EventCode IN (4625, 4624, 4698, 7045, 1102, 104)) OR (host="web" AND sourcetype="linux:audit" ("cron_persistence" OR "ssh_keys"))
  | table _time, host, sourcetype, EventCode, Account_Name, Logon_Type, key, _raw
  | sort _time
  ```

### Stage 3 — Decisions (Target Time: `03:30 – 04:30`)
* **IF** verified user password rotation typo with zero post-logon persistence commands and an approved Linux change ticket exists: Close as **P4 Benign**.
* **IF** unrecognized `Account_Name` (`FakeAdmin`), `Logon_Type=3` (Network SMB), log clearing (`EventCode=104`/`1102`), or unapproved cron/SSH key injection: Confirm **P2 High True Positive** (promote to **P1** if Patient Portal `web` data is exposed) and proceed to **Stage 4**.

### Stage 4 — Containment (Target Time: `04:30 – 07:30`)
1. **Windows Account & Network Containment (`DESKTOP-DTUQ6D4`):**
   ```powershell
   Disable-LocalUser -Name "FakeAdmin" -ErrorAction SilentlyContinue
   New-NetFirewallRule -DisplayName "SOC_Block_BruteForce_Source" -Direction Inbound -Action Block -RemoteAddress 198.51.100.0/24
   ```
2. **Linux Session & Account Containment (`web` / `192.168.120.151`):**
   ```bash
   sudo passwd -l compromised_user ; sudo pkill -KILL -u compromised_user
   ```

### Stage 5 — Evidence Preservation (Target Time: `07:30 – 10:00`)
* Archive and hash Linux `/var/log/audit/audit.log`, `/etc/crontab`, and `~/.ssh/authorized_keys`, plus Windows `Security.evtx` (`evidence-hashes.md`):
  ```bash
  sudo tar -czf /tmp/audit_and_apache_web_20261019.tar.gz /var/log/audit/audit.log /var/log/apache2/access.log /etc/crontab
  sha256sum /tmp/audit_and_apache_web_20261019.tar.gz
  ```

### Stage 6 — Recovery & Eradication (Target Time: `10:00 – 14:00`)
1. **Remove Windows Persistence (`DESKTOP-DTUQ6D4`)** *(Note added in v1.1 after Cold Test: stop service before deleting)*:
   ```powershell
   schtasks /delete /tn "SOC_Test_Task" /f 2>$null
   Stop-Service -Name "SOC_Test_Svc" -Force -ErrorAction SilentlyContinue ; sc.exe delete "SOC_Test_Svc" 2>$null
   ```
2. **Remove Linux Cron & SSH Key Persistence (`web`):**
   ```bash
   sudo sed -i '/\/tmp\/pwn/d' /etc/crontab
   sed -i '/test@attack/d' ~/.ssh/authorized_keys
   sudo chattr +i /etc/crontab ~/.ssh/authorized_keys
   ```
3. **Verify Clean State in Splunk:** Confirm `0 events` across both `DESKTOP-DTUQ6D4` and `web` over the next 15 minutes.

### Stage 7 — Communication & Stage 8 — Closure
* Notify Tier-2 IR Lead (`Task 2.3`); if Patient Portal `web` requires downtime, issue **Customer/Patient Notification (`Template 2`)**. Document remediation in Ticket `#SOC-2026-102` and close.
