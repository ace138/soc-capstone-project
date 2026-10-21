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
