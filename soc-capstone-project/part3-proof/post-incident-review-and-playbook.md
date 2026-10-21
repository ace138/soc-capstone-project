# Part 3: Incident Response, Recovery & Post-Incident Review

## 1. Containment, Eradication, and Recovery Log
* **Affected Host:** `DESKTOP-DTUQ6D4` (`192.168.120.150`)
* **SIEM Server:** Splunk Enterprise (`192.168.120.149`)

| Phase | Action Taken | Command / Technical Method | Status |
| :--- | :--- | :--- | :--- |
| **Containment** | Isolated outbound C2 communications via host firewall | `New-NetFirewallRule -DisplayName "SOC_Contain_Outbound_C2" -Direction Outbound -Action Block` | Completed |
| **Containment** | Disabled compromised/targeted user account during brute force triage | `Disable-LocalUser -Name "TargetUser"` | Completed |
| **Eradication** | Removed unauthorized scheduled task (`T1053.005`) | `schtasks /delete /tn "SOC_Test_Task" /f` | Completed |
| **Eradication** | Deleted unauthorized Windows service (`T1543.003`) | `sc.exe delete "SOC_Test_Svc"` | Completed |
| **Eradication** | Removed staged ingress payload (`T1105`) | `Remove-Item -Path ".\test.txt" -Force` | Completed |
| **Recovery** | Re-enabled audit logging after log-clear test (`T1070.001`) and verified zero new alerts in Splunk | Verified via `sourcetype="WinEventLog:Security"` | Verified Clean |

---

## 2. Standard Operating Procedure (SOP) Response Playbook
### Playbook: Suspicious PowerShell & Persistence Triage
1. **Detect & Acknowledge:**
   * Triggered by **Rule 01** (`EventCode=4688` / `4104`) or **Rule 02/03** (`EventCode=4698` / `7045`).
2. **Validate & Scope (First 15 Minutes):**
   * Query Splunk for parent-child process relationships on `DESKTOP-DTUQ6D4`:
     `index=* sourcetype="WinEventLog:Security" EventCode=4688 host="DESKTOP-DTUQ6D4" | table _time, Account_Name, Creator_Process_Name, New_Process_Name`
   * Check if `Account_Name` is an interactive user or a routine `SYSTEM` service.
3. **Contain:**
   * If malicious encoded commands (`-enc`, `IEX`) or `comsvcs.dll` LSASS dumps are confirmed, isolate the endpoint network interface and revoke active sessions.
4. **Eradicate & Recover:**
   * Terminate the offending `New_Process_ID`, delete persistence tasks/services, rotate credentials, and monitor Splunk for 24 hours.

---

## 3. Post-Incident Review (Lessons Learned)
* **What Went Well:**
  * Windows Security Auditing (`EventCode=4688`, `4625`, `4624`) successfully captured process creation and authentication events across the Universal Forwarder pipeline.
  * Custom Sigma-to-SPL rules detected execution, persistence, credential dumping, and defense evasion techniques.
* **What Went Wrong (Root Challenges Identified):**
  * **Clock Skew / Timezone Drift:** A 7-hour timezone offset between `DESKTOP-DTUQ6D4` and the Splunk server initially prevented relative time-window alerts (`Last 15 minutes`) from firing.
  * **Index & Field Normalization:** Logs ingested into the default index under `sourcetype="WinEventLog:Security"` used `New_Process_Name` rather than standard Sigma field names (`Process_Name`), requiring query tuning.
* **Actionable Improvements (Short & Long Term):**
  * **Immediate:** Enforce NTP time synchronization across all Windows and Linux endpoints so SIEM timestamps align to UTC.
  * **Short-Term:** Deploy the Splunk Add-on for Microsoft Windows (`Splunk_TA_windows`) to normalize field names (`Image`, `CommandLine`, `User`) to the Common Information Model (CIM).
  * **Long-Term:** Enable Sysmon (`EventCode=1`, `EventCode=10`) on all Windows endpoints for granular process-access and hash telemetry.