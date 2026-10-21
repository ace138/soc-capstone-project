# Step 1.4: Benign Activity Testing (All 10 Rules) & Rule Tuning Log (Before/After)

## 1. Benign Test per Rule (Normal Administrative & User Activity Across All 10 Rules)
Per **Step 1.4** (*"Benign test per rule (normal activity, show result)"*), a legitimate, non-malicious administrative or user action was executed for **each of the 10 rules** on `DESKTOP-DTUQ6D4` (`192.168.120.150`) and Linux server `web` (`192.168.120.151`).

| Rule # | Rule Name | Benign / Normal Activity Command Executed | Host | Pre-Tuning Result | Post-Tuning Result | Verification Screenshot |
| :---: | :--- | :--- | :---: | :--- | :--- | :--- |
| **Rule 01** | Suspicious PowerShell (`T1059.001`) | `powershell.exe -Command "Get-Process \| Select -First 5"` + background `splunk-powershell.exe` (`SYSTEM`) | `DESKTOP-DTUQ6D4` | **681 False-Positive Events** (`splunk-powershell.exe` under `SYSTEM`) | **0 Alerts Fired** (Excluded `SYSTEM` & `splunk-powershell.exe`) | `tuned_rule01_powershell.png` & `benign_test_zero_alerts.png` |
| **Rule 02** | Scheduled Task Creation (`T1053.005`) | `schtasks /query /fo LIST` + Windows background maintenance task registration under `SYSTEM` | `DESKTOP-DTUQ6D4` | **Noisy `SYSTEM` `EventCode=4698` triggers** | **0 False-Positive Alerts** (Only 7 true user task events remain) | `tuned_rule02_schtasks.png` & `benign_test_zero_alerts.png` |
| **Rule 03** | Windows Service Creation (`T1543.003`) | `sc.exe query EventLog` & `Get-Service \| Where-Object {$_.Status -eq "Running"}` | `DESKTOP-DTUQ6D4` | **0 Alerts Fired** | **0 Alerts Fired** (Query-only flags do not match `create`) | `benign_test_zero_alerts.png` |
| **Rule 04** | LSASS Memory Dump (`T1003.001`) | `tasklist /fi "imagename eq lsass.exe"` (Standard process health check without memory access) | `DESKTOP-DTUQ6D4` | **0 Alerts Fired** | **0 Alerts Fired** (No `comsvcs`/`MiniDump` or `0x1fffff` grant) | `benign_test_zero_alerts.png` |
| **Rule 05** | Brute Force Correlation (`T1110`) | 1 accidental password typo (`4625`) followed by normal interactive login (`4624`) | `DESKTOP-DTUQ6D4` | **0 Alerts Fired** | **0 Alerts Fired** (Correlation requires $\ge 3$ `4625` + $\ge 1$ `4624` in 10m) | `benign_test_zero_alerts.png` |
| **Rule 06** | Clear Windows Event Logs (`T1070.001`) | `wevtutil qe Application /c:5 /f:text` (Read-only query of last 5 Application events) | `DESKTOP-DTUQ6D4` | **0 Alerts Fired** | **0 Alerts Fired** (`qe` query-events does not match `cl`/`clear-log`) | `benign_test_zero_alerts.png` |
| **Rule 07** | Rundll32 Proxy Execution (`T1218.011`) | Normal Windows GUI shell operation (`explorer.exe`) without proxy export flags | `DESKTOP-DTUQ6D4` | **0 Alerts Fired** | **0 Alerts Fired** | `benign_test_zero_alerts.png` |
| **Rule 08** | Ingress Tool Transfer (`T1105`) | `certutil.exe -store My` (Local certificate store inspection without `-urlcache`) | `DESKTOP-DTUQ6D4` | **0 Alerts Fired** | **0 Alerts Fired** (Local store check does not invoke URLCache) | `benign_test_zero_alerts.png` |
| **Rule 09** | Linux Cron Persistence (`T1053.003`) | `crontab -l` and `cat /etc/crontab` (Read-only schedule verification by sysadmin) | `web` (`Linux`) | **0 Alerts Fired** | **0 Alerts Fired** (`auditd` `-p wa` only logs write/attribute changes) | `benign_test_zero_alerts.png` |
| **Rule 10** | Linux SSH Keys Mod (`T1098.004`) | `ssh-keygen -lf ~/.ssh/authorized_keys` (Read-only SSH key fingerprint audit) | `web` (`Linux`) | **0 Alerts Fired** | **0 Alerts Fired** (`auditd` `-p wa` ignores read-only checks) | `benign_test_zero_alerts.png` |

---

## 2. Rule Tuning Comparisons: 2 Tuned Rules (Before vs. After)

### 2.1 Tuned Rule 01: Suspicious PowerShell Execution (`T1059.001`)
* **Before Tuning (Initial Query):**
  ```spl
  index=* sourcetype="WinEventLog:*" (EventCode=4688 OR EventCode=4104) (*powershell* OR *IEX* OR *-enc*)
  ```
* **False Positive Observed During Benign Testing:**
  * The Splunk Universal Forwarder service (`C:\Program Files\SplunkUniversalForwarder\bin\splunkd.exe`) periodically spawns `splunk-powershell.exe` under `Account_Name="SYSTEM"`, generating **681 noisy background events** (documented in `tuned_rule01_powershell.png` and closed in Incident B Ticket `#SOC-2026-103`).
* **After Tuning (Production Query):**
  ```spl
  index=* sourcetype="WinEventLog:*" (EventCode=4688 OR EventCode=4104) (*powershell* OR *IEX* OR *-enc* OR *-EncodedCommand* OR *DownloadString*) NOT Account_Name="SYSTEM" NOT New_Process_Name="*splunk-powershell.exe*"
  ```
* **Before vs. After Result:** False-positive volume dropped from **681 events to 0 false positives** during benign activity (`benign_test_zero_alerts.png`), while still firing 100% on interactive attacker `IEX` and `-EncodedCommand` simulations.

### 2.2 Tuned Rule 02: Scheduled Task Creation (`T1053.005`)
* **Before Tuning (Initial Query):**
  ```spl
  index=* sourcetype="WinEventLog:*" (*schtasks* OR EventCode=4698)
  ```
* **False Positive Observed During Benign Testing:**
  * Windows operating system maintenance tasks registered automatically by `NT AUTHORITY\SYSTEM` triggered `EventCode=4698` alerts during routine operation.
* **After Tuning (Production Query):**
  ```spl
  index=* sourcetype="WinEventLog:*" (*schtasks* OR EventCode=4698) NOT Account_Name="SYSTEM"
  ```
* **Before vs. After Result:** Filtered out all routine OS `SYSTEM` task registrations, isolating only the **7 true-positive user-initiated task creation/deletion events** (`tuned_rule02_schtasks.png`) and yielding **0 events** during post-tuning benign verification (`benign_test_zero_alerts.png`).
