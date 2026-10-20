# Step 1.4: Benign Activity Testing & Detection Rule Tuning Log

## 1. Benign Administrative Activity Testing
To validate false-positive resilience, routine administrative commands were executed on `DESKTOP-DTUQ6D4` (`192.168.120.150`):
```powershell
Get-Process
Get-Service
ipconfig /all
```
* **Result:** Initial broad keyword rules triggered on background `SYSTEM` processes (specifically `C:\Program Files\SplunkUniversalForwarder\bin\splunk-powershell.exe` running under `Account_Name="SYSTEM"`).

## 2. Rule Tuning Comparisons (Before vs. After)

### Tuned Rule 01: Suspicious PowerShell Execution (`T1059.001`)
* **Before Tuning:**
  ```spl
  index=* sourcetype="WinEventLog:*" (EventCode=4688 OR EventCode=4104) (*powershell* OR *IEX* OR *-enc*)
  ```
* **False Positive Identified:** Routine `SYSTEM` execution of `splunk-powershell.exe` by `splunkd.exe` generated noisy events (`681 events`).
* **After Tuning (Production Query):**
  ```spl
  index=* sourcetype="WinEventLog:*" (EventCode=4688 OR EventCode=4104) (*powershell* OR *IEX* OR *-enc*) NOT Account_Name="SYSTEM" NOT New_Process_Name="*splunk-powershell.exe*"
  ```
* **Evidence Screenshot:** `tuned_rule01_powershell.png`

### Tuned Rule 02: Scheduled Task Creation (`T1053.005`)
* **Before Tuning:**
  ```spl
  index=* sourcetype="WinEventLog:*" (*schtasks* OR EventCode=4698)
  ```
* **False Positive Identified:** Windows background maintenance tasks registered by `NT AUTHORITY\SYSTEM` triggered `EventCode=4698`.
* **After Tuning (Production Query):**
  ```spl
  index=* sourcetype="WinEventLog:*" (*schtasks* OR EventCode=4698) NOT Account_Name="SYSTEM"
  ```
* **Result:** Reduced noise to only the **7 true-positive user-initiated task events** on `DESKTOP-DTUQ6D4`.
* **Evidence Screenshots:** `tuned_rule02_schtasks.png` and `benign_test_zero_alerts.png` (showing **0 false-positive events** post-tuning).
