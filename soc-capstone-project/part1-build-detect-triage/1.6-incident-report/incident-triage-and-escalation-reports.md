# Step 1.6: Incident A Post-Incident Report (`INC-2026-001`) & Triage Summary

## 1. Executive Summary — Incident A (`INC-2026-001`)
* **Incident ID:** `INC-2026-001` (Incident A)
* **Organisational Severity:** **P1 (Critical)** — Confirmed LSASS credential dumping and dual system persistence on clinical administrative workstation `DESKTOP-DTUQ6D4` (`192.168.120.150`).
* **Red Team Attacker (Did NOT Triage):** **Member 1**
* **Triage, Escalation & Response Team:** **Member 2** (Detection, Ticket `#SOC-2026-101` & 6-Field Escalation Call), **Member 3** (Containment & Forensic Evidence Hashing), **Member 4** (Timeline Reconstruction & Post-Incident Report).
* **Current Status:** Contained, Eradicated, Verified Clean (`0 events` in Splunk post-recovery), and Closed.

---

## 2. Minute-by-Minute Incident A Timeline (Attack, Detection, Escalation, Containment & Recovery)
Reconstructed from Splunk Enterprise (`192.168.120.149`) using:
```spl
index=* sourcetype="WinEventLog:*" host="DESKTOP-DTUQ6D4" (EventCode=4688 OR EventCode=4104 OR EventCode=4698 OR EventCode=7045 OR EventCode=104)
| table _time, EventCode, Account_Name, Creator_Process_Name, New_Process_Name, Process_Command_Line
| sort _time
```

| Timestamp (`2026-10-19 EDT`) | Phase | Event / Action Observed | MITRE ATT&CK / Rule | Actor / Owner |
| :--- | :--- | :--- | :--- | :--- |
| **`15:10:01.000`** | **Attack (Stage 1)** | Attacker executes `powershell.exe "IEX 'Write-Host Test'"` and `-EncodedCommand` on `DESKTOP-DTUQ6D4` (`EventCode=4688`, `4104`). | `T1059.001` (**Rule 01**) | Member 1 *(Attacker)* |
| **`15:10:01.400`** | **Attack (Stage 2)** | Attacker stages external payload via `certutil.exe -urlcache -f http://127.0.0.1/test.txt test.txt`. | `T1105` (**Rule 08**) | Member 1 *(Attacker)* |
| **`15:10:01.800`** | **Attack (Stage 3)** | Attacker dumps `lsass.exe` memory via `rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Windows\Temp\lsass.dmp full`. | `T1003.001` (**Rule 04**) & `T1218.011` (**Rule 07**) | Member 1 *(Attacker)* |
| **`15:10:02.100`** | **Attack (Stage 4)** | Attacker creates scheduled task `SOC_Test_Task` (`schtasks /create`, `EventCode=4698`) and Windows service `SOC_Test_Svc` (`sc.exe create`, `EventCode=7045`). | `T1053.005` (**Rule 02**) & `T1543.003` (**Rule 03**) | Member 1 *(Attacker)* |
| **`15:11:00.000`** | **SIEM Detection** | Scheduled Splunk alerts fire in `Triggered Alerts` queue (`triggered_alerts_batch1.png`) with `< 1s` ingestion latency. | Rules 01, 02, 03, 04, 07, 08 | Splunk SIEM (`192.168.120.149`) |
| **`15:12:15.000`** | **Triage & Ticket** | Member 2 correlates the 6 alerts on `DESKTOP-DTUQ6D4`, opens **Ticket `#SOC-2026-101`**, and classifies as **P1 (Critical)** due to active LSASS memory dump. | Playbook `PB-01` & `PB-02` | Member 2 *(Triage Lead)* |
| **`15:14:30.000`** | **Escalation** | Member 2 completes the mandatory **6-Field Escalation Call** to On-Call IR Lead (Member 3) and CISO requesting immediate host isolation and forensic capture. | Task 1.5 & 2.3 Escalation Tree | Member 2 $\rightarrow$ Member 3 |
| **`15:15:30.000`** | **Forensic Preservation** | Member 3 captures VMware Snapshot (`.vmsn`), 8 GB volatile RAM dump (`.raw`), `lsass.dmp`, `test.txt`, and `.evtx` logs, computing SHA-256 hashes (`../1.5-triage-tickets/evidence-hashes/evidence-hashes.md`). | Playbook `PB-01` Stage 5 | Member 3 *(Forensics Lead)* |
| **`15:16:20.000`** | **Containment** | Member 3 isolates `DESKTOP-DTUQ6D4` outbound C2 via `New-NetFirewallRule -DisplayName "SOC_Contain_Outbound_C2" -Direction Outbound -Action Block -RemoteAddress 198.51.100.0/24` (`../../part3-proof/screenshots/proof for part 3.png`). | Playbook `PB-01` Stage 4 | Member 3 *(Responder)* |
| **`15:17:10.000`** | **Eradication** | Member 3 deletes rogue task (`schtasks /delete /tn "SOC_Test_Task" /f`), service (`sc.exe delete "SOC_Test_Svc"`), and staged files (`Remove-Item .\test.txt, C:\Windows\Temp\lsass.dmp -Force`). | Playbook `PB-01` & `PB-03` | Member 3 *(Responder)* |
| **`15:18:22.000` – `15:33:22.000`** | **Recovery Verification** | 15-minute post-eradication monitoring window in Splunk confirms **0 new malicious events** (`../../part3-proof/screenshots/recovery_verification_0_events.png`). | Playbook `PB-01` Stage 6 | Member 2 & Member 4 |

---

## 3. Root Cause Analysis (`INC-2026-001`)
* **Primary Technical Root Cause:** An interactive administrative session on `DESKTOP-DTUQ6D4` permitted unconstrained PowerShell execution (`LanguageMode = FullLanguage`) and allowed standard Living-off-the-Land binaries (`certutil.exe`, `rundll32.exe`, `schtasks.exe`, `sc.exe`) to run without Application Control (AppLocker / WDAC) or Attack Surface Reduction (ASR) rules blocking `comsvcs.dll` from reading `lsass.exe`.
* **Architectural Contributing Factor:** Windows Defender Credential Guard and LSA Protection (`RunAsPPL = 1`) were not enforced via Group Policy on the workstation VLAN, allowing an elevated process to open a `0x1fffff` handle to `lsass.exe`.

---

## 4. MITRE ATT&CK v19 Mapping Table (`INC-2026-001`)

| Tactic | Technique ID & Name | Procedure Observed on `DESKTOP-DTUQ6D4` | Detecting Part 1 Rule | Containment / Remediation Applied |
| :--- | :--- | :--- | :--- | :--- |
| **Execution** (`TA0002`) | `T1059.001` — PowerShell | `powershell.exe "IEX ..."` & `-EncodedCommand` | **Rule 01** | Terminated shell; enforce PowerShell Constrained Language Mode & ScriptBlock logging. |
| **Command & Control** (`TA0011`) | `T1105` — Ingress Tool Transfer | `certutil.exe -urlcache -f http://127.0.0.1/test.txt test.txt` | **Rule 08** | Blocked outbound C2 (`SOC_Contain_Outbound_C2`); deleted `test.txt` after hashing. |
| **Persistence** (`TA0003`) | `T1053.005` — Scheduled Task | `schtasks /create /tn "SOC_Test_Task" /tr "notepad.exe"` | **Rule 02** | Removed via `schtasks /delete /tn "SOC_Test_Task" /f`. |
| **Persistence / PrivEsc** (`TA0003`/`TA0004`) | `T1543.003` — Windows Service | `sc.exe create "SOC_Test_Svc" binPath= "...calc.exe"` | **Rule 03** | Removed via `sc.exe delete "SOC_Test_Svc"`. |
| **Defense Evasion** (`TA0005`) | `T1218.011` — Rundll32 Proxy | `rundll32.exe` invoking `comsvcs.dll, MiniDump` | **Rule 07** | Audited DLL exports; blocked unsigned/proxy `rundll32` calls via WDAC/ASR. |
| **Credential Access** (`TA0006`) | `T1003.001` — LSASS Memory | Dumped `lsass.exe` PID to `C:\Windows\Temp\lsass.dmp` | **Rule 04** | Preserved dump hash, purged file, rotated credentials, enabled `RunAsPPL=1`. |

---

## 5. Lessons Learned (What Went Well, What Went Wrong & Actionable Improvements)
1. **What Went Well:**
   * Sub-second log forwarding (`0.638s` Linux, `1.0s` Windows, `0.412s` Web) allowed all 6 attack techniques in Incident A to trigger alerts inside Splunk within 60 seconds.
   * Real-time log shipping to `192.168.120.149:9997` preserved the complete historical audit trail even when `wevtutil cl Application` (`T1070.001`) was tested.
   * Separation of duties worked smoothly: Member 2, 3, and 4 reconstructed Member 1's entire attack chain solely from SIEM telemetry without attacker hints.
2. **What Went Wrong (Challenges Overcome):**
   * **Initial False-Positive Noise on Rule 01 & Rule 02:** Prior to tuning, `splunk-powershell.exe` running under `NT AUTHORITY\SYSTEM` generated 681 background events (`tuned_rule01_powershell.png`). Closing Incident B (`#SOC-2026-103`) and applying `NOT Account_Name="SYSTEM" NOT New_Process_Name="*splunk-powershell.exe*"` eliminated 100% of benign noise.
   * **Timezone Skew During Early Lab Setup:** A 7-hour timezone offset between `DESKTOP-DTUQ6D4` and the Splunk server initially affected relative time searches (`Last 15 minutes`) before NTP synchronization was enforced.
   * **Raw Field Names vs. CIM:** Raw `WinEventLog:Security` events use `New_Process_Name` and `Process_Command_Line` rather than Sigma's generic `Image` and `CommandLine`, which required updating Playbook `PB-01` after our Task 2.5 cold test.
3. **Actionable Security Improvements:**
   * **Immediate (Completed in Lab):** Tuned Rules 01 & 02, updated Playbooks `PB-01`–`PB-03` with exact field names, and enforced NTP clock sync across all hosts.
   * **Short-Term (30 Days):** Enable Windows LSA Protection (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1`) and Defender ASR rule `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` (Block credential stealing from LSASS).
   * **Long-Term (90 Days):** Close the 3 documented ATT&CK gaps (`T1055.012` Process Hollowing, `T1557.001` LLMNR Poisoning, `T1014` Kernel Rootkits) via kernel ETW/EDR, SPAN-port Zeek NDR, and Linux Secure Boot/IMA.
