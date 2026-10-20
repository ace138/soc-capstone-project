# Step 1.5: SOC Alert Triage Tickets

## Ticket #SOC-2026-101 — Suspicious PowerShell, Tool Transfer & Persistence Chain
* **Timestamp:** `2026-10-19 15:10:01 EDT` – `15:18:00 EDT`
* **Affected Host:** `DESKTOP-DTUQ6D4` (`192.168.120.150`)
* **Triggered Rules:** Rule 01 (`T1059.001`), Rule 02 (`T1053.005`), Rule 03 (`T1543.003`), Rule 04 (`T1003.001`), Rule 07 (`T1218.011`), Rule 08 (`T1105`)
* **Triage Determination:** **True Positive — Escalated to Incident A (`INC-2026-001`)**
* **Analyst Notes:** Correlated `EventCode=4688` process creation events show interactive PowerShell spawning `certutil.exe -urlcache`, `schtasks.exe /create /tn SOC_Test_Task`, `sc.exe create SOC_Test_Svc`, and `rundll32.exe` with `comsvcs.dll MiniDump`.

---

## Ticket #SOC-2026-102 — Brute Force Authentication & Audit Log Clearing
* **Timestamp:** `2026-10-19 15:10:01 EDT` – `15:15:01 EDT`
* **Affected Host:** `DESKTOP-DTUQ6D4` (`192.168.120.150`) & Linux Server `web` (`192.168.120.149`)
* **Triggered Rules:** Rule 05 (`T1110`), Rule 06 (`T1685.005` / `T1070.001`), Rule 09 (`T1053.003`), Rule 10 (`T1098.004`)
* **Triage Determination:** **True Positive — Escalated to Incident B (`INC-2026-002`)**
* **Analyst Notes:** Multiple `EventCode=4625` failed logons against `FakeAdmin` followed by `EventCode=4624` session establishment and `wevtutil cl Application` log clearing (`EventCode=104`). Concurrent Linux persistence modifications detected on `web`.

---

## Ticket #SOC-2026-103 — Splunk Forwarder Background PowerShell Execution
* **Timestamp:** `2026-10-19 15:20:24 EDT`
* **Affected Host:** `DESKTOP-DTUQ6D4` (`192.168.120.150`)
* **Triggered Rule:** Rule 01 (`T1059.001`)
* **Triage Determination:** **False Positive / Benign System Activity — Closed**
* **Analyst Notes:** `Creator_Process_Name` is `C:\Program Files\SplunkUniversalForwarder\bin\splunkd.exe` spawning `splunk-powershell.exe` under `SYSTEM`. Rule 01 tuned with `NOT Account_Name="SYSTEM"`.
