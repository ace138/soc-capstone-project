# Step 2.8: Executive Briefing — 1-Page Board Summary (Aegis Health Regional Hospital) (5 Points)

**Prepared For:** Chief Executive Officer (CEO), Hospital Board of Directors & Chief Medical Information Officer (CMIO)  
**Prepared By:** SOC Capstone Team (Members 1–4) | **Date:** October 2026 | **Length:** Strictly 1 Page

---

## 1. Executive Bottom Line
Aegis Health Regional Hospital operates 24/7 life-critical systems where Electronic Health Record (EHR) downtime exceeding **15 minutes** or ICU telemetry disruption exceeding **5 minutes** directly impacts patient safety. Over the past sprint, our SOC team built and validated a centralized **Splunk SIEM detection architecture (`192.168.120.149`)** with **10 behavioral detection rules**, **3 tested incident response playbooks**, and a **45-minute crisis tabletop exercise**. While our mean time to detect (`< 1 second` log ingestion) and contain (`3m 40s` to host isolation) active workstation compromises is now proven, closing three critical visibility and hardening gaps requires **three executive decisions and a $42,000 investment** today to prevent a projected **$1.13M–$9.77M breach impact**.

---

## 2. Top 3 Organisational Cyber Risks (From Task 2.1 Risk Register)
1. **Risk R-01 — Master Password Theft from Workstation Memory (`T1003.001` | Score: 20/25 Critical):** Attackers who compromise a single reception or ward Windows PC (`DESKTOP-DTUQ6D4`) can dump `lsass.exe` memory (`Rule 04`) to extract cached administrator credentials and unlock the central EHR database within minutes.
2. **Risk R-02 — Living-off-the-Land Ransomware Staging (`T1059.001` & `T1105` | Score: 20/25 Critical):** Attackers bypass traditional antivirus by abusing built-in Windows tools (`powershell.exe -EncodedCommand` and `certutil.exe -urlcache`, detected by `Rules 01 & 08`) to silently download and execute ransomware across clinical VLANs.
3. **Risk R-03 — Password Spraying & Persistent Server Backdoors (`T1110`, `T1053.003`, `T1098.004` | Score: 16/25 High):** Automated brute-force attacks (`Rule 05`) target staff accounts without Multi-Factor Authentication (MFA) and plant hidden scheduled tasks (`Rules 02/09`) or rogue SSH keys (`Rule 10`) on our Linux Patient Portal (`web`).

---

## 3. Current Readiness Posture & Remaining Visibility Gaps
* **What Is Live & Proven Today:**
  * **10 Behavioral Rules Firing in Splunk:** Covering 6 MITRE ATT&CK tactics across Windows + Sysmon (`DESKTOP-DTUQ6D4`), Linux + `auditd` (`web`), and Apache/Firewall logs with **0 false positives** post-tuning (`681` noisy `SYSTEM` events eliminated).
  * **Verified Rapid Containment:** In live Incident A (`INC-2026-001`) and external Cold Testing (`Task 2.5`), our playbooks (`PB-01`–`PB-03`) isolated outbound C2 in **`3m 40s` (Team)** and **`5m 15s` (External Cold Tester — PASS)**, well inside our **15-minute P1 SLA**.
* **3 Remaining Architectural Gaps (`Task 1.3` & `Task 2.1`):**
  1. **Memory-Only Process Hollowing (`T1055.012`):** Requires Kernel ETW / EDR memory scanning beyond standard OS logs.
  2. **Local Subnet Broadcast Poisoning (`T1557.001`):** Requires GPO hardening (disable LLMNR/NBT-NS) + a switch SPAN-port Zeek NDR sensor.
  3. **Linux Kernel Rootkits (`T1014`):** Requires UEFI Secure Boot + kernel module signature enforcement on `web`.

---

## 4. Three Executive Decisions Needed Today

| Decision # | Executive Decision Requested | Owner | Budget Required | Target Timeline | Risk Reduced |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **Decision 1** | **Mandate Enterprise GPO Hardening:** Enable Windows LSA Protection (`RunAsPPL=1`), PowerShell Constrained Language Mode, and disable LLMNR/NetBIOS across all 620 hospital PCs. | CISO & IT Ops | **$0** *(Internal GPO)* | **7 Days** | Eliminates cleartext `lsass.dmp` extraction (`R-01`) & LLMNR poisoning (`R-12`). |
| **Decision 2** | **Approve Endpoint EDR + SPAN-Port Zeek NDR Deployment:** Procure EDR memory protection for 620 endpoints + 1 open-source Zeek network sensor on the clinical core switch. | CFO & CISO | **$30,000 / yr** | **30 Days** | Closes `T1055.012` Process Hollowing & `T1557.001` lateral movement gaps. |
| **Decision 3** | **Enforce Hospital-Wide MFA + 5-Attempt Lockout & Retainer:** Require hardware/badge MFA for all admin/remote logins and fund a pre-negotiated 24/7 IR retainer + bi-annual tabletop drills. | CEO, CMIO & HR | **$12,000 / yr** | **14 Days** | Neutralizes `R-03` brute-force attacks & guarantees `<1 hr` Tier-3 forensic surge support. |

---

## 5. Cost of Doing Nothing (Financial & Clinical Impact Analysis with Sources & Assumptions)

| Cost Category | Conservative Single-Incident Estimate (Aegis Hospital) | Basis, Assumptions & Industry Sources |
| :--- | :---: | :--- |
| **1. Clinical & EHR Downtime Loss (48 Hours)** | **$696,000** | **Assumption:** 450-bed hospital experiencing a 48-hour EHR/scheduling outage at **$14,500/hour** in diverted ambulances, canceled elective procedures, and manual paper-charting overtime *(Source: Ponemon Institute / Censinet Healthcare Ransomware Benchmark: avg. $14,500–$45,000/hr for regional hospitals)*. |
| **2. Emergency Incident Response, Forensics & System Rebuilding** | **$180,000** | **Assumption:** Emergency un-retainered forensic rates ($450/hr $\times$ 250 hrs = $112,500) + re-imaging 150 clinical workstations and rebuilding AD/portal servers ($67,500). |
| **3. Regulatory Fines (PDPL / MoH) & Patient Notification (25,000 Records)** | **$250,000** | **Assumption:** Statutory PDPL / healthcare data protection penalties + credit/identity monitoring and legal notification for 25,000 affected patients at **$10/record** *(Conservative vs. **IBM Cost of a Data Breach Report 2024**: global healthcare breach average = **$9.77 Million**, or **$165–$408 per health record** in mature regulatory markets)*. |
| **Total Conservative Cost of Doing Nothing (1 Incident)** | **$1,126,000** *(vs. $9.77M Industry Avg.)* | **Return on Security Investment (ROSI):** Spending **$42,000/yr** (Decisions 1–3) avoids a **$1,126,000** baseline loss — a **26.8x return on investment** while protecting patient lives. |
