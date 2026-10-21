# Step 2.8: 10-Minute Executive Briefing Presentation Script & Slide Breakdown

**Companion Deliverable:** `Executive-Briefing-10Min-Presentation.pptx` (Located in this folder and in project output)  
**Target Audience:** Hospital CEO, Board of Directors, CFO, CMIO, and General Counsel  
**Total Duration:** **10 Minutes** (8 Slides + 2 Minutes Board Decision Q&A)

---

## Slide-by-Slide Structure & Timed Speaker Notes (10 Minutes Total)

### Slide 1 — Cover (`00:00 – 00:45` | Presenter: Member 1)
* **Title:** Protecting Patient Care: Aegis Health Cyber Readiness & Risk Briefing
* **Subtitle:** SOC Capstone Part 2 Executive Briefing — Top Risks, Proven Readiness, Decisions Needed & Cost of Inaction
* **Speaker Notes:** *"Good morning. In the next 10 minutes, we will brief the Board on the three highest cyber risks facing Aegis Health Regional Hospital, demonstrate our current SOC readiness verified in live testing, outline the $1.13M financial and clinical cost of doing nothing, and request three concrete decisions totaling $42,000."*

### Slide 2 — Clinical Stakes & Maximum Tolerable Downtime (`00:45 – 02:00` | Presenter: Member 1)
* **Action Title:** EHR Outages Exceeding 15 Minutes Directly Threaten Patient Care
* **Key Metrics on Slide:**
  * **5 Minutes MTD:** ICU & Emergency Patient Telemetry (`SYS-01`)
  * **15 Minutes MTD:** Electronic Health Record (EHR) Core (`SYS-02`)
  * **30 Minutes MTD:** Active Directory & Staff Badge SSO (`SYS-03`)
  * **2–4 Hours MTD:** Patient Web Portal (`web`) & Clinical Workstations (`DESKTOP-DTUQ6D4`)
* **Speaker Notes:** *"As an acute-care hospital, cybersecurity is patient safety. Our Task 2.1 system profile established that while back-office billing can tolerate 24 hours of downtime, our EHR Core has a maximum tolerable downtime of just 15 minutes before clinicians must fall back to manual paper charting."*

### Slide 3 — Top 3 Cyber Risks in Plain Language (`02:00 – 03:45` | Presenter: Member 1)
* **Action Title:** Three Attack Vectors Drive 80% of Hospital Breach Exposure
* **3 Pillars:**
  1. **Master Password Theft (`R-01` / `T1003.001` — Score 20/25):** Dumping `lsass.exe` memory on one workstation (`DESKTOP-DTUQ6D4`) exposes domain admin keys to unlock the EHR.
  2. **Built-In Tool Abuse (`R-02` / `T1059.001` & `T1105` — Score 20/25):** Encoded PowerShell & `certutil` stage ransomware silently without triggering legacy antivirus.
  3. **Password Guessing & Backdoors (`R-03` / `T1110` & `T1053.003` — Score 16/25):** Brute-force logins followed by hidden Linux cron jobs or SSH keys on `web`.
* **Speaker Notes:** *"Instead of complex zero-days, attackers use three simple playbooks: stealing cached admin keys from memory on a single nursing workstation, using Windows' own PowerShell and Certutil tools to stage ransomware, and guessing passwords to plant backdoors on our patient portal."*

### Slide 4 — Current SOC Readiness: What We Built & Verified (`03:45 – 05:15` | Presenter: Member 2)
* **Action Title:** Sub-Second SIEM Alerting & 10 Behavioral Rules Are Live Today
* **Key Proof Points:**
  * **< 1.0s Ingestion Delay:** `0.638s` on Linux `web`, `1.0s` on Windows `DESKTOP-DTUQ6D4`, `0.412s` on Web/Firewall.
  * **10 Behavioral Rules Across 6 ATT&CK Tactics:** 100% Sigma-validated; **0 false positives** after tuning out `681` benign `SYSTEM` forwarder events.
  * **Live Incident A Contained in 3m 40s:** Full 6-stage attack chain detected, escalated via 6-field call, isolated via host firewall, and forensically hashed.
* **Speaker Notes:** *"The good news is our foundation works. We deployed a central Splunk SIEM monitoring Windows, Sysmon, Linux auditd, and web logs with under 1 second of delay. When we simulated a 6-stage credential-dumping attack in Incident A, our team detected, escalated, and isolated the host in 3 minutes and 40 seconds—well inside our 15-minute P1 SLA."*

### Slide 5 — Playbook Cold Test & Tabletop Exercise Findings (`05:15 – 06:45` | Presenter: Member 3)
* **Action Title:** Independent Cold Test & 45-Minute Drill Validated Our Playbooks
* **Key Proof Points:**
  * **External Cold Test PASSED (`5m 15s` vs. `7m 20s` limit):** An analyst from another team executed `Playbook PB-01` solo with only **1 question** (max 2 allowed).
  * **45-Minute Tabletop ("Operation Silent Ward"):** Tested 7 injects including a **15 BTC ransom note** and a **hostile journalist call**.
  * **4 Governance Upgrades Applied (`v1.2`):** Shortened P1 call rollover to **5 minutes**, added the **24/7 Night Nursing Supervisor (`Ext. 1111`)**, and pre-authorized a **15-minute Media Holding Statement**.
* **Speaker Notes:** *"A plan only matters if someone can run it under pressure. We handed our P1 Credential Dumping playbook to a student from another team cold—they isolated the host in 5 minutes 15 seconds with just 1 question. Our 45-minute tabletop exercise also exposed four practical gaps—such as needing faster 5-minute phone rollover and pre-approved media holding statements—which are already fixed in v1.2."*

### Slide 6 — Remaining Visibility Gaps & Cost of Doing Nothing (`06:45 – 08:30` | Presenter: Member 4)
* **Action Title:** Inaction Exposes Aegis Health to a $1.13M Baseline Incident Cost
* **Cost Breakdown (Sources: IBM 2024 Healthcare Breach Report [$9.77M avg] & Ponemon Hospital Benchmark):**
  * **$696,000:** 48 Hours of Clinical / EHR Downtime (`$14,500/hour` in ambulance diversion & canceled procedures)
  * **$180,000:** Emergency Un-Retainered Forensics (`$450/hr`) & Workstation/AD Rebuilding
  * **$250,000:** Regulatory Penalties (PDPL / MoH) & Notification for 25,000 Patients (`$10/record`)
  * **Total Baseline Single-Incident Cost:** **$1,126,000** *(vs. **$42,000** preventative cost = **26.8x ROI**)*
* **Speaker Notes:** *"Why can't we stop here? Because host logs alone cannot catch memory-only Process Hollowing (`T1055.012`), local subnet LLMNR poisoning (`T1557.001`), or kernel rootkits (`T1014`). Based on Ponemon and IBM healthcare benchmarks, a single 48-hour disruption costs a hospital of our size $1.126 million conservatively—and up to $9.77 million on average."*

### Slide 7 — Three Executive Decisions Needed Today (`08:30 – 09:45` | Presenter: Member 4)
* **Action Title:** Three Board Decisions Deliver a 26.8x Risk-Reduction Return
* **3 Decisions:**
  1. **Decision 1 ($0 — 7 Days):** Approve Enterprise GPO Hardening (`RunAsPPL=1` LSA Protection, PowerShell Constrained Mode, Disable LLMNR/NBT-NS).
  2. **Decision 2 ($30,000/yr — 30 Days):** Approve EDR Memory Protection (620 PCs) + 1 SPAN-Port Zeek NDR Sensor to close our 3 ATT&CK visibility gaps.
  3. **Decision 3 ($12,000/yr — 14 Days):** Mandate MFA + 5-Attempt Account Lockout & sign a 24/7 IR Retainer (`<1 hr` SLA).
* **Speaker Notes:** *"We need three decisions today: First, zero-dollar GPO approval from the CISO and CMIO this week to lock down LSASS memory and PowerShell. Second, $30,000 to deploy EDR memory scanning and a Zeek network sensor. Third, $12,000 for MFA and a 24/7 forensic retainer. Together, $42,000 protects $1.13M in hospital operations."*

### Slide 8 — Closing Thesis (`09:45 – 10:00` | All Members)
* **Closing Thesis:** *"Resilient cyber readiness keeps every hospital ward open and every patient safe."*
