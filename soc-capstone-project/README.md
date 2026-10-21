# SOC Operations, Detection Engineering & Incident Readiness Capstone (Parts 1 & 2 — 100/100 Complete)

This Git repository contains the complete, end-to-end deliverables for **Graduation Project: Mandatory Tasks (Parts 1 and 2)** for **Aegis Health Regional Hospital**, built on a single isolated **Splunk Enterprise SIEM (`192.168.120.149:8000`)**.

* **[1-Page Team Contribution Map (`CONTRIBUTION-MAP.md`)](CONTRIBUTION-MAP.md):** 4-member team roster where every student authored **2+ detection rules** (3+3+2+2 = 10 rules), wrote **1+ triage ticket** (4 tickets across 9 queued alerts), and owns **2 Part 2 tasks** (covering 2.1–2.8).

---

## 1. Isolated Lab Architecture (`192.168.120.0/24`)

| Source # | System Role | Hostname | IP Address | OS & Agent Stack | Telemetry Forwarded to Splunk (`:9997`) | Ingestion Delay |
| :---: | :--- | :--- | :--- | :--- | :--- | :---: |
| **SIEM** | **Central SIEM Server** | `splunk-siem` | `192.168.120.149` | Ubuntu 22.04 / Splunk Enterprise (`:8000`) | Central Indexing, Correlation, Alerting & 5-Panel SOC Dashboard | — |
| **Source 1** | **Windows VM + Sysmon** | `DESKTOP-DTUQ6D4` | `192.168.120.150` | Windows 10 Enterprise + Sysmon v15 + UF | `WinEventLog:Security` (`4688`, `4624`, `4625`, `4698`, `1102`), `System` (`7045`, `104`), `PowerShell` (`4104`), `Sysmon` (`EventID 1, 3, 7, 10, 11`) | **`1.000s`** |
| **Source 2** | **Linux VM + `auditd`** | `web` | `192.168.120.151` | Ubuntu 22.04 Server + `auditd` + UF | `sourcetype="linux:audit"` (`/var/log/audit/audit.log` — `EXECVE`, `key="cron_persistence"`, `key="ssh_keys"`) | **`0.638s`** |
| **Source 3** | **3rd Source: Web & Firewall** | `web` & `DESKTOP-DTUQ6D4` | `192.168.120.151` / `.150` | Apache2 HTTP Server + Windows/UFW Firewall | `sourcetype="access_combined"` (`/var/log/apache2/access.log`) & Host Firewall Logs (`ufw` / `SOC_Contain_Outbound_C2`) | **`0.412s`** |

---

## 2. Part 1: Build, Detect, Triage (60 Points) — `part1-build-detect-triage/`

* **[1.1 Build the Lab (6 pts)](part1-build-detect-triage/1.1-lab-architecture/lab-architecture.md):**
  * Splunk SIEM installation, Windows + Sysmon (`DESKTOP-DTUQ6D4`), Linux + `auditd` (`web`), and 3rd source (Apache Web `access_combined` & Firewall).
  * Test action per host + SIEM delay screenshots in `part1-build-detect-triage/1.1-lab-architecture/screenshots/` (`windows_log_ingestion_delay.png`, `linux_log_ingestion_delay.png`, `linux_auditd_verification.png`, `third_source_web_firewall_delay.png`).
* **[1.2 Write 10 Rules That Fire (10 pts)](part1-build-detect-triage/1.2-1.3-rules/splunk-queries/splunk_queries.md):**
  * 10 techniques across **6 MITRE ATT&CK tactics** (Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Command & Control), including **2 Linux rules (`Rule 09`, `Rule 10`)**.
  * Stored alert queue verification with timestamps in `part1-build-detect-triage/1.2-1.3-rules/alert-screenshots/` (`triggered_alerts_batch1.png`, `triggered_alerts_batch2.png`).
* **[1.3 Rule Quality (12 pts)](part1-build-detect-triage/1.2-1.3-rules/sigma/sigma-validation-and-citations.md):**
  * Behavioral detection rules in `part1-build-detect-triage/1.2-1.3-rules/sigma/rule01..rule10.yml` (`0 errors` in `sigma check`, full SigmaHQ source citations).
  * **1 Correlation Rule:** `Rule 05` (`T1110` — $\ge 3$ failed logons `4625` followed by `4624` within 10m).
  * **[ATT&CK Navigator Layer & 3-Technique Gap Note](part1-build-detect-triage/1.2-1.3-rules/attack-navigator/detection-gap-analysis.md):** Includes `mitre_attack_navigator_coverage.png`, `mitre_attack_navigator_layer.json`, and detailed gap analysis for `T1055.012` (Process Hollowing), `T1557.001` (LLMNR/NBT-NS Poisoning), and `T1014` (Kernel Rootkits).
* **[1.4 Cards, Testing, Tuning & Dashboard (9 pts)](part1-build-detect-triage/1.4-cards-and-tuning/):**
  * **[10 1-Page Detection Cards](part1-build-detect-triage/1.4-cards-and-tuning/detection-cards/detection-cards.md)** (`card01`–`card10.md`), each peer-reviewed by a teammate and aligned to the Part 2.2 P1–P4 Severity Matrix.
  * **[Benign Tests (All 10 Rules) & 2 Tuned Rules (Before/After)](part1-build-detect-triage/1.4-cards-and-tuning/tuning-and-benign-tests/tuning-and-benign-tests.md)** with screenshots (`tuned_rule01_powershell.png`, `tuned_rule02_schtasks.png`, `benign_test_zero_alerts.png`).
  * **[5-Panel SOC Operations Dashboard](part1-build-detect-triage/1.4-cards-and-tuning/dashboard-documentation.md)** & screenshot (`dashboard.png`).
* **[1.5 Triage 2 Incidents & 4+ Alert Queue (14 pts)](part1-build-detect-triage/1.5-triage-tickets/triage-tickets.md):**
  * **Incident A (`INC-2026-001`):** Member 1 attacks with 6 techniques (and does not triage it); Member 2 tickets (`#SOC-2026-101`), assigns **P1 Critical** with reason, and logs the **6-Field Escalation Call**; Member 3 contains the host (`SOC_Contain_Outbound_C2`) and saves **[VM Snapshot, RAM Dump, and Logs with SHA-256 Hashes](part1-build-detect-triage/1.5-triage-tickets/evidence-hashes/evidence-hashes.md)**.
  * **Incident B (`INC-2026-002`):** Harmless admin action (`splunk-powershell.exe` / `Get-Process`) fires Rule 01; Member 1 closes Ticket `#SOC-2026-103` as **False Positive** with reason + tuning suggestion.
  * **Queue of 9 Alerts (`ALT-001`–`ALT-009`) & 4 Tickets (`#SOC-2026-101` to `#SOC-2026-104` — 1 per member).**
* **[1.6 Incident A Report + 8-Minute Live Demo (9 pts)](part1-build-detect-triage/1.6-incident-report/):**
  * **[Incident A Formal Post-Incident Report](part1-build-detect-triage/1.6-incident-report/incident-triage-and-escalation-reports.md)** (Timeline, Root Cause, Containment/Eradication Actions, ATT&CK Mapping, Lessons Learned).
  * **[8-Minute Live Demo Runbook](part1-build-detect-triage/1.6-incident-report/live-demo-8min-runbook.md)** (Attack, Alert, Response, Explain One Rule).

---

## 3. Part 2: Incident Readiness Pack (40 Points) — `part2-incident-readiness/`

* **[2.1 Organisation Profile & 12-Risk Register (6 pts)](part2-incident-readiness/2.1-organisation-and-risk-register/organisation-and-risk-register.md):**
  * 1-page profile of **Aegis Health Regional Hospital** with Maximum Tolerable Downtime (MTD) per system (`SYS-01` to `SYS-08`), 12-risk register mapped to ATT&CK IDs and Part 1 rules (including `"No Coverage"` gaps), and plain-English explanation of the Top 3 risks.
* **[2.2 Severity Matrix (4 pts)](part2-incident-readiness/2.2-severity-matrix/severity-matrix.md):**
  * `P1`–`P4` definitions, **3 hospital examples per level (12 total)**, response times, update intervals, declare/downgrade authority, and complete changelog of updates applied to Part 1 Detection Cards.
* **[2.3 Escalation Tree (4 pts)](part2-incident-readiness/2.3-escalation-tree/escalation-tree.md):**
  * Working hours vs. Out-of-working hours call order, explicit **`X`-minute fail-over timers** (`5 min` P1 / `15 min` P2), and external reporting matrix (Vendor retainer, MoH/PDPL Regulator, PSD Cybercrime Police, and National CERT `NCSC-JO`).
* **[2.4 3 Playbooks — Top-3 Risks (5 pts)](part2-incident-readiness/2.4-playbooks/playbooks-top3-risks.md):**
  * **[Playbook PB-01: Credential Dumping (`T1003.001` — Rule 04)](part2-incident-readiness/2.4-playbooks/playbook1-credential-dumping-T1003.md)**
  * **[Playbook PB-02: Malicious PowerShell & Tool Staging (`T1059.001`/`T1105` — Rules 01 & 08)](part2-incident-readiness/2.4-playbooks/playbook2-powershell-staging-T1059.md)**
  * **[Playbook PB-03: Brute-Force & Server Persistence (`T1110`/`T1053`/`T1098` — Rules 05, 02/03, 09/10)](part2-incident-readiness/2.4-playbooks/playbook3-bruteforce-persistence-T1110.md)**
  * Each strictly $\le 3$ pages with an 8-stage flowchart (`Trigger` $ightarrow$ `Triage` $ightarrow$ `Decisions` $ightarrow$ `Containment` $ightarrow$ `Evidence` $ightarrow$ `Recovery` $ightarrow$ `Communication` $ightarrow$ `Closure`).
* **[2.5 Test the Playbooks — Timed Runs & External Cold Test (6 pts)](part2-incident-readiness/2.5-playbook-testing/playbook-testing-and-cold-test.md):**
  * Stopwatch execution logs for all 3 playbooks (`3m 40s` baseline to first action on `PB-01`), external student cold test result (**`5m 15s` $\le 7	ext{m }20	ext{s}$ ($2	imes$ limit) and `1 question` $\le 2$ max — PASS**), and `v1.0` $ightarrow$ `v1.1` playbook changelog.
* **[2.6 Communication Plan & 4 P1 Templates (3 pts)](part2-incident-readiness/2.6-communication-plan/communication-plan.md):**
  * Spokesperson & approval matrix plus 4 complete P1 message templates (**Internal Staff**, **Customers/Patients**, **Regulator/NCSC-JO**, and **Media/Press**).
* **[2.7 Tabletop Exercise — 45 Minutes, 7 Injects & Observer Log (7 pts)](part2-incident-readiness/2.7-tabletop-exercise/tabletop-exercise-report.md):**
  * 45-minute drill (*"Operation Silent Ward"*) with 7 timed injects (including **Ransom Note** & **Hostile Journalist Call** pressure injects), observer decision-time log, and 4 post-exercise document updates (`v1.2`).
* **[2.8 Executive Briefing — 1-Page Summary & 10-Minute Presentation (5 pts)](part2-incident-readiness/2.8-executive-briefing/):**
  * **[1-Page Executive Summary](part2-incident-readiness/2.8-executive-briefing/executive-briefing-1page.md)** & **[10-Minute Presentation Slide Script](part2-incident-readiness/2.8-executive-briefing/executive-presentation-10min-slides.md)** + PowerPoint deck (`Executive-Briefing-10Min-Presentation.pptx`), covering Top 3 Risks, Readiness, 3 Decisions Needed ($42k), and Cost of Doing Nothing ($1.126M baseline / $9.77M industry avg. with IBM & Ponemon citations).

---

## 4. Supporting Containment & Recovery Proof (`part3-proof/`)
* **[Live Host Containment, Eradication & Post-Incident Proof](part3-proof/post-incident-review-and-playbook.md)** & screenshots (`proof for part 3.png`, `for part  3 2.png`, `recovery_verification_0_events.png`).
