# Team Contribution Map (1-Page Mandatory Overview)

**Project Title:** SOC Operations, Detection Engineering & Incident Readiness Capstone (Parts 1 & 2)  
**Fictional Organisation (Part 2):** Aegis Health Regional Hospital (*450-Bed Acute-Care Medical Center*)  
**SIEM & Isolated Lab Environment:** Single Splunk Enterprise SIEM (`splunk-siem` / `192.168.120.149:8000`) on Isolated Lab Subnet (`192.168.120.0/24`) receiving telemetry from Windows 10 + Sysmon (`DESKTOP-DTUQ6D4` / `192.168.120.150`), Ubuntu Linux + `auditd` (`web` / `192.168.120.151`), and Apache Web / Host Firewall Logs (3rd Source).

---

## 1. Team Roster & Mandatory Allocation Verification
Per the graduation project rubric:
* **Team Size:** 4 Members (within the mandatory 3–4 member requirement).
* **Part 1 Rule Allocation:** Every student authored **2+ detection rules** (Total = 10 rules across 6 MITRE ATT&CK tactics, including 2 Linux rules and 1 correlation rule).
* **Part 1 Triage & Ticket Allocation:** Every student authored **1+ triage ticket** across a queue of **9 triggered alerts**, maintaining strict separation of duties for **Incident A** (Member 1 executed the 3+ technique attack and did not triage it; Members 2, 3, and 4 detected, ticketed, escalated via a 6-field call, contained the host, and hashed forensic evidence) and **Incident B** (harmless admin action closed as False Positive with tuning suggestion).
* **Part 2 Task Allocation:** Every student owns **2 Part 2 tasks** (covering all 8 tasks from `2.1` to `2.8`).

| Team Member | Role | Part 1 Rules Authored (2+ Each) | Detection Cards Peer-Reviewed | Part 1 Triage, Incident Role & Ticket Written (1+ Each) | Part 2 Tasks Owned (1+ Each) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Member 1**<br>*(Student 1 — Detection Lead)* | Windows Endpoint & Detection Lead | **3 Rules:**<br>• **Rule 01:** `T1059.001` (PowerShell)<br>• **Rule 04:** `T1003.001` (LSASS Dump)<br>• **Rule 07:** `T1218.011` (Rundll32 Proxy) | Reviewed Cards **02, 03, 05** | • **Incident A Red-Team Attacker** (Executed 6 techniques on `DESKTOP-DTUQ6D4`; **did NOT triage Incident A**)<br>• **Incident B Triage Analyst:** Closed harmless admin alert as False Positive + tuning suggestion (**Ticket `#SOC-2026-103`**) | • **Task 2.1:** Organisation Profile & 12-Risk Register<br>• **Task 2.2:** P1–P4 Severity Matrix & Card Updates |
| **Member 2**<br>*(Student 2 — SIEM & Triage Lead)* | SIEM Architect & Incident Commander | **3 Rules:**<br>• **Rule 02:** `T1053.005` (Schtasks)<br>• **Rule 03:** `T1543.003` (Service Creation)<br>• **Rule 05:** `T1110` (Brute-Force Correlation) | Reviewed Cards **01, 04, 08** | • **Incident A Lead Triage Analyst:** Detected multi-stage attack, assigned **P1** with reason, and executed **6-Field Escalation Call** (**Ticket `#SOC-2026-101`**)<br>• Tuned Rules 01 & 02 (Before/After validation) | • **Task 2.3:** Working / Out-of-Hours Escalation Tree<br>• **Task 2.4:** Top-3 Risk Response Playbooks (`PB-01`–`PB-03`) |
| **Member 3**<br>*(Student 3 — Linux & Forensics Lead)* | Linux Telemetry, Containment & Forensics Lead | **2 Rules:**<br>• **Rule 09:** `T1053.003` (Linux Cron)<br>• **Rule 10:** `T1098.004` (Linux SSH Keys) | Reviewed Cards **06, 07** | • **Incident A Responder & Evidence Custodian:** Contained `DESKTOP-DTUQ6D4` (`SOC_Contain_Outbound_C2`) & preserved VM Snapshot, RAM Dump, and Event Logs with SHA-256 hashes<br>• Authored **Ticket `#SOC-2026-102`** (Brute Force & Linux Persistence) | • **Task 2.5:** Playbook Timed Execution & External Cold Test<br>• **Task 2.6:** Stakeholder Communication Plan & P1 Templates |
| **Member 4**<br>*(Student 4 — Threat Intel & Readiness Lead)* | Threat Intelligence, Dashboard & Readiness Lead | **2 Rules:**<br>• **Rule 06:** `T1070.001` (Clear Event Logs)<br>• **Rule 08:** `T1105` (Ingress Tool Transfer) | Reviewed Cards **09, 10** | • **Incident A Root-Cause Analyst & Dashboard Engineer:** Built 5-Panel SOC Dashboard, MITRE ATT&CK Navigator Layer + 3-Gap Note, and Incident A Report<br>• Authored **Ticket `#SOC-2026-104`** (Web/Certutil Tool Transfer Triage) | • **Task 2.7:** 45-Minute Tabletop Exercise (7 Injects + Observer Log)<br>• **Task 2.8:** Executive Briefing (1-Page Summary + 10-Min Deck) |

---

## 2. End-to-End Rubric Traceability Matrix (100 Points Total)

| Section | Task | Points | Primary Owner | Secondary Reviewer | Deliverable Path in Git Repository |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **Part 1** | **1.1 Build the lab** | 6 | Member 2 & Member 3 | Member 1 | `part1-build-detect-triage/1.1-lab-architecture/lab-architecture.md` |
| **Part 1** | **1.2 Write 10 rules that fire** | 10 | All 4 Members (3+3+2+2) | Member 2 | `part1-build-detect-triage/1.2-1.3-rules/splunk-queries/splunk_queries.md` |
| **Part 1** | **1.3 Rule quality (Sigma + Navigator + Gaps)** | 12 | Member 4 & Member 1 | Member 2 | `part1-build-detect-triage/1.2-1.3-rules/sigma/` & `attack-navigator/detection-gap-analysis.md` |
| **Part 1** | **1.4 Cards, testing, tuning, dashboard** | 9 | All 4 Members | Cross-Peer Reviewed | `part1-build-detect-triage/1.4-cards-and-tuning/` |
| **Part 1** | **1.5 Triage 2 incidents & 4+ Tickets** | 14 | Members 2, 3, 4 (Inc A) / Member 1 (Inc B) | All Members | `part1-build-detect-triage/1.5-triage-tickets/triage-tickets.md` & `evidence-hashes/evidence-hashes.md` |
| **Part 1** | **1.6 Report + 8-minute live demo** | 9 | Member 4 & Member 2 | All Members | `part1-build-detect-triage/1.6-incident-report/incident-triage-and-escalation-reports.md` & `live-demo-8min-runbook.md` |
| **Part 2** | **2.1 Organisation + risk register** | 6 | Member 1 | Member 4 | `part2-incident-readiness/2.1-organisation-and-risk-register/organisation-and-risk-register.md` |
| **Part 2** | **2.2 Severity matrix** | 4 | Member 1 | Member 2 | `part2-incident-readiness/2.2-severity-matrix/severity-matrix.md` |
| **Part 2** | **2.3 Escalation tree** | 4 | Member 2 | Member 3 | `part2-incident-readiness/2.3-escalation-tree/escalation-tree.md` |
| **Part 2** | **2.4 3 playbooks (Max 3 pages each)** | 5 | Member 2 | Member 3 | `part2-incident-readiness/2.4-playbooks/playbooks-top3-risks.md` |
| **Part 2** | **2.5 Test the playbooks (Timer + Cold test)** | 6 | Member 3 | Member 2 | `part2-incident-readiness/2.5-playbook-testing/playbook-testing-and-cold-test.md` |
| **Part 2** | **2.6 Communication plan (4 P1 templates)** | 3 | Member 3 | Member 4 | `part2-incident-readiness/2.6-communication-plan/communication-plan.md` |
| **Part 2** | **2.7 Tabletop exercise (45m, 6+ injects)** | 7 | Member 4 | All Members | `part2-incident-readiness/2.7-tabletop-exercise/tabletop-exercise-report.md` |
| **Part 2** | **2.8 Executive briefing (1-page + 10m deck)** | 5 | Member 4 | Member 1 | `part2-incident-readiness/2.8-executive-briefing/executive-briefing-1page.md` & `.pptx` |
