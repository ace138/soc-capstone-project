# SOC Operations, Detection Engineering & Incident Response Capstone

## 1. Executive Summary & Lab Architecture
This repository contains the end-to-end Detection Engineering, SIEM Alert Triage, Incident Escalation, and Live Host Containment deliverables for the SOC Capstone Project.

| System Role | Hostname | IP Address | Operating System | Telemetry Forwarded to Splunk (`:9997`) |
| :--- | :--- | :--- | :--- | :--- |
| **SIEM Server** | `splunk-siem` | `192.168.120.149` | Ubuntu Linux (Splunk Enterprise `:8000`) | Central Indexing, Correlation, Alerting & Dashboards |
| **Windows Endpoint** | `DESKTOP-DTUQ6D4` | `192.168.120.150` | Windows 10 Enterprise | `WinEventLog:Security` (`4688`, `4624`, `4625`, `4698`, `1102`), `System` (`7045`, `104`), `PowerShell` (`4104`) |
| **Linux Endpoint** | `web` | `192.168.120.151` | Ubuntu Linux Server | `sourcetype="linux:audit"` (`/var/log/audit/audit.log` — `cron_persistence`, `ssh_keys`) |

---

## 2. Repository Structure & Deliverables Navigation

### Part 1: Build, Detect, Tune & Dashboard (`part1-build-detect-triage/`)
* **[1.1 Lab Architecture & Log Ingestion](part1-build-detect-triage/1.1-lab-architecture/lab-architecture.md):** Verified sub-second log shipping (`0.638s` on Linux `web`, `1.0s` on Windows `DESKTOP-DTUQ6D4`) with screenshots in `1.1-lab-architecture/screenshots/`.
* **[1.2 & 1.3 Detection Rules & Alert Validation](part1-build-detect-triage/1.2-1.3-rules/splunk-queries/splunk_queries.md):**
  * **10 Custom Sigma Rules:** Located in `1.2-1.3-rules/sigma/` (`rule01` through `rule10`).
  * **MITRE ATT&CK v19 Navigator Layer:** Coverage screenshot in `1.2-1.3-rules/attack-navigator/mitre_attack_navigator_coverage.png`.
  * **Triggered Alerts Evidence:** Verified Splunk `Triggered Alerts` queue screenshots showing all 10 rules firing in `1.2-1.3-rules/alert-screenshots/`.
* **[1.4 Detection Cards, Benign Tuning & 5-Panel SOC Dashboard](part1-build-detect-triage/1.4-cards-and-tuning/):**
  * **[10 Detection Cards](part1-build-detect-triage/1.4-cards-and-tuning/detection-cards/detection-cards.md)**
  * **[Benign Testing & Rule Tuning Log](part1-build-detect-triage/1.4-cards-and-tuning/tuning-and-benign-tests/tuning-and-benign-tests.md)** (Excluding `Account_Name="SYSTEM"` noise, verified with screenshots).
  * **5-Panel SOC Operations Dashboard:** `1.4-cards-and-tuning/dashboard.png` (Pie Chart, Bar Chart, Column Chart, Area Timeline, and Logon Statistics Table).
* **[1.5 Triage Tickets & Forensic Hashes](part1-build-detect-triage/1.5-triage-tickets/triage-tickets.md)** & **[Evidence SHA-256 Hashes](part1-build-detect-triage/1.5-triage-tickets/evidence-hashes/evidence-hashes.md)**.
* **[1.6 Escalated Incident Reports](part1-build-detect-triage/1.6-incident-report/incident-triage-and-escalation-reports.md)**.

### Part 2: Incident Triage & Escalation (`part2-incident-readiness/`)
* **[Alert Queue Triage Log & Incident Reports A & B](part2-incident-readiness/incident-triage-and-escalation-reports.md):** Full reconstruction of **Incident A (`INC-2026-001`)** (PowerShell $ightarrow$ Certutil $ightarrow$ Scheduled Task/Service $ightarrow$ LSASS Dump) and **Incident B (`INC-2026-002`)** (Brute Force $ightarrow$ Linux Persistence $ightarrow$ Event Log Clearing).
* **Forensic Timeline Evidence:** `part2-incident-readiness/screenshots/for part 3.png` (`2,855` correlated events on `DESKTOP-DTUQ6D4`).

### Part 3: Containment, Eradication, Recovery & Post-Incident Review (`part3-proof/`)
* **[Post-Incident Review, Containment Log & SOP Playbook](part3-proof/post-incident-review-and-playbook.md):** Documented host isolation (`SOC_Contain_Outbound_C2`), persistence removal (`schtasks /delete`, `sc.exe delete`, `Remove-Item`), recovery verification (`0 events` in Splunk), and architectural lessons learned (NTP clock synchronization & CIM field normalization).
* **Containment & Recovery Proof Screenshots:** Located in `part3-proof/screenshots/`.
