# Part 2: Complete Incident Readiness Pack (Tasks 2.1 – 2.8 | 40 Points)

**Organisation:** Aegis Health Regional Hospital (*450-Bed Acute-Care Medical Center*)  
**SIEM & Lab Architecture:** Central Splunk Enterprise SIEM (`splunk-siem` / `192.168.120.149:8000`), Windows 10 + Sysmon (`DESKTOP-DTUQ6D4` / `192.168.120.150`), Ubuntu Linux + `auditd` (`web` / `192.168.120.151`), and Apache Web / Host Firewall Logs (3rd Source).

## Directory Structure of `part2-incident-readiness/`
* `2.1-organisation-and-risk-register/organisation-and-risk-register.md` — **Task 2.1 (6 pts):** 1-Page Hospital Profile with Max Downtime per system, 12-Risk Register mapped to ATT&CK & Part 1 rules (or `"No Coverage"`), and simple explanation of Top 3 risks.
* `2.2-severity-matrix/severity-matrix.md` — **Task 2.2 (4 pts):** P1–P4 Severity Matrix with 3 examples per level (12 total), response times, update intervals, declare/downgrade authorities, and changelog of updates applied to Part 1 Detection Cards.
* `2.3-escalation-tree/escalation-tree.md` — **Task 2.3 (4 pts):** Working vs. Out-of-Working Hours call order, explicit `X`-minute fail-over timers (`5m` P1 / `15m` P2), and External Parties (Vendor, MoH/PDPL Regulator, PSD Cybercrime Police) + National CERT (`NCSC-JO`) reporting.
* `2.4-playbooks/` — **Task 2.4 (5 pts):** 3 Playbooks (`PB-01` Credential Dumping, `PB-02` PowerShell/Staging, `PB-03` Brute-Force/Persistence), one per Top-3 risk, triggered by Part 1 rules, max 3 pages each, with 8-stage flowcharts (`Trigger` -> `Triage` -> `Decisions` -> `Containment` -> `Evidence` -> `Recovery` -> `Communication` -> `Closure`).
* `2.5-playbook-testing/playbook-testing-and-cold-test.md` — **Task 2.5 (6 pts):** Timed execution of all 3 playbooks with stopwatch splits, external student Cold Test (`5m 15s` <= `7m 20s` 2x limit, `1 question` <= 2 max — **PASS**), and `v1.0 -> v1.1` playbook changelog.
* `2.6-communication-plan/communication-plan.md` — **Task 2.6 (3 pts):** Spokesperson & approval authority matrix + 4 complete P1 message templates (Staff, Customers/Patients, Regulator/NCSC-JO, Media).
* `2.7-tabletop-exercise/tabletop-exercise-report.md` — **Task 2.7 (7 pts):** 45-minute tabletop exercise (*"Operation Silent Ward"*) with 7 injects (including Ransom Note & Hostile Journalist Call pressure injects), Observer decision-time & gap log, and 4 post-exercise document updates (`v1.2`).
* `2.8-executive-briefing/` — **Task 2.8 (5 pts):** 1-Page Executive Summary (`executive-briefing-1page.md`), 10-Minute Presentation Script (`executive-presentation-10min-slides.md`), and PowerPoint Deck (`Executive-Briefing-10Min-Presentation.pptx`) covering Top Risks, Readiness, Decisions Needed ($42k), and Cost of Doing Nothing ($1.126M baseline / $9.77M industry avg. with sources & assumptions).

---

# Step 2.1: Fictional Organisation Profile & Enterprise Risk Register (6 Points)

**Task Owner:** Member 1 *(Detection Lead)* | **Peer Reviewer:** Member 4 *(Readiness Lead)*

---

## 1. Fictional Organisation 1-Page Profile: Aegis Health Regional Hospital
* **Organisation Name & Sector:** **Aegis Health Regional Hospital ("Aegis Medical Center")** — Healthcare & Acute Emergency Services
* **Scale & Operations:** A 450-bed regional acute-care hospital and Level-1 Trauma Center operating 24/7/365 across Emergency Medicine, Intensive Care Units (ICU), Surgical Suites, Radiology (PACS), Laboratory Information Systems (LIS), Pharmacy Dispensing, and an external Patient Portal (`web`).
* **Staff & Digital Footprint:** 1,850 clinical and administrative employees; ~620 Windows 10/11 clinical workstations (represented in our lab by `DESKTOP-DTUQ6D4` / `192.168.120.150`), 45 Linux/Windows clinical & web servers (represented by `web` / `192.168.120.151`), and a central 24/7 internal Security Operations Center running Splunk Enterprise (`splunk-siem` / `192.168.120.149`).
* **Regulatory & Safety Context:** Subject to Ministry of Health (MoH) clinical safety mandates, national Personal Data Protection Law (PDPL — 72-hour breach reporting requirement for Protected Health Information [PHI]), and National Cyber Security Center (NCSC) critical infrastructure incident reporting.

### 1.1 Critical Systems Inventory & Maximum Tolerable Downtime (MTD / RTO)

| System ID | System / Asset Name | Lab / Production Host Mapping | Business & Clinical Function | Max Tolerable Downtime (MTD) | Recovery Point Objective (RPO) | Fallback / Downtime Procedure |
| :--- | :--- | :--- | :--- | :---: | :---: | :--- |
| **SYS-01** | **ICU & Emergency Patient Telemetry** | Clinical VLAN Core | Real-time bedside vitals, ventilator & cardiac alerts | **5 Minutes** | 0 min (Real-time) | Local bedside hardware alarms & manual nurse station watch |
| **SYS-02** | **Electronic Health Record (EHR) Core** | Clinical DB Cluster / AD | Patient charts, allergy checks, medication orders (eMAR) | **15 Minutes** | 5 min (Sync replica) | Read-only local downtime workstations + emergency paper charting |
| **SYS-03** | **Active Directory & Identity Core** | Tier-0 Domain Controllers | Hospital-wide staff authentication & SSO badge login | **30 Minutes** | 15 min | Cached local workstation credentials & break-glass local accounts |
| **SYS-04** | **Radiology PACS & Lab (LIS)** | Clinical Imaging & Lab Servers | CT/MRI trauma imaging & urgent blood/pathology results | **1 Hour** | 15 min | Direct modality viewing at radiology console + phone/paper lab reporting |
| **SYS-05** | **Central SIEM & Log Collector** | `splunk-siem` (`192.168.120.149`) | Real-time security alert correlation (`:9997` / `:8000`) | **1 Hour** | 15 min | Local Universal Forwarder disk buffering (`maxQueueSize`) on endpoints |
| **SYS-06** | **Patient Web Portal & Scheduling** | `web` (`192.168.120.151` — Linux) | Online appointment booking, lab results portal, HTTP API | **2 Hours** | 1 hour | Static maintenance page + telephone scheduling desk |
| **SYS-07** | **Clinical Admin Workstation Fleet** | `DESKTOP-DTUQ6D4` (`192.168.120.150`) | Nursing station & reception Windows 10 endpoints | **4 Hours** | 4 hours | Swap with pre-imaged spare workstation or failover to adjacent terminal |
| **SYS-08** | **Finance, Billing & Insurance ERP** | Back-Office ERP Server | Claims processing, payroll, and vendor invoicing | **24 Hours** | 12 hours | Deferred batch billing after clinical operations stabilize |

---

## 2. Enterprise Cyber Risk Register (12 Risks — Requirement: 10+ Risks)

Likelihood ($L$) and Impact ($I$) are scored on a **1–5 scale** ($1=	ext{Very Low}$, $5=	ext{Critical}$), yielding an Inherent Risk Score ($R = L 	imes I$, max $25$). Every risk is mapped to its **Asset**, **Scenario**, **Likelihood**, **Impact**, **Risk Owner**, **Action**, **MITRE ATT&CK ID**, and the **Part 1 Rule That Detects It (or `"No Coverage"`)**.

| Risk ID | Target Asset | Threat Scenario | Likelihood (1–5) | Impact (1–5) | Score ($L	imes I$) | Risk Owner | Mitigation / Response Action | ATT&CK ID | Part 1 Rule That Detects It |
| :---: | :--- | :--- | :---: | :---: | :---: | :--- | :--- | :---: | :--- |
| **R-01** *(Top 1)* | Clinical Admin Workstations (`DESKTOP-DTUQ6D4`) & AD | Attacker dumps `lsass.exe` memory via `rundll32`/`comsvcs.dll` to steal cached domain/EHR admin credentials and pivot to EHR Core. | **4** | **5** | **20 (Critical)** | CISO & Endpoint Lead (Member 1) | Isolate host within 15m (`PB-01`), enable LSA Protection (`RunAsPPL=1`), rotate privileged passwords. | `T1003.001` | **Rule 04** (`LSASS Memory Credential Dumping`) |
| **R-02** *(Top 2)* | Clinical Workstations (`DESKTOP-DTUQ6D4`) | Phishing macro or rogue admin session invokes encoded PowerShell (`-enc` / `IEX`) and `certutil.exe` to stage ransomware/backdoor payloads. | **5** | **4** | **20 (Critical)** | SOC Lead & IT Ops (Member 1 & 4) | Block outbound C2 (`PB-02`), enforce PowerShell Constrained Language Mode & AppLocker. | `T1059.001` & `T1105` | **Rule 01** (`Suspicious PowerShell`) & **Rule 08** (`Ingress Tool Transfer`) |
| **R-03** *(Top 3)* | Patient Portal (`web`) & Workstations (`DESKTOP-DTUQ6D4`) | Password-spraying / SMB brute force compromises staff account (`FakeAdmin`), followed by Linux `/etc/crontab` or SSH `authorized_keys` backdoor persistence. | **4** | **4** | **16 (High)** | IAM & Linux Lead (Member 2 & 3) | Lock compromised user (`PB-03`), enforce 5-attempt lockout + MFA, revert `/etc/crontab` & `~/.ssh/authorized_keys` (`chattr +i`). | `T1110`, `T1053.003`, `T1098.004` | **Rule 05** (`Brute Force Correlation`), **Rule 09** (`Linux Cron`) & **Rule 10** (`Linux SSH Keys`) |
| **R-04** | Clinical Admin Workstations (`DESKTOP-DTUQ6D4`) | Attacker registers a malicious Windows Scheduled Task (`schtasks /create`) to survive reboots and re-launch C2 beacons on clinical terminals. | **4** | **3** | **12 (High)** | Windows Systems Admin (Member 2) | Delete rogue scheduled task (`schtasks /delete`), restrict task creation to signed GPO scripts. | `T1053.005` | **Rule 02** (`Scheduled Task Creation`) |
| **R-05** | Clinical Workstations & Windows Servers | Attacker installs a rogue Windows Service (`sc.exe create` / `EventCode=7045`) running as `LocalSystem` for privilege escalation and persistence. | **3** | **4** | **12 (High)** | Windows Systems Admin (Member 2) | Stop and delete rogue service (`sc.exe delete`), audit service binary signatures (`PB-03`). | `T1543.003` | **Rule 03** (`New Windows Service Created`) |
| **R-06** | Windows Endpoints (`DESKTOP-DTUQ6D4`) & SIEM Trail | Attacker executes `wevtutil cl Security/Application` (`EventCode=1102`/`104`) to erase local forensic evidence after privilege escalation. | **3** | **4** | **12 (High)** | SIEM Architect (Member 4) | Forward all logs in real time (`<1s` delay) to immutable Splunk server (`192.168.120.149`); treat log clear as high-priority incident. | `T1070.001` (`/ T1685.005`) | **Rule 06** (`Clearing Windows Event Logs`) |
| **R-07** | Clinical Admin Workstations (`DESKTOP-DTUQ6D4`) | Attacker abuses signed `rundll32.exe` (`Control_RunDLL` / `javascript:` / temp DLLs) to bypass basic application whitelisting controls. | **3** | **3** | **9 (Medium)** | Endpoint Security Lead (Member 1) | Monitor `rundll32` CLI exports; enforce Windows Defender Application Control (WDAC) DLL rules. | `T1218.011` | **Rule 07** (`Rundll32 Proxy Execution`) |
| **R-08** | Patient Web Portal (`web` / `192.168.120.151`) | External attacker uses compromised workstation as a staging pivot to host or fetch secondary payloads over HTTP (`CertUtil URL Agent`). | **3** | **3** | **9 (Medium)** | Network & Web Lead (Member 4) | Correlate Apache `access_combined` logs with endpoint process creation; isolate outbound C2 subnets. | `T1105` | **Rule 08** (`Ingress Tool Transfer`) |
| **R-09** | Linux Patient Portal (`web`) | Compromised web application or root session injects reverse shell into `/etc/crontab` or `/var/spool/cron` to maintain root access. | **3** | **4** | **12 (High)** | Linux Systems Lead (Member 3) | Monitor `auditd` `key=cron_persistence`; restrict cron access via `/etc/cron.allow`. | `T1053.003` | **Rule 09** (`Linux Cron Job Persistence`) |
| **R-10** | Linux Patient Portal (`web`) | Attacker appends unauthorized SSH public key to `/root/.ssh/authorized_keys` to bypass password/MFA authentication permanently. | **3** | **4** | **12 (High)** | Linux Systems Lead (Member 3) | Monitor `auditd` `key=ssh_keys`; set `chattr +i` on `authorized_keys` and centralize SSH CA keys. | `T1098.004` | **Rule 10** (`Linux SSH Authorized Keys Mod`) |
| **R-11** | EHR Core & Clinical Workstations | Fileless malware spawns benign `svchost.exe` in suspended mode and hollow-injects ransomware payload in memory without touching disk. | **2** | **5** | **10 (High)** | CISO & Threat Intel Lead (Member 4) | **Current SIEM Gap (See Step 1.3 Gap 1):** Deploy kernel ETW (`Threat-Intelligence`) & EDR memory integrity scanning. | `T1055.012` | **`No Coverage`** *(Documented in Step 1.3 Gap Note)* |
| **R-12** | Clinical VLAN (`192.168.120.0/24`) | Rogue device on clinical subnet performs LLMNR/NBT-NS broadcast poisoning (`Responder`) to capture NetNTLMv2 hashes in transit. | **3** | **4** | **12 (High)** | Network Security Lead (Member 3) | **Current SIEM Gap (See Step 1.3 Gap 2):** Disable LLMNR/NetBIOS-NS via GPO and deploy SPAN-port Zeek NDR sensor. | `T1557.001` | **`No Coverage`** *(Documented in Step 1.3 Gap Note)* |

---

## 3. Simple, Plain-English Explanation of the Top 3 Risks (For Hospital Leadership)

1. **Top Risk #1 — Stealing Master Passwords from Computer Memory (`R-01` / `T1003.001` — Detected by Rule 04):**
   * **What it means in plain English:** When IT staff or senior clinicians log into a hospital Windows workstation (`DESKTOP-DTUQ6D4`), Windows keeps a digital copy of their login keys in a protected memory vault called `LSASS`. If an attacker gets onto just *one* reception or nursing computer, they use a built-in Windows tool (`rundll32`) to take a snapshot of that memory vault (`lsass.dmp`). With those stolen keys, the attacker can impersonate a hospital administrator and unlock the central Electronic Health Record (EHR) system within minutes—without ever needing to guess a password.
2. **Top Risk #2 — Using Built-in Hospital Tools to Silently Download & Launch Attacks (`R-02` / `T1059.001` & `T1105` — Detected by Rules 01 & 08):**
   * **What it means in plain English:** Modern attackers rarely bring obvious "virus" files that traditional antivirus software blocks immediately. Instead, after a staff member clicks a phishing link, the attacker uses Microsoft's own built-in administration tools—**PowerShell** (to run scrambled, hidden commands in memory) and **Certutil** (to download malicious files disguised as routine certificate updates). Because these tools are pre-installed on every Windows PC, they blend in unless the SOC actively watches *how* they are used.
3. **Top Risk #3 — Guessing Staff Passwords & Planting Hidden Backdoors (`R-03` / `T1110`, `T1053.003`, `T1098.004` — Detected by Rules 05, 09 & 10):**
   * **What it means in plain English:** Attackers use automated scripts to rapidly try common or leaked passwords against hospital accounts (`Brute Force`). Once one password works, their first move is to plant a "spare key" so they don't get locked out when the staff member changes their password—either by scheduling an automatic hidden task (`Cron` / `Scheduled Task`) or by adding their own digital master key (`SSH Key`) to our Linux patient portal (`web`).

---

# Step 2.2: Organisational Severity Matrix (P1–P4) & Part 1 Detection Card Updates (4 Points)

**Task Owner:** Member 1 *(Detection Lead)* | **Peer Reviewer:** Member 2 *(SIEM Architect)*

---

## 1. Aegis Health Regional Hospital Incident Severity Matrix (`P1` – `P4`)
Per **Step 2.2**, the matrix below defines **P1 through P4** for Aegis Health Regional Hospital, including **3 concrete examples per severity level (12 examples total)**, **SLA Response Times**, **Stakeholder Update Intervals**, and **Who Can Declare / Who Can Downgrade**.

| Severity Level | Operational & Clinical Impact Definition | 3 Concrete Organisational Examples (12 Total) | Max Response Time (Acknowledge & Triage) | Mandatory Update Interval | Who Can Declare | Who Can Downgrade |
| :--- | :--- | :--- | :---: | :---: | :--- | :--- |
| **P1 — Critical**<br>*(Life-Safety / Enterprise Breach)* | Immediate threat to patient safety, clinical system availability (EHR/ICU/PACS approaching MTD), active domain/LSASS credential theft, or confirmed PHI data exfiltration/ransomware. | **1.** LSASS memory credential dumping (`T1003.001` / Rule 04) on any hospital endpoint (`DESKTOP-DTUQ6D4`).<br>**2.** Multi-stage attack chain combining encoded PowerShell, payload staging, and persistence (`Incident A`).<br>**3.** Ransomware encryption or outage affecting EHR Core (`SYS-02`) or ICU Telemetry (`SYS-01`). | **$\le 15$ Minutes** (24/7 Immediate Voice Call) | **Every 30 Minutes** | Any SOC Analyst (Tier 1/2), IR Lead, CISO, or Clinical Supervisor | **CISO or Designated Incident Commander ONLY** (requires written root-cause proof) |
| **P2 — High**<br>*(Single-Host Compromise / Active Attack)* | Confirmed malicious activity, persistence, brute-force account takeover, or anti-forensic log clearing on a single workstation or non-life-safety server (`web`) with containment required. | **4.** Successful Brute-Force logon ($\ge 3$ `4625` $
ightarrow$ `4624`, Rule 05 `T1110`) on `DESKTOP-DTUQ6D4`.<br>**5.** Unauthorized Linux `/etc/crontab` (`Rule 09`) or `~/.ssh/authorized_keys` (`Rule 10`) modification on Patient Portal `web`.<br>**6.** Windows Event Log clearing (`wevtutil cl` / `EventCode=1102`/`104`, Rule 06) or unauthorized Scheduled Task / Service creation (`Rule 02`/`03`). | **$\le 30$ Minutes** | **Every 2 Hours** | Any Tier-1 or Tier-2 SOC Analyst | **SOC Lead / Tier-2 IR Manager or CISO** |
| **P3 — Medium**<br>*(Suspicious Activity / Policy Violation)* | Isolated suspicious LOLBin execution, anomalous outbound web utility usage, or unapproved admin tool invocation with no evidence of credential theft or persistence. | **7.** Isolated `rundll32.exe` proxy execution (`Rule 07`) invoking a local Control Panel applet (`Control_RunDLL`) without child payloads.<br>**8.** Developer or sysadmin running `curl.exe` (`Rule 08`) to fetch an unverified package from an external HTTP URL.<br>**9.** Repeated failed logons (`EventCode=4625`) from an internal clinic badge kiosk with **zero** subsequent successful logon (`4624`). | **$\le 2$ Hours** | **Every 8 Hours (Once per Shift)** | Any Tier-1 SOC Analyst | **Tier-2 SOC Analyst or SOC Lead** |
| **P4 — Low**<br>*(Benign Admin / Informational / False Positive)* | Verified benign administrative activity, background service helper scripts, or routine maintenance that triggered a broad detection signature (`Incident B`). | **10.** Splunk Universal Forwarder (`splunkd.exe`) spawning `splunk-powershell.exe` under `NT AUTHORITY\SYSTEM` (`Incident B` / Ticket `#SOC-2026-103`).<br>**11.** Windows Update registering a routine background maintenance task under `SYSTEM` (`EventCode=4698`).<br>**12.** Authorized Linux sysadmin running read-only `crontab -l` or `wevtutil qe` health checks during an approved change window. | **$\le 24$ Hours** (Next Business Day / Shift Queue) | **Upon Ticket Closure Only** | Any Tier-1 SOC Analyst | **Any Tier-1 SOC Analyst** (with mandatory reason + tuning suggestion in ticket) |

---

## 2. Part 1 Detection Cards Update & Complete Changelog (`v1.0` $
ightarrow$ `v1.2`)
Per **Step 2.2** (*"Update the Part 1 cards to match and list the changes"*), all 10 Detection Cards in `../../part1-build-detect-triage/1.4-cards-and-tuning/detection-cards/detection-cards.md` (and `card01`–`card10`) were updated to replace generic Sigma severities (`Critical`/`High`/`Medium`) with our **Aegis Health P1–P4 Severity Matrix**, SLA response timers, escalation rules, and playbook references:

| Card # | Rule Name | Previous Card Severity (`v1.0`) | Updated Card Severity (`v1.2`) | Exact Changes Applied to Part 1 Detection Card |
| :---: | :--- | :---: | :---: | :--- |
| **Card 01** | Suspicious PowerShell Execution (`T1059.001`) | `High` | **`P2 — High`** *(Auto-escalates to `P1` if paired w/ Rule 04/02/03)* | Replaced generic `High` with `P2` ($\le 30	ext{m}$ SLA, 2h updates); added auto-escalation clause to `P1` ($\le 15	ext{m}$) when correlated with credential access; added `PB-02` playbook link and `P4` downgrade rule for `SYSTEM` forwarder noise. |
| **Card 02** | Scheduled Task Creation (`T1053.005`) | `Medium` | **`P2 — High`** | Upgraded from `Medium` to `P2 — High` ($\le 30	ext{m}$ SLA) because interactive `/create` task persistence on a hospital endpoint indicates active post-exploitation; linked to `PB-03` and SOC Lead downgrade rule. |
| **Card 03** | Windows Service Creation (`T1543.003`) | `Medium` | **`P2 — High`** | Upgraded from `Medium` to `P2 — High` ($\le 30	ext{m}$ SLA) due to `LocalSystem` privilege escalation impact (`EventCode=7045`); added change-window verification step and `PB-03` reference. |
| **Card 04** | LSASS Memory Credential Dumping (`T1003.001`) | `Critical` | **`P1 — Critical`** | Mapped to **`P1 — Critical`** ($\le 15	ext{m}$ response SLA, 30m updates); locked downgrade authority strictly to **CISO / Incident Commander**; linked directly to `PB-01` and 6-field escalation call. |
| **Card 05** | Brute Force Followed by Success (`T1110`) | `High` | **`P2 — High`** | Mapped to **`P2 — High`** ($\le 30	ext{m}$ SLA, 2h updates); added post-logon `EventCode=4688` inspection step and `PB-03` account lockout procedure. |
| **Card 06** | Clearing Windows Event Logs (`T1070.001`) | `High` | **`P2 — High`** *(`P1` if active IR)* | Mapped to **`P2 — High`** ($\le 30	ext{m}$ SLA); added instruction to query the 30 minutes of pre-clear telemetry stored in Splunk (`192.168.120.149`). |
| **Card 07** | Rundll32 Proxy Execution (`T1218.011`) | `Medium` | **`P3 — Medium`** *(`P1` if `comsvcs.dll`)* | Assigned base severity **`P3 — Medium`** ($\le 2	ext{h}$ SLA) for standalone proxy calls (`Control_RunDLL`), with mandatory immediate promotion to **`P1 — Critical`** ($\le 15	ext{m}$ SLA) if `comsvcs.dll MiniDump` is present. |
| **Card 08** | Ingress Tool Transfer (`T1105`) | `Medium` | **`P2 — High`** *(`P3` if dev `curl`)* | Upgraded `certutil -urlcache` triggers to **`P2 — High`** ($\le 30	ext{m}$ SLA) linked to `PB-02`; added **`P3`** classification for verified developer `curl` checks. |
| **Card 09** | Linux Cron Job Persistence (`T1053.003`) | `Medium` | **`P2 — High`** | Upgraded from `Medium` to **`P2 — High`** ($\le 30	ext{m}$ SLA) because `web` (`192.168.120.151`) hosts the hospital Patient Portal (MTD: 2 Hours); linked to `PB-03`. |
| **Card 10** | Linux SSH Authorized Keys Mod (`T1098.004`) | `High` | **`P2 — High`** | Mapped to **`P2 — High`** ($\le 30	ext{m}$ SLA, 2h updates); added `chattr +i` recovery step and `PB-03` link. |

---

# Step 2.3: Internal & External Incident Escalation Tree (Working vs. Out-of-Working Hours) (4 Points)

**Task Owner:** Member 2 *(SIEM Architect & Incident Commander)* | **Peer Reviewer:** Member 3 *(Forensics Lead)*  
**Document Version:** `v1.2` *(Updated post-Tabletop Exercise Task 2.7 to include Clinical Night Supervisor & Deputy CISO 5-minute P1 rollover)*

---

## 1. Escalation Decision Flowchart (Working Hours vs. Out-of-Working Hours & Fail-Over Timers)

```text
                       +---------------------------------------------------+
                       |   SIEM Alert Fires in Splunk (192.168.120.149)    |
                       |   Tier-1 Duty Analyst Triages & Assigns P1 - P4   |
                       +-------------------------+-------------------------+
                                                 |
                  +------------------------------+------------------------------+
                  |                                                             |
                  v                                                             v
   [WORKING HOURS: Sun-Thu 08:00-17:00]                         [OUT-OF-HOURS: 17:00-08:00, Fri-Sat, Holidays]
                  |                                                             |
   1. Call Tier-2 IR Lead (Member 3)                            1. Page + Call On-Call IR Lead (Member 3)
      (P1 SLA: <= 15m | P2 SLA: <= 30m)                            via PagerDuty + Direct Mobile
                  |                                                             |
      No Answer within 5 min (P1) / 15 min (P2)?                   No Answer within 5 min (P1) / 15 min (P2)?
                  |                                                             |
                  v                                                             v
   2. Fail-Over #1: Call SIEM Architect /                       2. Fail-Over #1: Call Backup On-Call IR Lead
      Deputy IR Lead (Member 2)                                    (Member 2) + Automated SMS Blast
                  |                                                             |
      No Answer within +5 min (P1) / +15 min (P2)?                 No Answer within +5 min (P1) / +15 min (P2)?
                  |                                                             |
                  +------------------------------+------------------------------+
                                                 |
                                                 v
                       +---------------------------------------------------+
                       | 3. Fail-Over #2 (T+10m P1 / T+30m P2):            |
                       |    Call CISO (Dr. Tariq Al-Mansoor)               |
                       |    --> If no answer in 5 min: Call Deputy CISO    |
                       +-------------------------+-------------------------+
                                                 |
                       +-------------------------+-------------------------+
                       | (If P1 Affects Clinical Ops / EHR / Patient Care) |
                       v                                                   v
        +------------------------------------+             +------------------------------------+
        | 4A. Internal Executive & Clinical: |             | 4B. External Parties & National:   |
        | • Chief Medical Info Officer (CMIO)|             | • Managed EDR/IR Retainer (< 1 hr) |
        | • Night Nursing Supervisor (OOH)   |             | • NCSC-JO National CERT (< 12-24h) |
        | • Hospital CEO & General Counsel   |             | • MoH & PDPL Regulator (< 72 hrs)  |
        | • Corporate Comms Director         |             | • PSD Cybercrime Police Unit       |
        +------------------------------------+             +------------------------------------+
```

---

## 2. Internal Call Order & Explicit Fail-Over Matrix ("If No Answer Within X Minutes, Who Is Next")

### 2.1 Working Hours (`Sunday – Thursday, 08:00 – 17:00 Local Time`)

| Call Step | Role & Designated Contact | Contact Channel | Trigger Severity | Max Wait Time (`X` Minutes) Before Next Contact | Who Is Next If No Answer Within `X` Minutes |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **Step 1** | **Tier-1 SOC Analyst on Shift** *(Member 2 / Member 4)* | SOC Console (`:8000`) & Internal Ext. `4101` | `P1` – `P4` | Immediate Triage ($\le 5	ext{m}$ for P1) | Escalates using 6-Field Call to **Step 2 (Tier-2 IR Lead)** |
| **Step 2** | **Tier-2 Incident Response Lead** *(Member 3)* | SOC War Room Ext. `4102` + Mobile `+962-79-555-0103` | `P1`, `P2` | **P1: `5 Minutes`**<br>**P2: `15 Minutes`** | Roll over immediately to **Step 3 (Deputy IR Lead / SIEM Architect — Member 2)** |
| **Step 3** | **Deputy IR Lead / SIEM Architect** *(Member 2)* | Ext. `4103` + Mobile `+962-79-555-0102` | `P1`, `P2` (Fail-over) | **P1: `5 Minutes`**<br>**P2: `15 Minutes`** | Roll over immediately to **Step 4 (CISO)** |
| **Step 4** | **Chief Information Security Officer (CISO)** *(Dr. Tariq Al-Mansoor)* | Direct Ext. `4001` + Mobile `+962-79-555-0100` | All `P1` (Mandatory) & Unanswered `P2` | **P1: `5 Minutes`**<br>**P2: `15 Minutes`** | Roll over to **Step 5 (Deputy CISO / VP of IT Infrastructure)** |
| **Step 5** | **Deputy CISO & Chief Medical Information Officer (CMIO)** *(Dr. Layla Haddad)* | Ext. `4002` / Clinical Bridge `+962-79-555-0110` | `P1` (Clinical Impact / CISO Fail-over) | **P1: `5 Minutes`** | Roll over to **Step 6 (Hospital CEO & General Counsel)** |
| **Step 6** | **Hospital CEO, General Counsel & Crisis Management Team (CMT)** | Executive Bridge `Ext. 4000` | `P1` (Ransomware, Extortion, PHI Breach, Media Call) | **P1: `10 Minutes`** | Chief Operating Officer (COO) assumes Acting Crisis Commander authority |

### 2.2 Out-of-Working Hours (`17:00 – 08:00 Overnight, Fridays, Saturdays & Public Holidays`)

| Call Step | On-Call Role & Designated Contact | Out-of-Hours Contact Method | Trigger Severity | Max Wait Time (`X` Minutes) Before Next Contact | Who Is Next If No Answer Within `X` Minutes |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **Step 1** | **On-Call Duty SOC Analyst** *(Rotating Shift)* | PagerDuty High-Urgency Push + Phone | `P1` – `P3` | **P1: `5 Minutes`** | Auto-pages **Primary On-Call IR Lead (Step 2)** |
| **Step 2** | **Primary On-Call IR Lead** *(Member 3)* | Two consecutive voice calls + PagerDuty SMS (`+962-79-555-0103`) | `P1`, `P2` | **P1: `5 Minutes`**<br>**P2: `15 Minutes`** | PagerDuty auto-escalates to **Secondary Backup On-Call IR Lead (Member 2 — Step 3)** |
| **Step 3** | **Secondary Backup On-Call IR Lead** *(Member 2)* | Voice Call + WhatsApp/Signal Emergency Bridge (`+962-79-555-0102`) | `P1`, `P2` (Fail-over) | **P1: `5 Minutes`**<br>**P2: `15 Minutes`** | Auto-escalates to **On-Call CISO (Step 4)** |
| **Step 4** | **On-Call CISO** *(Dr. Tariq Al-Mansoor)* | Dedicated 24/7 Emergency Phone (`+962-79-555-0100`) | All `P1` & Unanswered `P2` | **P1: `5 Minutes`** | Rolls over to **Deputy CISO (`+962-79-555-0105`)** AND **Night Nursing Supervisor (Step 5)** |
| **Step 5** | **24/7 Hospital Night Nursing Supervisor & Duty Physician** *(Added post-Tabletop 2.7)* | Hospital Red-Phone `Ext. 1111` (Physical Ward Desk — Always Staffed 24/7) | Any `P1` impacting workstations (`DESKTOP-DTUQ6D4`), EHR, or Portal (`web`) | **`2 Minutes`** (Staffed 24/7 desk) | Activates ward paper-charting protocol and dispatches on-site night IT technician |

---

## 3. External Parties & National Reporting Matrix (Vendor, Regulator, Police & National CERT)

| External Party Category | Specific Entity / Agency | When to Contact (Trigger Condition) | Mandatory Notification Window / SLA | Authorized Caller & Required Pre-Approval | Contact Details & Reporting Mechanism |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **1. External Security & IT Vendors** | **A. Managed IR & Forensics Retainer (CrowdStrike / Mandiant Partner)**<br>**B. EHR & Cloud Vendor Critical Support**<br>**C. Upstream ISP (Orange / Zain Enterprise NOC)** | • Confirmed `P1` incident requiring Tier-3 memory forensics or domain-wide containment<br>• EHR database corruption or DDoS on `web` (`192.168.120.151`) | **Within 1 Hour** of `P1` declaration (Contractual 24/7 SLA) | **CISO or Tier-2 IR Lead** *(Pre-authorized under master retainer)* | • IR Hotline: `+962-6-500-9911` (`ir-emergency@vendor-soc.example`)<br>• EHR Critical Line: `800-EHR-CARE` |
| **2. National Reporting (National CERT)** | **National Cyber Security Center (NCSC-JO) — Critical Infrastructure Sector CERT** | • Any `P1` cyber incident affecting hospital operations, credential dumping (`T1003.001`), or widespread malware/ransomware | **Initial Alert: Within 12–24 Hours** of `P1` confirmation | **CISO** *(with notification to Hospital CEO & Legal Counsel)* | • NCSC-JO 24/7 Portal & Hotline: `incident@ncsc.jo` / `+962-6-550-0000` (Submit with SHA-256 IOCs & MITRE ATT&CK IDs) |
| **3. Sector Regulator & Data Protection** | **A. Ministry of Health (MoH) — Digital Health Directorate**<br>**B. National Data Protection Council (PDPL Regulator)** | • Any clinical system downtime exceeding MTD (`>15 min` EHR) **OR**<br>• Confirmed or reasonably suspected unauthorized access/exfiltration of Patient PHI | **MoH: Within 24 Hours** (Clinical impact)<br>**PDPL: Within 72 Hours** (Personal data breach) | **General Counsel (Legal) + CISO** *(Joint sign-off by CEO required)* | • MoH Emergency Desk: `ehealth-ir@moh.gov.jo`<br>• PDPL Statutory Filing Portal (Form PDPL-IR-01) |
| **4. Law Enforcement (Police)** | **Public Security Directorate (PSD) — Cybercrime Investigation Unit** | • Confirmed ransomware extortion note, financial wire fraud, destructive sabotage (`wevtutil` + wiper), or insider criminal activity | **Within 24 Hours** of criminal/extortion confirmation (Never pay ransom; preserve chain-of-custody hashes) | **General Counsel + Hospital CEO** *(Supported by Member 3 Forensics Custodian)* | • PSD Cybercrime 24/7 Duty Officer: `+962-6-563-3333` (Provide Step 1.5 SHA-256 Evidence Register `evidence-hashes.md`) |

---

# Playbook PB-01: OS Credential Dumping & Privileged Account Compromise (`T1003.001`)
**Target Top-3 Risk:** `Risk R-01` (Credential Theft from Clinical Workstations — Score: 20/25 Critical)  
**Triggering Part 1 Rule(s):** **Rule 04** (`LSASS Memory Credential Dumping` — `T1003.001`) & **Rule 07** (`Rundll32 Proxy Execution` — `T1218.011`)  
**Organisational Severity & SLA:** **P1 — Critical** | Acknowledge $\le 15\text{ min}$ | First Containment $\le 15\text{ min}$ | Length: **2 Pages (Max 3 Pages)** | Version: `v1.2` *(Updated post-Cold Test 2.5 & Tabletop 2.7)*

---

## 1. End-to-End 8-Stage Operational Flowchart
```text
+---------------------------------------------------------------------------------------------------+
| 1. TRIGGER: Part 1 Rule 04 Fires in Splunk (comsvcs.dll MiniDump / lsass.exe / GrantedAccess)     |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 2. TRIAGE (<= 5 min): Query WinEventLog:Security (EventCode=4688) & Sysmon (EventID=1/10)         |
|    Inspect New_Process_Name, Process_Command_Line, Creator_Process_Name, Account_Name on host     |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 3. DECISIONS (<= 8 min): Is the process a verified signed EDR/AV sensor in an approved path?      |
+-----------------------+---------------------------------------------------+-----------------------+
                        | YES (Benign EDR Scan)                             | NO (True Positive P1)
                        v                                                   v
+-----------------------------------------------+   +-----------------------------------------------+
| Downgrade request to CISO -> Close as P4 FP   |   | 4. CONTAINMENT (<= 15 min):                   |
| Document exclusion in Detection Card 04       |   | • Block outbound C2 (SOC_Contain_Outbound_C2) |
+-----------------------------------------------+   | • Disable compromised Account_Name in AD/Local|
                                                    | • Notify Ward Supervisor if clinical terminal |
                                                    +-----------------------+-----------------------+
                                                                            v
+---------------------------------------------------------------------------------------------------+
| 5. EVIDENCE (<= 20 min): Take VM Snapshot (.vmsn), RAM Dump (winpmem .raw), export .evtx logs,    |
|    and compute SHA-256 hash of C:\Windows\Temp\lsass.dmp BEFORE deleting any files                |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 6. RECOVERY (<= 45 min): Delete lsass.dmp & rogue tasks/services; rotate all cached credentials & |
|    Kerberos krbtgt/session tickets; enable RunAsPPL=1; verify 0 alerts in Splunk for 15+ minutes  |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 7. COMMUNICATION: Execute 6-Field Call (Step 1.5/2.3) -> Issue P1 Staff Advisory (Template 1) &   |
|    NCSC-JO Notification (Template 3) with CISO + Legal + CEO sign-off                             |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 8. CLOSURE: Attach SHA-256 Evidence Register, update Ticket #SOC-2026-101, conduct Post-Incident  |
|    Review within 48 hours, and obtain CISO formal sign-off to close P1 incident                   |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Step-by-Step Analyst Execution Checklist (Stages 1 to 8)

### Stage 1 — Trigger
* **Alert Condition:** Splunk Scheduled Alert **Rule 04 (`LSASS Memory Credential Dumping`)** fires on `comsvcs.dll`, `MiniDump`, `lsass.dmp`, or Sysmon `EventID=10` (`TargetImage="*\lsass.exe"` with `GrantedAccess="0x1fffff"` / `0x143a`).

### Stage 2 — Triage (Target Time: `00:00 – 03:00`)
* Run the exact triage query in Splunk (`http://192.168.120.149:8000`) *(Note added in v1.1 after Cold Test: use raw field names `New_Process_Name` and `Process_Command_Line` alongside `CommandLine`)*:
  ```spl
  index=* sourcetype="WinEventLog:*" host="DESKTOP-DTUQ6D4" (EventCode=4688 OR EventCode=4698 OR EventCode=7045) (*lsass* OR *comsvcs* OR *MiniDump* OR *rundll32*)
  | table _time, host, Account_Name, Creator_Process_Name, New_Process_Name, Process_Command_Line
  | sort _time
  ```
* Identify: (a) Target `host` (`DESKTOP-DTUQ6D4`), (b) `Account_Name`, (c) Dump file output path (`C:\Windows\Temp\lsass.dmp`), and (d) Any accompanying persistence (`EventCode=4698` / `7045`).

### Stage 3 — Decisions (Target Time: `03:00 – 04:00`)
* **Decision Gate A (True vs. False Positive):**
  * **IF** `New_Process_Name` is a known, digitally signed EDR agent and no dump file is written to `\Temp\`: Request CISO review to downgrade to **P4 Benign**.
  * **IF** `rundll32.exe`, `procdump.exe`, `powershell.exe`, or an unknown binary accessed `lsass.exe`: **Confirm P1 Critical True Positive** and proceed immediately to **Stage 4**.
* **Decision Gate B (Clinical Impact Check — Added post-Tabletop 2.7):**
  * Check if the host is an active ICU/ER workstation (`SYS-01`/`SYS-02`). If isolating the host disrupts bedside care, notify the **Night Nursing Supervisor (`Ext. 1111`)** to switch the bay to the spare terminal before cutting LAN access.

### Stage 4 — Containment (Target Time: `04:00 – 07:00` — First Action Pass Benchmark)
1. **Isolate Host Outbound C2 Traffic (Execute via Admin PowerShell on `DESKTOP-DTUQ6D4`):**
   ```powershell
   New-NetFirewallRule -DisplayName "SOC_Contain_Outbound_C2" -Direction Outbound -Action Block -RemoteAddress 198.51.100.0/24
   Get-NetFirewallRule -DisplayName "SOC_Contain_Outbound_C2" | Select-Object DisplayName, Enabled, Direction, Action
   ```
2. **Disable Compromised / Suspicious Account:**
   ```powershell
   Disable-LocalUser -Name "<Compromised_Account_Name>" -ErrorAction SilentlyContinue
   ```

### Stage 5 — Evidence Preservation (Target Time: `07:00 – 10:00`)
* **CRITICAL RULE:** Compute SHA-256 hashes and preserve volatile evidence **BEFORE** deleting any attacker artifacts:
  1. Take VMware Host Snapshot: `DESKTOP-DTUQ6D4_INC-2026-001_Snapshot_YYYYMMDD.vmsn`.
  2. Capture RAM dump via `winpmem_mini_x64.exe DESKTOP-DTUQ6D4_RAM.raw`.
  3. Hash the credential dump file and exported logs:
     ```powershell
     wevtutil epl Security C:\Forensics\Security_DESKTOP-DTUQ6D4.evtx
     Get-FileHash -Algorithm SHA256 C:\Windows\Temp\lsass.dmp, C:\Forensics\Security_DESKTOP-DTUQ6D4.evtx
     ```

### Stage 6 — Recovery & Eradication (Target Time: `10:00 – 14:00`)
1. **Remove Credential Dump File & Any Associated Persistence:**
   ```powershell
   Remove-Item -Path "C:\Windows\Temp\lsass.dmp" -Force -ErrorAction SilentlyContinue
   schtasks /delete /tn "SOC_Test_Task" /f 2>$null
   Stop-Service -Name "SOC_Test_Svc" -Force -ErrorAction SilentlyContinue ; sc.exe delete "SOC_Test_Svc" 2>$null
   ```
2. **Harden LSASS & Rotate Credentials:** Enable LSA Protection (`reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f`) and rotate passwords for all accounts active on `DESKTOP-DTUQ6D4`.
3. **Verify Clean State in Splunk:** Run `index=* host="DESKTOP-DTUQ6D4" (*lsass* OR *comsvcs* OR EventCode=4698 OR EventCode=7045)` over `Last 15 minutes` and confirm **`0 events`** (`recovery_verification_0_events.png`).

### Stage 7 — Communication
* Complete **6-Field Escalation Call** to Tier-2 IR Lead & CISO within 15 minutes (`Task 1.5` & `Task 2.3`).
* Issue **P1 Internal Staff Advisory (`Template 1`)** and prepare **NCSC-JO / Regulator Notification (`Template 3`)** per `Task 2.6`.

### Stage 8 — Closure
* Verify all SHA-256 hashes are logged in `evidence-hashes.md`, attach recovery screenshot (`0 events`), complete Post-Incident Review (`Task 1.6`), and obtain **CISO signature** to close the P1 ticket.


---

# Playbook PB-02: Malicious PowerShell Execution & Ingress Tool Staging (`T1059.001` & `T1105`)
**Target Top-3 Risk:** `Risk R-02` (Malicious Script Execution & Ransomware Staging via LOLBins — Score: 20/25 Critical)  
**Triggering Part 1 Rule(s):** **Rule 01** (`Suspicious PowerShell Execution` — `T1059.001`) & **Rule 08** (`Ingress Tool Transfer` — `T1105`)  
**Organisational Severity & SLA:** **P2 — High** *(Escalates to **P1 Critical** if paired with payload execution/persistence)* | Acknowledge $\le 30\text{ min}$ | Length: **2 Pages (Max 3 Pages)** | Version: `v1.2`

---

## 1. End-to-End 8-Stage Operational Flowchart
```text
+---------------------------------------------------------------------------------------------------+
| 1. TRIGGER: Part 1 Rule 01 (PowerShell -enc/IEX) or Rule 08 (certutil -urlcache / curl) Fires     |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 2. TRIAGE (<= 5 min): Inspect EventCode=4688 / 4104 & Apache access_combined logs in Splunk       |
|    Decode Base64 command line; identify remote URI/IP and local staged file path (e.g., test.txt) |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 3. DECISIONS (<= 8 min): Is the command a verified SYSTEM forwarder script or approved dev check? |
+-----------------------+---------------------------------------------------+-----------------------+
                        | YES (Benign Admin / Incident B)                   | NO (Malicious Staging)
                        v                                                   v
+-----------------------------------------------+   +-----------------------------------------------+
| Close Ticket as P4 False Positive             |   | 4. CONTAINMENT (<= 15 min):                   |
| Add exclusion filter (NOT Account_Name=SYSTEM)|   | • Kill rogue powershell.exe / certutil.exe PID|
+-----------------------------------------------+   | • Block remote C2 IP/subnet via Host Firewall |
                                                    +-----------------------+-----------------------+
                                                                            v
+---------------------------------------------------------------------------------------------------+
| 5. EVIDENCE (<= 20 min): Compute SHA-256 hash of staged payload (test.txt), export PowerShell     |
|    ScriptBlock logs (EventCode=4104), and capture VM snapshot if P1 escalation occurred           |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 6. RECOVERY (<= 35 min): Delete staged file (Remove-Item -Force), purge Certutil URLCache,        |
|    enforce PowerShell Constrained Language Mode, and verify 0 new alerts in Splunk (15m window)   |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 7. COMMUNICATION: Escalate to Tier-2 IR Lead (or CISO if P1); notify IT Helpdesk & Clinical Staff |
|    if workstation replacement is needed (Task 2.6 Communication Plan)                             |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 8. CLOSURE: Document decoded payload, C2 URI, and SHA-256 hash in Ticket (#SOC-2026-101 / 104);   |
|    update firewall blocklist and obtain SOC Lead / CISO closure sign-off                          |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Step-by-Step Analyst Execution Checklist (Stages 1 to 8)

### Stage 1 — Trigger
* **Alert Condition:** **Rule 01 (`T1059.001`)** fires on `EventCode=4688` / `4104` containing `-enc`, `-EncodedCommand`, `IEX`, or `DownloadString`, OR **Rule 08 (`T1105`)** fires on `certutil.exe -urlcache`, `curl.exe`, or `Invoke-WebRequest`.

### Stage 2 — Triage (Target Time: `00:00 – 03:00`)
* Query Splunk for process creation and web logs across `DESKTOP-DTUQ6D4` and `web`:
  ```spl
  index=* (host="DESKTOP-DTUQ6D4" OR host="web") (EventCode=4688 OR EventCode=4104 OR sourcetype="access_combined")
  | table _time, host, sourcetype, Account_Name, Creator_Process_Name, New_Process_Name, Process_Command_Line, uri_path, status
  | sort _time
  ```
* Decode any Base64 `-EncodedCommand` string to inspect the cleartext commands.

### Stage 3 — Decisions (Target Time: `03:00 – 04:00`)
* **IF** `Account_Name="SYSTEM"` and `New_Process_Name="*splunk-powershell.exe*"` (as in **Incident B / Ticket `#SOC-2026-103`**): Classify as **P4 False Positive**, close ticket with reason, and apply tuning filter `NOT Account_Name="SYSTEM"`.
* **IF** an interactive user/admin session executed `IEX` or downloaded an external payload via `certutil -urlcache`: Classify as **P2 High** (or **P1 Critical** if chained with persistence/credential dump) and proceed to **Stage 4**.

### Stage 4 — Containment (Target Time: `04:00 – 07:00`)
1. **Terminate Active Malicious PowerShell / LOLBin Processes & Block C2 Subnet:**
   ```powershell
   Stop-Process -Name "powershell" -Force -ErrorAction SilentlyContinue
   New-NetFirewallRule -DisplayName "SOC_Contain_Outbound_C2" -Direction Outbound -Action Block -RemoteAddress 198.51.100.0/24
   ```

### Stage 5 — Evidence Preservation (Target Time: `07:00 – 10:00`)
* Hash the staged payload on disk and export PowerShell operational logs before eradication:
  ```powershell
  Get-FileHash -Algorithm SHA256 C:\Windows\System32\test.txt, C:\Windows\Temp\test.txt -ErrorAction SilentlyContinue
  wevtutil epl "Microsoft-Windows-PowerShell/Operational" C:\Forensics\PowerShell_DESKTOP-DTUQ6D4.evtx
  ```

### Stage 6 — Recovery & Eradication (Target Time: `10:00 – 13:00`)
1. **Delete Staged Payload & Clear Certutil Cache:**
   ```powershell
   Remove-Item -Path "C:\Windows\System32\test.txt", "C:\Windows\Temp\test.txt" -Force -ErrorAction SilentlyContinue
   certutil.exe -urlcache * delete
   ```
2. **Verify Clean State in Splunk:** Confirm `0 events` over a 15-minute post-remediation window (`recovery_verification_0_events.png`).

### Stage 7 — Communication & Stage 8 — Closure
* Notify Tier-2 IR Lead per **Task 2.3 Escalation Tree**; if promoted to P1, issue **P1 Staff Advisory (`Template 1`)**. Record the decoded command, C2 IP, and SHA-256 hash (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`) in the ticket and close.


---

# Playbook PB-03: Brute-Force Account Compromise & Cross-Platform Persistence (`T1110`, `T1053`, `T1098`)
**Target Top-3 Risk:** `Risk R-03` (Brute-Force Account Takeover & Persistent Backdoors on Hospital Servers — Score: 16/25 High)  
**Triggering Part 1 Rule(s):** **Rule 05** (`Brute Force Correlation` — `T1110`), **Rule 02/03** (`Windows Task/Service` — `T1053.005`/`T1543.003`), **Rule 09/10** (`Linux Cron & SSH Keys` — `T1053.003`/`T1098.004`)  
**Organisational Severity & SLA:** **P2 — High** *(Escalates to **P1 Critical** if Patient Portal `web` or EHR is breached)* | Acknowledge $\le 30\text{ min}$ | Length: **2 Pages (Max 3 Pages)** | Version: `v1.2`

---

## 1. End-to-End 8-Stage Operational Flowchart
```text
+---------------------------------------------------------------------------------------------------+
| 1. TRIGGER: Rule 05 (>=3 4625 + >=1 4624 in 10m) OR Rule 02/03/09/10 Persistence Alert Fires      |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 2. TRIAGE (<= 5 min): Inspect Account_Name, Logon_Type, Source IP on Windows (DESKTOP-DTUQ6D4)    |
|    and auditd SYSCALL/EXECVE events (key=cron_persistence / ssh_keys) on Linux server (web)       |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 3. DECISIONS (<= 8 min): Was it a legitimate user password typo / approved change window?         |
+-----------------------+---------------------------------------------------+-----------------------+
                        | YES (Verified User Typo / Change Ticket)          | NO (Confirmed Compromise)
                        v                                                   v
+-----------------------------------------------+   +-----------------------------------------------+
| Close as P4 Benign after user phone check     |   | 4. CONTAINMENT (<= 15 min):                   |
+-----------------------------------------------+   | • Disable compromised account (FakeAdmin)     |
                                                    | • Block attacker Source IP at host firewall   |
                                                    | • Lock rogue SSH session on Linux `web`       |
                                                    +-----------------------+-----------------------+
                                                                            v
+---------------------------------------------------------------------------------------------------+
| 5. EVIDENCE (<= 20 min): Preserve /var/log/audit/audit.log, /etc/crontab, ~/.ssh/authorized_keys, |
|    and Windows Security.evtx; compute SHA-256 hashes (check Rule 06 EventCode 1102/104 log clear) |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 6. RECOVERY (<= 35 min): Remove rogue Windows Task/Service (schtasks /delete, sc.exe delete);     |
|    clean Linux /etc/crontab & ~/.ssh/authorized_keys + set chattr +i; verify 0 alerts in Splunk   |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 7. COMMUNICATION: Escalate to Tier-2 IR Lead; if Patient Portal (`web`) is impacted, issue        |
|    Customer/Patient Maintenance Notification (Template 2) with CMIO/CEO approval                  |
+-------------------------------------------------+-------------------------------------------------+
                                                  v
+---------------------------------------------------------------------------------------------------+
| 8. CLOSURE: Enforce 5-attempt account lockout policy + MFA; attach SHA-256 evidence table to      |
|    Ticket #SOC-2026-102 and sign off closure with SOC Lead                                        |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Step-by-Step Analyst Execution Checklist (Stages 1 to 8)

### Stage 1 — Trigger
* **Alert Condition:** **Rule 05 (`T1110` Correlation)** fires when an account records $\ge 3$ `EventCode=4625` failed logons followed by $\ge 1$ `EventCode=4624` success within 10 minutes, OR **Rules 02/03/09/10** fire on Windows task/service creation or Linux `/etc/crontab` / `~/.ssh/authorized_keys` modification.

### Stage 2 — Triage (Target Time: `00:00 – 03:30`)
* Run the cross-platform authentication and persistence triage query in Splunk:
  ```spl
  index=* (host="DESKTOP-DTUQ6D4" AND EventCode IN (4625, 4624, 4698, 7045, 1102, 104)) OR (host="web" AND sourcetype="linux:audit" ("cron_persistence" OR "ssh_keys"))
  | table _time, host, sourcetype, EventCode, Account_Name, Logon_Type, key, _raw
  | sort _time
  ```

### Stage 3 — Decisions (Target Time: `03:30 – 04:30`)
* **IF** verified user password rotation typo with zero post-logon persistence commands and an approved Linux change ticket exists: Close as **P4 Benign**.
* **IF** unrecognized `Account_Name` (`FakeAdmin`), `Logon_Type=3` (Network SMB), log clearing (`EventCode=104`/`1102`), or unapproved cron/SSH key injection: Confirm **P2 High True Positive** (promote to **P1** if Patient Portal `web` data is exposed) and proceed to **Stage 4**.

### Stage 4 — Containment (Target Time: `04:30 – 07:30`)
1. **Windows Account & Network Containment (`DESKTOP-DTUQ6D4`):**
   ```powershell
   Disable-LocalUser -Name "FakeAdmin" -ErrorAction SilentlyContinue
   New-NetFirewallRule -DisplayName "SOC_Block_BruteForce_Source" -Direction Inbound -Action Block -RemoteAddress 198.51.100.0/24
   ```
2. **Linux Session & Account Containment (`web` / `192.168.120.151`):**
   ```bash
   sudo passwd -l compromised_user ; sudo pkill -KILL -u compromised_user
   ```

### Stage 5 — Evidence Preservation (Target Time: `07:30 – 10:00`)
* Archive and hash Linux `/var/log/audit/audit.log`, `/etc/crontab`, and `~/.ssh/authorized_keys`, plus Windows `Security.evtx` (`evidence-hashes.md`):
  ```bash
  sudo tar -czf /tmp/audit_and_apache_web_20261019.tar.gz /var/log/audit/audit.log /var/log/apache2/access.log /etc/crontab
  sha256sum /tmp/audit_and_apache_web_20261019.tar.gz
  ```

### Stage 6 — Recovery & Eradication (Target Time: `10:00 – 14:00`)
1. **Remove Windows Persistence (`DESKTOP-DTUQ6D4`)** *(Note added in v1.1 after Cold Test: stop service before deleting)*:
   ```powershell
   schtasks /delete /tn "SOC_Test_Task" /f 2>$null
   Stop-Service -Name "SOC_Test_Svc" -Force -ErrorAction SilentlyContinue ; sc.exe delete "SOC_Test_Svc" 2>$null
   ```
2. **Remove Linux Cron & SSH Key Persistence (`web`):**
   ```bash
   sudo sed -i '/\/tmp\/pwn/d' /etc/crontab
   sed -i '/test@attack/d' ~/.ssh/authorized_keys
   sudo chattr +i /etc/crontab ~/.ssh/authorized_keys
   ```
3. **Verify Clean State in Splunk:** Confirm `0 events` across both `DESKTOP-DTUQ6D4` and `web` over the next 15 minutes.

### Stage 7 — Communication & Stage 8 — Closure
* Notify Tier-2 IR Lead (`Task 2.3`); if Patient Portal `web` requires downtime, issue **Customer/Patient Notification (`Template 2`)**. Document remediation in Ticket `#SOC-2026-102` and close.

---

# Step 2.5: Playbook Timed Execution, External Cold Test & Playbook Changelog (6 Points)

**Task Owner:** Member 3 *(Linux & Forensics Lead)* | **Peer Reviewer:** Member 2 *(SIEM Architect)*

---

## 1. Internal Team Timed Execution of All 3 Playbooks ("Fire the Rule and Follow Each Playbook with a Timer")
Each of the 3 playbooks (`PB-01`, `PB-02`, `PB-03`) was tested live in our isolated Splunk lab (`192.168.120.0/24`) by firing its triggering Part 1 detection rule(s) on `DESKTOP-DTUQ6D4` (`192.168.120.150`) and `web` (`192.168.120.151`) while recording stopwatch split times from **Alert Trigger (`T+00:00`)** to **First Containment Action** and **Full Playbook Closure**:

| Playbook ID & Name | Triggering Part 1 Rule Fired | Stage 1–2: Alert & Triage Time | Stage 3: Decision Time | Stage 4: First Correct Containment Action Time *(Team Baseline)* | Stage 5: Evidence Hashing Time | Stage 6–8: Eradication, Recovery & Closure | Total End-to-End Run Time | Proof Screenshot |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **`PB-01`: Credential Dumping (`T1003.001`)** | **Rule 04** (`rundll32 comsvcs.dll MiniDump lsass`) | `01m 55s` | `00m 35s` | **`03m 40s`** (`New-NetFirewallRule SOC_Contain_Outbound_C2`) | `02m 45s` (`Get-FileHash lsass.dmp`) | `04m 55s` (`Remove-Item` + `0 events` check) | **`11m 20s`** | `../../part3-proof/screenshots/proof for part 3.png` |
| **`PB-02`: PowerShell & Tool Staging (`T1059.001` / `T1105`)** | **Rule 01** (`powershell -enc`) & **Rule 08** (`certutil -urlcache`) | `01m 40s` | `00m 30s` | **`03m 10s`** (`Stop-Process` + Outbound C2 Firewall Block) | `02m 05s` (`Get-FileHash test.txt`) | `04m 30s` (`Remove-Item test.txt` + `urlcache delete`) | **`09m 45s`** | `../../part3-proof/screenshots/for part  3 2.png` |
| **`PB-03`: Brute Force & Persistence (`T1110` / `T1053` / `T1098`)** | **Rule 05** (`4625->4624`), **Rule 02/03** (`schtasks`/`sc`), **Rule 09/10** (`cron`/`ssh`) | `02m 15s` | `00m 40s` | **`04m 05s`** (`Disable-LocalUser` + Firewall Block) | `02m 30s` (`tar` + `sha256sum` logs) | `05m 35s` (`schtasks /delete`, `sed -i /etc/crontab`) | **`12m 10s`** | `../../part3-proof/screenshots/recovery_verification_0_events.png` |

---

## 2. External Cold Test Evaluation ("A Student from Another Team Uses One Playbook Alone")
Per **Step 2.5**:
* **Cold Test Rubric Criteria:**
  * External student from another team executes the playbook **alone** after we fire the rule.
  * **Pass Condition 1 (Speed):** Correct first containment action completed within **$2\times$ our team baseline time** ($2 \times 03\text{m }40\text{s} = \mathbf{07\text{m }20\text{s}}$ max allowed for `PB-01`).
  * **Pass Condition 2 (Clarity):** **Maximum 2 questions** asked during execution.

### 2.1 Cold Test Execution Log (`Playbook PB-01: Credential Dumping & Host Containment`)

| Cold Test Parameter | Recorded Details & Stopwatch Measurements | Rubric Requirement | Verdict |
| :--- | :--- | :--- | :---: |
| **External Tester Identity** | Student Analyst from **Team Beta (Group 2)** — had zero prior exposure to our lab rules or `PB-01` draft (`v1.0`) | Student from another team working alone | **Verified** |
| **Trigger Fired (`T+00:00`)** | Fired **Rule 04 (`T1003.001`)** + **Rule 02 (`T1053.005`)** on `DESKTOP-DTUQ6D4` (`192.168.120.150`) | Fire the rule | **Verified** |
| **Team Baseline to First Action** | **`03m 40s`** (`220 seconds`) | Baseline timer recorded | — |
| **Max Allowed Cold-Test Time ($2\times$)** | **`07m 20s`** (`440 seconds`) | $\le 2\times$ team time | — |
| **External Tester Actual Time to Correct First Action** | **`05m 15s`** (`315 seconds` — executed `New-NetFirewallRule -DisplayName "SOC_Contain_Outbound_C2" -Direction Outbound -Action Block` on `DESKTOP-DTUQ6D4`) | $\le 07\text{m }20\text{s}$ ($1.43\times$ baseline) | **PASS** |
| **External Tester Total Completion Time** | **`15m 40s`** (Completed SHA-256 hashing of `lsass.dmp`, deleted `SOC_Test_Task`, and verified `0 events` in Splunk) | Full playbook completion | **PASS** |
| **Number of Questions Asked** | **`1 Question`** *(See exact transcript below)* | **Max 2 questions** ($\le 2$) | **PASS (1 / 2)** |

### 2.2 Verbatim Log of the 1 Question Asked & Observer Notes During Cold Test
* **Question #1 (Asked at `T+02m 10s` during Stage 2 Triage):**
  > *"In Stage 2 of your playbook, the SPL table command references generic Sigma field names `Image` and `CommandLine`, which appear blank in `WinEventLog:Security` EventCode 4688 unless I expand the event—should I use `New_Process_Name` and `Process_Command_Line` instead?"*
  * **Observer Answer Given:** *"Yes, use `New_Process_Name` and `Process_Command_Line`."* (Tester immediately found `rundll32.exe ... comsvcs.dll, MiniDump` and proceeded to Stage 4 Containment without asking any further questions.)
* **Observer Friction Note (Recorded at `T+11m 05s` during Stage 6 Eradication — No question asked):**
  * When the tester ran `sc.exe delete "SOC_Test_Svc"`, Windows returned `[SC] OpenService FAILED 1060` (visible in `../../part3-proof/screenshots/proof for part 3.png`) because the service had already been removed or was in a stopped state, and when running `Remove-Item` on `lsass.dmp` the tester had to confirm the exact `C:\Windows\Temp\` path.

---

## 3. Fixes Applied to Playbooks & Complete Changelog (`v1.0` $\rightarrow$ `v1.1` / `v1.2`)
Per **Step 2.5** (*"Fix the playbooks and list the changes"*), all friction points discovered during the timed runs and the external cold test were immediately fixed in `2.4-playbooks/`:

| Change # | Affected Playbook(s) | Defect / Friction Identified During Testing | Exact Fix Applied to Playbook (`v1.1` / `v1.2`) |
| :---: | :--- | :--- | :--- |
| **Fix 1** | `PB-01`, `PB-02`, `PB-03` (Stage 2 Triage) | Cold-test participant noted that raw `WinEventLog:Security` (`EventCode=4688`) populates `New_Process_Name`, `Creator_Process_Name`, and `Process_Command_Line` rather than unmapped Sigma field names (`Image`, `CommandLine`). | Updated all Stage 2 SPL queries in `PB-01`, `PB-02`, and `PB-03` to explicitly output `Account_Name, Creator_Process_Name, New_Process_Name, Process_Command_Line` so analysts see process details immediately in the statistics table. |
| **Fix 2** | `PB-01`, `PB-02` (Stage 4 Containment) | Draft `v1.0` said *"Block outbound C2 traffic in Windows Firewall"* without providing the exact `-RemoteAddress` parameter, costing ~45 seconds of syntax lookup. | Added the complete copy-pasteable PowerShell one-liner: `New-NetFirewallRule -DisplayName "SOC_Contain_Outbound_C2" -Direction Outbound -Action Block -RemoteAddress 198.51.100.0/24` followed by `Get-NetFirewallRule` verification. |
| **Fix 3** | `PB-01`, `PB-03` (Stage 6 Recovery) | Running `sc.exe delete "SOC_Test_Svc"` directly without stopping a running service or suppressing non-existent service errors caused console warnings (`FAILED 1060`). | Updated Stage 6 to run `Stop-Service -Name "SOC_Test_Svc" -Force -ErrorAction SilentlyContinue ; sc.exe delete "SOC_Test_Svc" 2>$null` and added `-ErrorAction SilentlyContinue` to `Remove-Item`. |
| **Fix 4** | `PB-01`, `PB-02` (Stage 5 Evidence) | Analysts risked running Stage 6 `Remove-Item` before computing the SHA-256 hash of `lsass.dmp` and `test.txt`. | Added a bold warning banner in Stage 5 and moved `Get-FileHash -Algorithm SHA256` directly above the eradication commands so evidence hashing is mandatory before deletion. |

---

# Step 2.6: Crisis Communication Plan, Approval Matrix & P1 Message Templates (3 Points)

**Task Owner:** Member 3 *(Linux & Forensics Lead)* | **Peer Reviewer:** Member 4 *(Readiness Lead)*  
**Document Version:** `v1.2` *(Updated post-Tabletop Exercise Task 2.7 with 15-minute Media Holding Statement pre-authorization)*

---

## 1. Stakeholder Communication Governance & Approval Matrix
Per **Step 2.6** (*"Who can talk to staff, customers, regulator, media + approvals"*), strict communication discipline applies during any **P1 (Critical)** or **P2 (High)** incident at Aegis Health Regional Hospital. **SOC analysts, IT staff, and clinicians are strictly prohibited from making external statements.**

| Target Audience | Authorized Primary Spokesperson | Backup Spokesperson | Mandatory Approval Required Before Release | Communication Channel(s) | Target Release SLA (for P1 Incident) |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **1. Internal Staff**<br>*(Clinicians, Nurses, Admin & IT Staff)* | **Chief Medical Information Officer (CMIO)** *(Clinical impact)* **OR** **CISO** *(IT security actions)* | Chief Operating Officer (COO) / Night Nursing Supervisor (OOH) | **CISO + CMIO** *(Joint sign-off; OOH Night Supervisor may issue pre-approved clinical downtime alert immediately)* | Hospital Intranet Banner, Mass SMS/Pager Broadcast, Ward Supervisor Red-Phone (`Ext. 1111`), Staff Email | **Within 30 Minutes** of P1 declaration |
| **2. Customers / Patients**<br>*(Inpatients, Outpatients & Portal Users)* | **Chief Executive Officer (CEO)** **OR** **Director of Patient Relations** | Chief Medical Officer (CMO) | **CEO + General Counsel (Legal) + CISO** | Patient Portal (`web`) Maintenance Landing Page, SMS Appointment Alerts, Reception Desk Printed Notice | **Within 2 Hours** (if Patient Portal `web` or scheduling is disrupted) |
| **3. Regulators & National CERT**<br>*(MoH, PDPL Data Protection, NCSC-JO, Police)* | **General Counsel (Chief Legal Officer)** *(for MoH / PDPL / Police)* & **CISO** *(for NCSC-JO technical filing)* | Deputy CISO / External Breach Counsel | **General Counsel + CISO + CEO** *(Technical IOC package verified by Member 3 Forensics Lead)* | NCSC-JO Encrypted Portal (`incident@ncsc.jo`), MoH Digital Health Desk, PDPL Statutory Form | **NCSC-JO: $\le 12–24\text{h}$**<br>**MoH: $\le 24\text{h}$**<br>**PDPL: $\le 72\text{h}$** |
| **4. Media & General Public**<br>*(Journalists, Press, Social Media)* | **Director of Corporate Communications & Public Relations** | Hospital CEO | **CEO + General Counsel + CISO** *(Note added post-Tabletop 2.7: PR Director is pre-authorized to read **Template 4 Holding Statement** within 15 min of a press call)* | Official Press Release, Verified Hospital Social Media, Press Inquiries Desk (`press@aegishealth.example`) | **Holding Statement: $\le 15–60\text{ min}$** upon media inquiry |

---

## 2. Mandatory P1 Message Templates (One Complete P1 Template per Audience)

### 2.1 Audience 1: Internal Staff P1 Advisory Template (`Template 1 — Staff`)
> **SUBJECT:** `[URGENT P1 SECURITY ADVISORY] Precautionary Network Containment on Clinical Admin Workstations — Action Required`  
> **FROM:** Dr. Tariq Al-Mansoor (CISO) & Dr. Layla Haddad (CMIO)  
> **TO:** All Aegis Health Clinical, Nursing, Administrative, and IT Personnel  
> **APPROVALS OBTAINED:** CISO + CMIO (`Incident Ref: INC-2026-001`)  
> **TIMESTAMP:** `2026-10-19 15:30 Local Time`  
>
> **What is happening:**  
> At `15:11` today, our Security Operations Center (SOC) detected unauthorized credential-access and script activity on administrative workstation `DESKTOP-DTUQ6D4` (`192.168.120.150`). Our Incident Response team immediately isolated the affected terminal and blocked suspicious outbound network connections (`SOC_Contain_Outbound_C2`). Core ICU telemetry and emergency care systems remain operational.
>
> **Immediate Actions Required from All Staff:**  
> 1. **Clinical Continuity:** Nursing stations on Ward B whose administrative terminal is isolated should immediately switch to the designated backup workstation or initiate standard **Paper Charting Protocol (SOP-CLIN-04)** until IT replaces the unit.  
> 2. **Mandatory Password Reset:** All administrative and clinical staff who logged into Ward B shared workstations today will receive a prompted Active Directory password reset within the next 30 minutes.  
> 3. **Report Anomalies Immediately:** If any screen displays unusual pop-ups, slow performance, or unexpected command windows, **do not turn off the power**—unplug the network cable and call the SOC War Room immediately at **`Ext. 4102`**.  
> 4. **Strict Confidentiality:** Do **not** discuss this incident on social media or with external callers. Forward any external/media inquiries directly to Corporate Communications at **`Ext. 4050`**.  
>
> **Next Update:** `16:00 Local Time` (30-minute P1 cadence).

---

### 2.2 Audience 2: Customers / Patients P1 Notification Template (`Template 2 — Customers / Patients`)
> **SUBJECT:** `Important Update Regarding Aegis Health Online Patient Portal & Appointment Services`  
> **FROM:** Office of the Chief Executive Officer & Patient Relations, Aegis Health Regional Hospital  
> **TO:** Registered Patients & Portal Users  
> **APPROVALS OBTAINED:** CEO + General Counsel + CISO (`Incident Ref: INC-2026-001`)  
>
> **Dear Patient,**  
> As part of our ongoing commitment to protecting the security of our hospital systems, Aegis Health Regional Hospital has temporarily placed our external **Online Patient Portal (`web`)** into scheduled security maintenance following suspicious technical activity detected and contained by our cybersecurity team earlier today.
>
> **How This Affects Your Care:**  
> * **Emergency, Inpatient & Outpatient Medical Care:** All hospital clinics, emergency departments, surgeries, and pharmacies are **open and operating normally**. Your scheduled in-person appointments are unaffected.  
> * **Appointment Scheduling & Lab Results:** While online portal login is temporarily paused for security verification, you may book or confirm appointments and request urgent test results 24/7 through our Patient Care Hotline at **`800-23447`**.  
> * **Protecting Your Account:** Out of an abundance of caution, when online portal access is restored, all users will be prompted to set a new password. Aegis Health will **never** call, SMS, or email you to ask for your current password, banking details, or one-time verification codes.  
>
> We apologize for any temporary inconvenience and will notify you as soon as full online portal services resume.

---

### 2.3 Audience 3: Regulator & National CERT P1 Statutory Notification Template (`Template 3 — Regulator / NCSC-JO / MoH / PDPL`)
> **SUBJECT:** `[STATUTORY P1 INCIDENT NOTIFICATION] Aegis Health Regional Hospital — Ref: INC-2026-001`  
> **FROM:** General Counsel & Chief Information Security Officer, Aegis Health Regional Hospital  
> **TO:** National Cyber Security Center (`incident@ncsc.jo`), Ministry of Health Digital Health Directorate (`ehealth-ir@moh.gov.jo`), and National Data Protection Commissioner (PDPL)  
> **APPROVALS OBTAINED:** General Counsel + CISO + CEO  
> **DATE / TIME OF FILING:** `2026-10-19 16:15 Local Time` *(Within 1 hour of detection; well inside 12–24h NCSC & 72h PDPL statutory windows)*  
>
> **1. Reporting Entity & Contact:**  
> * **Organisation:** Aegis Health Regional Hospital (Critical Healthcare Infrastructure)  
> * **Primary Point of Contact:** Dr. Tariq Al-Mansoor, CISO (`+962-79-555-0100`, `ciso@aegishealth.example`) & Office of General Counsel  
>
> **2. Incident Summary & Timeline (`INC-2026-001`):**  
> * **Time of Occurrence & Detection:** `2026-10-19 15:10:01 EDT` (Detected at `15:11:00 EDT` via Splunk SIEM behavioral alerting; `< 1s` log ingestion latency).  
> * **Affected Assets:** Clinical administrative workstation `DESKTOP-DTUQ6D4` (`192.168.120.150`) and staging web server `web` (`192.168.120.151`). Core EHR databases and ICU life-safety systems were **not** disrupted.  
> * **Observed MITRE ATT&CK Vectors:** `T1059.001` (Encoded PowerShell), `T1105` (`certutil` Ingress Tool Transfer), `T1053.005` / `T1543.003` (Scheduled Task & Service Persistence), `T1218.011` (`rundll32`), and `T1003.001` (`comsvcs.dll` LSASS Memory Dump).  
>
> **3. Containment, Eradication & Forensic Preservation:**  
> * **Containment Completed (`15:16 EDT`):** Outbound C2 blocked via host firewall (`SOC_Contain_Outbound_C2`), affected accounts disabled, and persistence tasks/services removed.  
> * **Forensic Chain of Custody:** Full VM snapshot (`.vmsn`), 8 GB volatile RAM image (`.raw`), `lsass.dmp` (`SHA-256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`), staged payload `test.txt` (`SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`), and raw `.evtx` / `auditd` logs have been preserved for NCSC-JO / PSD Cybercrime inspection.  
> * **Preliminary Data Impact Assessment:** No evidence of bulk PHI database exfiltration has been observed to date; forensic memory and network log analysis is ongoing.  
>
> **4. Next Scheduled Regulatory Update:** `2026-10-20 12:00 Local Time` (or immediately upon any material finding).

---

### 2.4 Audience 4: Media / Press P1 Holding Statement Template (`Template 4 — Media / Press`)
> **FOR IMMEDIATE RELEASE — OFFICIAL HOLDING STATEMENT**  
> **SPOKESPERSON:** Director of Corporate Communications, Aegis Health Regional Hospital  
> **APPROVALS OBTAINED:** CEO + General Counsel + CISO *(Pre-authorized for 15-minute rapid response under Task 2.7 update)*  
>
> *"Earlier today, Aegis Health Regional Hospital's cybersecurity monitoring systems detected and immediately contained unauthorized technical activity on a limited segment of our administrative computer network. Our Incident Response team isolated the affected systems within minutes in accordance with our established hospital readiness protocols.*  
>
> *All emergency, intensive care, surgical, and outpatient medical services remain fully operational, and patient care continues safely without interruption. We have proactively notified the relevant national cybersecurity and health authorities and are working alongside independent forensic specialists to complete a thorough review. We will share further verified updates on our official website as our investigation concludes."*  
>
> **Media Contact:** Corporate Communications Office (`press@aegishealth.example` | `+962-6-555-4050`)

---

# Step 2.7: 45-Minute Tabletop Exercise Report ("Operation Silent Ward" — 7 Injects, Observer Log & Post-Exercise Updates) (7 Points)

**Task Owner & Exercise Facilitator / Observer:** Member 4 *(Threat Intel & Readiness Lead)*  
**Exercise Participants:** Member 1 *(Endpoint & Clinical Liaison)*, Member 2 *(Incident Commander / SIEM Lead)*, Member 3 *(Forensics & Comms Lead)*  
**Duration & Format:** **45 Minutes Strict Timed Exercise** | **7 Injects** *(Requirement: 6+ injects including 1+ pressure inject — includes **2 high-pressure injects**: Ransom Note & Live Journalist Call)*

---

## 1. Tabletop Exercise Scenario & Ground Rules
* **Exercise Scenario ("Operation Silent Ward"):** During a busy Tuesday afternoon shift handover at **Aegis Health Regional Hospital**, an attacker leverages a compromised administrative session on clinical workstation `DESKTOP-DTUQ6D4` (`192.168.120.150`) to stage tools, dump credentials, pivot via brute-force and SSH/cron persistence onto the Linux Patient Portal `web` (`192.168.120.151`), wipe local Windows event logs, drop a ransom/extortion note threatening 25,000 patient records, and leak the story to a local health journalist.
* **Observer Mandate:** **Member 4** ran the master stopwatch, delivered the 7 injects at scheduled timestamps, and recorded **exact decision times** (from inject delivery to team consensus action) and **operational/documentation gaps**.

---

## 2. Complete 45-Minute Exercise Timeline, 7 Injects & Observer Decision Log

| Inject # & Timestamp | Inject Type & Scenario Delivered to Team | Expected Playbook / Document Referenced | Team Decision & Action Taken | Measured Decision Time *(Target SLA)* | Observer Assessment & Gaps Identified |
| :---: | :--- | :--- | :--- | :---: | :--- |
| **Inject 1**<br>`T+00:00`<br>*(00–06m)* | **Initial Detection:** Splunk fires **Rule 01 (`T1059.001`)** (`powershell.exe -EncodedCommand`) and **Rule 08 (`T1105`)** (`certutil.exe -urlcache -f http://127.0.0.1/test.txt`) on `DESKTOP-DTUQ6D4`. | `Card 01`, `Card 08`, `Playbook PB-02` | Member 2 triaged `EventCode=4688`, decoded Base64 command, declared **P2 High**, and instructed Member 3 to block outbound C2 and hash `test.txt`. | **`02m 40s`**<br>*(Target: $\le 5\text{m}$)* | **Pass.** Smooth triage using `PB-02`. No gaps on initial detection. |
| **Inject 2**<br>`T+06:00`<br>*(06–13m)* | **Privilege & Credential Escalation:** **Rule 04 (`T1003.001`)** fires as `rundll32.exe comsvcs.dll, MiniDump` dumps `lsass.exe` to `C:\Windows\Temp\lsass.dmp`, followed by **Rule 02 (`schtasks`)** & **Rule 03 (`sc.exe create`)**. | `Card 04`, `Severity Matrix 2.2`, `Playbook PB-01`, `Escalation Tree 2.3` | Member 2 immediately upgraded severity from **P2 to P1 Critical**, executed the **6-Field Escalation Call** to Member 3 & CISO, and ordered VM snapshot + RAM capture before eradication. | **`03m 10s`**<br>*(Target: $\le 5\text{m}$)* | **Gap #1 Identified:** When escalating to CISO during simulated shift change, `Escalation Tree v1.0` had a 15-minute wait timer before calling the Deputy CISO—too slow for an active P1 LSASS dump (needs a **5-minute P1 fail-over timer**). |
| **Inject 3**<br>`T+13:00`<br>*(13–20m)* | **Cross-Host Pivot & Anti-Forensics:** **Rule 05 (`T1110` Brute Force)** and **Rule 06 (`wevtutil cl Application`)** fire on `DESKTOP-DTUQ6D4` at the exact same moment **Rule 09 (`cron_persistence`)** and **Rule 10 (`ssh_keys`)** fire on Linux server `web` (`192.168.120.151`). | `Card 05`, `Card 06`, `Card 09`, `Card 10`, `Playbook PB-03` | Member 3 disabled `FakeAdmin`, queried pre-clear logs from Splunk (`192.168.120.149`), removed `/tmp/pwn` cron job and rogue SSH key on `web`, and applied `chattr +i`. | **`04m 15s`**<br>*(Target: $\le 5\text{m}$)* | **Pass.** Real-time Splunk forwarding neutralized the attacker's local `wevtutil` log clear. |
| **Inject 4**<br>`T+20:00`<br>*(20–27m)* | **Clinical Operational Friction:** Ward B Nursing Supervisor calls the SOC stating that isolating `DESKTOP-DTUQ6D4` disconnected the reception scheduling terminal and asks whether nurses should halt admissions or switch to paper charts. | `Org Profile 2.1`, `Escalation Tree 2.3`, `Comms Plan 2.6` | Member 1 checked `SYS-07` MTD (4 hours), instructed Ward B to switch to the adjacent spare terminal + paper charting (`SOP-CLIN-04`), and issued **Template 1 (Internal Staff Advisory)**. | **`04m 50s`**<br>*(Target: $\le 5\text{m}$)* | **Gap #2 Identified:** `Escalation Tree v1.0` and `PB-01 v1.1` did not explicitly list the **24/7 Night Nursing Supervisor (`Ext. 1111`)** as a mandatory operational contact prior to isolating a clinical workstation. |
| **Inject 5**<br>`T+27:00`<br>*(27–34m)* | **PRESSURE INJECT #1 (Ransom Note & Data Leak Extortion):** A text file `README_AEGIS_LOCKED.txt` appears on `DESKTOP-DTUQ6D4` demanding **15 BTC within 12 hours** and claiming **25,000 patient PHI records** were exfiltrated from `web`. | `Severity Matrix 2.2`, `Escalation Tree 2.3`, `Comms Plan 2.6` | Team refused ransom negotiation, preserved `README_AEGIS_LOCKED.txt` SHA-256 hash, checked Apache `access_combined` outbound bytes on `web` to verify whether bulk exfiltration occurred, and triggered **Template 3 (NCSC-JO / MoH / PDPL + PSD Cybercrime Police notification)**. | **`03m 55s`**<br>*(Target: $\le 5\text{m}$)* | **Gap #3 Identified:** `Severity Matrix v1.0` did not explicitly state that a ransom note or extortion claim **cannot be downgraded** from P1 by the SOC Lead without forensic proof of zero exfiltration and **CISO + Legal joint sign-off**. |
| **Inject 6**<br>`T+34:00`<br>*(34–40m)* | **PRESSURE INJECT #2 (Hostile Journalist Media Call):** A health reporter calls the hospital switchboard saying: *"We received a screenshot showing Aegis Hospital is hit by ransomware. Comment in 15 minutes or we publish that life-support systems are down."* | `Comms Plan 2.6 (Template 4 — Media)` | Member 3 instructed the switchboard not to comment, routed the call to the Corporate Communications Director, and released **Template 4 (Media Holding Statement)** confirming ICU/emergency care is 100% unaffected. | **`05m 30s`**<br>*(Target: $\le 5\text{m}$ — **Slight Delay**)* | **Gap #4 Identified:** Obtaining live 3-way approval (CEO + Legal + CISO) for a routine holding statement took 5m 30s under media pressure; the PR Director needed **pre-authorized standing approval** to read the factual **Template 4 Holding Statement** within 15 minutes whenever a journalist calls. |
| **Inject 7**<br>`T+40:00`<br>*(40–45m)* | **Recovery Verification & Closure Gate:** All persistence is removed; Splunk shows `0 events` over the last 15 minutes (`recovery_verification_0_events.png`). CISO asks what conditions must be met before reconnecting `DESKTOP-DTUQ6D4` and closing `INC-2026-001`. | `Playbooks PB-01`–`03` Stage 6 & 8, `Evidence Hashes 1.5` | Team verified: (1) All 6 forensic hashes logged (`evidence-hashes.md`), (2) `RunAsPPL=1` + password rotation completed, (3) `0 events` in Splunk, and (4) NCSC-JO initial filing submitted. | **`02m 50s`**<br>*(Target: $\le 5\text{m}$)* | **Pass.** Clean, auditable closure achieved at `T+44m 10s`. |

---

## 3. Post-Exercise Document Updates ("Update Documents After")
Per **Step 2.7** (*"Observer records decision times and gaps. Update documents after"*), all 4 gaps identified by the Observer during the 45-minute tabletop exercise were immediately remediated across our Part 2 readiness pack (bumping documents to **`v1.2`**):

| Gap # | Gap Recorded by Observer (Member 4) | Target Document Updated | Exact Revision Applied (`v1.1` $\rightarrow$ `v1.2`) |
| :---: | :--- | :--- | :--- |
| **Gap 1** | 15-minute phone wait timer before failing over from Primary IR Lead / CISO to Deputy was too slow during a P1 LSASS dump (`Inject 2`). | **`2.3-escalation-tree/escalation-tree.md`** | Reduced P1 fail-over wait timer (`X` minutes) from `15 minutes` to **`5 minutes`** across all working and out-of-working hours call steps. |
| **Gap 2** | Isolating a clinical workstation (`Inject 4`) caused ward confusion because Nursing Supervision wasn't in the containment loop. | **`2.3-escalation-tree/escalation-tree.md`** & **`2.4-playbooks/playbook1-credential-dumping-T1003.md`** | Added **Step 5: 24/7 Hospital Night Nursing Supervisor (`Ext. 1111`)** to the Out-of-Hours Escalation Tree and added **Decision Gate B (Clinical Impact Check)** to `PB-01` Stage 3. |
| **Gap 3** | Ambiguity on whether SOC Lead could downgrade an extortion/ransomware alert once the host was isolated (`Inject 5`). | **`2.2-severity-matrix/severity-matrix.md`** | Locked P1 downgrade authority strictly to **CISO or Designated Incident Commander ONLY** with written root-cause proof. |
| **Gap 4** | Waiting for 3-way executive sign-off delayed the media holding statement during the 15-minute journalist deadline (`Inject 6`). | **`2.6-communication-plan/communication-plan.md`** | Added a **Standing Pre-Authorization Clause** allowing the Director of Corporate Communications to issue the factual **Template 4 Holding Statement** within 15 minutes of a press inquiry once CISO confirms clinical care is unaffected. |

---

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

---

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

---

