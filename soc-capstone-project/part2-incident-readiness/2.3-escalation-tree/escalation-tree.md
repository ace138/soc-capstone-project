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
