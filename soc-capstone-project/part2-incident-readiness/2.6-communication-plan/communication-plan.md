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
