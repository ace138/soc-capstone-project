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
