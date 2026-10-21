# Step 1.1: SOC Lab Architecture & Multi-Source Log Ingestion Verification (6 Points)

## 1. Isolated Lab Network & Host Inventory
The entire project operates inside an **isolated host-only/NAT virtual lab network (`192.168.120.0/24`)** with a **single central Splunk Enterprise SIEM (`192.168.120.149`)** receiving real-time telemetry from three distinct log sources:
1. **Windows 10 Endpoint + Sysmon (`DESKTOP-DTUQ6D4`)**
2. **Ubuntu Linux Server + `auditd` (`web`)**
3. **3rd Telemetry Source: Apache HTTP Web Logs & Host Firewall Telemetry (`access_combined` & `WindowsFirewall`/`ufw`)**

| Source # | System Role | Hostname | IP Address | OS & Agent Stack | Telemetry Forwarded to Splunk (`:9997`) |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **SIEM** | **Central SIEM Server** | `splunk-siem` | `192.168.120.149` | Ubuntu 22.04 LTS / Splunk Enterprise (`:8000`) | Central Indexing (`win_logs`, `linux_logs`, `web_logs`, `main`), Correlation, Alerting & 5-Panel Dashboard |
| **Source 1** | **Windows VM + Sysmon** | `DESKTOP-DTUQ6D4` | `192.168.120.150` | Windows 10 Enterprise + Sysmon v15 + Splunk UF | • `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` (Sysmon Event IDs `1` ProcessCreate, `3` NetworkConnect, `7` ImageLoaded, `10` ProcessAccess, `11` FileCreate)<br>• `WinEventLog:Security` (`4688` w/ CmdLine, `4624`, `4625`, `4698`, `4697`, `1102`)<br>• `WinEventLog:System` (`7045`, `104`) & `PowerShell` (`4104`) |
| **Source 2** | **Linux VM + `auditd`** | `web` | `192.168.120.151` | Ubuntu 22.04 Server + `auditd` + Splunk UF | • `sourcetype="linux:audit"` (`/var/log/audit/audit.log` monitoring `EXECVE` syscalls, `key="cron_persistence"` on `/etc/crontab` & `/var/spool/cron`, and `key="ssh_keys"` on `~/.ssh/authorized_keys`) |
| **Source 3** | **3rd Source: Web & Firewall** | `web` & `DESKTOP-DTUQ6D4` | `192.168.120.151` & `.150` | Apache2 HTTP Server + Windows/UFW Firewall | • `sourcetype="access_combined"` (`/var/log/apache2/access.log` HTTP GET/POST requests, status codes, user agents)<br>• `sourcetype="ufw"` (`/var/log/ufw.log`) & Windows Filtering Platform (`EventCode=5156`/`5157` & `SOC_Contain_Outbound_C2` firewall blocks) |

---

## 2. Test Action per Host & SIEM Ingestion Delay (`_indextime - _time`)
To verify real-time forwarding across all three sources, one deliberate test action was executed on each source and queried in Splunk using `eval delay = _indextime - _time`:

| Telemetry Source | Hostname | Test Action Executed | Splunk Verification Query | Event Timestamp (`_time`) | Index Timestamp (`_indextime`) | Measured Delay | Evidence Screenshot |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| **1. Windows VM + Sysmon** | `DESKTOP-DTUQ6D4` | Executed `whoami.exe` in administrative prompt (captured by `EventCode=4688` & Sysmon `EventID=1`) | `index=win_logs "whoami" \| eval delay=_indextime-_time \| table _time, _indextime, delay, host, EventCode, Image, CommandLine, User` | `2026-10-19 10:18:01.000` | `2026-10-19 10:18:02.000` | **1.000 sec** | `screenshots/windows_log_ingestion_delay.png` |
| **2. Linux VM + `auditd`** | `web` | Executed `ausearch -k cron_persistence` & touched `/etc/crontab` (`type=EXECVE`) | `index=linux_logs "cron_persistence" \| eval delay=_indextime-_time \| table _time, _indextime, delay, host, sourcetype, _raw` | `2026-10-19 10:21:44.362` | `2026-10-19 10:21:45.000` | **0.638 sec** | `screenshots/linux_log_ingestion_delay.png` & `screenshots/linux_auditd_verification.png` |
| **3. 3rd Source (Web & Firewall)** | `web` (`Apache2` / `Firewall`) | Issued HTTP probe `curl -s http://192.168.120.151/test.txt` & outbound firewall rule test | `index=web_logs sourcetype="access_combined" "/test.txt" \| eval delay=_indextime-_time \| table _time, _indextime, delay, host, clientip, uri_path, status` | `2026-10-19 10:24:11.588` | `2026-10-19 10:24:12.000` | **0.412 sec** | `screenshots/third_source_web_firewall_delay.png` |

---

## 3. Configuration Snippets Forwarded to SIEM

### 3.1 Windows Universal Forwarder (`inputs.conf` on `DESKTOP-DTUQ6D4`)
```ini
[WinEventLog://Security]
disabled = 0
index = win_logs

[WinEventLog://System]
disabled = 0
index = win_logs

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = win_logs

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
index = win_logs
```

### 3.2 Linux Universal Forwarder & 3rd Source (`inputs.conf` & `audit.rules` on `web`)
```ini
# /opt/splunkforwarder/etc/system/local/inputs.conf
[monitor:///var/log/audit/audit.log]
disabled = false
index = linux_logs
sourcetype = linux:audit

[monitor:///var/log/apache2/access.log]
disabled = false
index = web_logs
sourcetype = access_combined

[monitor:///var/log/ufw.log]
disabled = false
index = linux_logs
sourcetype = ufw
```

```bash
# /etc/audit/rules.d/soc_capstone.rules
-w /etc/crontab -p wa -k cron_persistence
-w /etc/cron.d/ -p wa -k cron_persistence
-w /var/spool/cron/crontabs/ -p wa -k cron_persistence
-w /root/.ssh/authorized_keys -p wa -k ssh_keys
-w /home/ -p wa -k ssh_keys
```

## 4. Evidence Screenshots Inventory
* `screenshots/windows_log_ingestion_delay.png` — Windows `EventCode=4688` + Sysmon field (`Image`, `CommandLine`, `User`) ingestion and latency verification (`delay = 1s`).
* `screenshots/linux_log_ingestion_delay.png` — Linux `sourcetype=linux:audit` ingestion and latency verification (`delay = 0.638s`).
* `screenshots/linux_auditd_verification.png` — Raw Linux `auditd` `EXECVE` event capture in Splunk.
* `screenshots/third_source_web_firewall_delay.png` — 3rd Log Source (`sourcetype=access_combined` & Firewall telemetry) ingestion and latency verification (`delay = 0.412s`).
