# Step 1.1: SOC Lab Architecture & Log Ingestion Verification

## 1. Network & Host Inventory
| Role | Hostname | IP Address | OS / Platform | Log Forwarding Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **SIEM Server** | `splunk-siem` | `192.168.120.149` | Ubuntu Linux / Splunk Enterprise (`:8000`) | Listening on TCP Port `9997` (`splunktcp`) |
| **Windows Endpoint** | `DESKTOP-DTUQ6D4` | `192.168.120.150` | Windows 10 Enterprise | Splunk Universal Forwarder (`WinEventLog:Security`, `System`, `PowerShell`) |
| **Linux Endpoint** | `web` | `192.168.120.151` / `.149` | Ubuntu Server (`auditd`) | Splunk Universal Forwarder (`/var/log/audit/audit.log`, `sourcetype=linux:audit`) |

## 2. Log Ingestion & Latency Verification
* **Windows Telemetry (`DESKTOP-DTUQ6D4`):** Verified `EventCode=4688` (Process Creation with Command Line Auditing enabled via `auditpol` and Registry `ProcessCreationIncludeCmdLine_Enabled=1`), `EventCode=4624/4625` (Authentication), `EventCode=4698` (Scheduled Tasks), `EventCode=7045` (Service Creation), and `EventCode=4104` (PowerShell Script Block Logging). Measured ingestion delay (`_indextime - _time`): **1 second**.
* **Linux Telemetry (`web`):** Verified `auditd` syscall telemetry (`sourcetype="linux:audit"`, keys `cron_persistence` and `ssh_keys`). Measured ingestion delay (`_indextime - _time`): **0.638 seconds**.

## 3. Evidence Screenshots
* `screenshots/windows_log_ingestion_delay.png` — Windows `EventCode=4688` ingestion and latency verification (`delay = 1s`).
* `screenshots/linux_log_ingestion_delay.png` — Linux `sourcetype=linux:audit` ingestion and latency verification (`delay = 0.638s`).
* `screenshots/linux_auditd_verification.png` — Raw Linux `auditd` `EXECVE` event capture in Splunk.
