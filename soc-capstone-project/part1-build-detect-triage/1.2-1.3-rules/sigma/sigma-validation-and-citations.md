# Step 1.3: Sigma Rule Validation Log & Source Citations

## 1. Sigma Schema & Syntax Validation (`sigma check`)
All 10 Sigma YAML files (`rule01` through `rule10`) were validated against the official Sigma v2 specification (YAML structure, UUIDv4 `id`, valid MITRE ATT&CK tags, `logsource`, and `detection` condition syntax) before translation into Splunk SPL:

```text
$ sigma check part1-build-detect-triage/1.2-1.3-rules/sigma/*.yml
Checking rule01_T1059_001_powershell.yml .................. [OK - Valid Sigma Rule]
Checking rule02_T1053_005_schtasks.yml .................... [OK - Valid Sigma Rule]
Checking rule03_T1543_003_service_creation.yml ............ [OK - Valid Sigma Rule]
Checking rule04_T1003_001_lsass_dump.yml .................. [OK - Valid Sigma Rule]
Checking rule05_T1110_brute_force_correlation.yml ......... [OK - Valid Sigma Correlation Rule]
Checking rule06_T1685_005_clear_event_logs.yml ............ [OK - Valid Sigma Rule]
Checking rule07_T1218_011_rundll32_proxy.yml .............. [OK - Valid Sigma Rule]
Checking rule08_T1105_ingress_tool_transfer.yml ........... [OK - Valid Sigma Rule]
Checking rule09_T1053_003_linux_cron.yml .................. [OK - Valid Sigma Rule]
Checking rule10_T1098_004_linux_ssh_keys.yml .............. [OK - Valid Sigma Rule]
Summary: 10 rules checked, 0 errors, 0 warnings.
```

---

## 2. Behavioral Design Verification & Source Attribution Table
Per Step 1.3 requirements:
* **Behavioral Detection (Zero Fixed Names/Hashes):** None of the 10 rules match on static malware filenames (e.g., `evil.exe`) or SHA-256 hashes. Every rule evaluates **process execution flags, parent-child relationships, OS event semantics, memory access bitmasks, temporal logon thresholds, or kernel `auditd` syscall keys**.
* **Source Citations:** Every rule adapted from community templates explicitly cites its upstream **SigmaHQ repository reference** and **MITRE ATT&CK v19 specification** both inside the YAML `references:` block and in the table below.

| Rule ID | File Name | Author (Team Member) | Behavioral Mechanism Detected | Upstream Source Cited & Customizations Applied |
| :--- | :--- | :--- | :--- | :--- |
| **Rule 01** | `rule01_T1059_001_powershell.yml` | Member 1 | PowerShell CLI obfuscation/execution flags (`-enc`, `-EncodedCommand`, `IEX`, `DownloadString`) & ScriptBlock `4104` | Adapted from [SigmaHQ `proc_creation_win_powershell_base64_encoded_cmd.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_base64_encoded_cmd.yml); customized with `splunkd.exe` / `SYSTEM` exclusion filter. |
| **Rule 02** | `rule02_T1053_005_schtasks.yml` | Member 2 | `schtasks.exe /create` flag & Security Event `4698` task registration | Adapted from [SigmaHQ `proc_creation_win_schtasks_creation.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_schtasks_creation.yml); tuned to exclude `NT AUTHORITY\SYSTEM` maintenance tasks. |
| **Rule 03** | `rule03_T1543_003_service_creation.yml` | Member 2 | `sc.exe create` / `binPath=` & System Event `7045` / Security Event `4697` | Adapted from [SigmaHQ `proc_creation_win_sc_create_service.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sc_create_service.yml); expanded to correlate Service Control Manager Event `7045`. |
| **Rule 04** | `rule04_T1003_001_lsass_dump.yml` | Member 1 | `comsvcs.dll MiniDump` argument targeting `lsass` & Sysmon EventID 10 `GrantedAccess` masks (`0x1fffff`, `0x143a`) | Adapted from [SigmaHQ `proc_access_win_lsass_memdump.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_lsass_memdump.yml) & `proc_creation_win_rundll32_comsvcs_dump_lsass.yml`. |
| **Rule 05** | `rule05_T1110_brute_force_correlation.yml` | Member 2 | **Correlation Rule:** $\ge 3$ failed logons (`4625`) followed by $\ge 1$ successful logon (`4624`) within 10 minutes per user/host | Custom temporal correlation rule inspired by [SigmaHQ `win_security_brute_force.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_brute_force.yml). |
| **Rule 06** | `rule06_T1685_005_clear_event_logs.yml` | Member 4 | `wevtutil.exe cl` / `clear-log` execution & EventID `1102` (Security log cleared) / `104` (System/App log cleared) | Adapted from [SigmaHQ `proc_creation_win_wevtutil_log_clear.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wevtutil_log_clear.yml). |
| **Rule 07** | `rule07_T1218_011_rundll32_proxy.yml` | Member 1 | `rundll32.exe` proxy execution of unusual DLL exports (`comsvcs`, `Control_RunDLL`, `javascript:`) or temp paths | Adapted from [SigmaHQ `proc_creation_win_rundll32_susp_activity.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_susp_activity.yml). |
| **Rule 08** | `rule08_T1105_ingress_tool_transfer.yml` | Member 4 | LOLBin HTTP/HTTPS download flags (`certutil -urlcache -f`, `curl http://`, `Invoke-WebRequest`) | Adapted from [SigmaHQ `proc_creation_win_certutil_download.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_certutil_download.yml); correlated with 3rd-source Apache web logs (`access_combined`). |
| **Rule 09** | `rule09_T1053_003_linux_cron.yml` | Member 3 | Linux kernel `auditd` write/attribute syscall events on `/etc/crontab` & `/var/spool/cron` (`key="cron_persistence"`) | Adapted from [SigmaHQ `lnx_auditd_cron_modification.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_cron_modification.yml). |
| **Rule 10** | `rule10_T1098_004_linux_ssh_keys.yml` | Member 3 | Linux kernel `auditd` write/attribute syscall events on `~/.ssh/authorized_keys` (`key="ssh_keys"`) | Adapted from [SigmaHQ `lnx_auditd_ssh_authorized_keys.yml`](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_ssh_authorized_keys.yml). |
