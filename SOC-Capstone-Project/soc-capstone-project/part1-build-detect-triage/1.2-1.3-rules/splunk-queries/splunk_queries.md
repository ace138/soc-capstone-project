# Step 1.2 & 1.3: 10 Custom Detection Rules (SPL Queries & Attack Simulations)

All 10 Sigma rules (`../sigma/*.yml`) were translated into Splunk Processing Language (SPL), configured as scheduled alerts (`*/1 * * * *`) with **Add to Triggered Alerts** enabled, and validated using live attack simulations across Windows (`DESKTOP-DTUQ6D4` / `192.168.120.150`) and Linux (`web`).

---

## Rule 01 — Suspicious PowerShell Execution (`T1059.001`)
* **Production SPL Query:**
  ```spl
  index=* sourcetype="WinEventLog:*" (EventCode=4688 OR EventCode=4104) (*powershell* OR *IEX* OR *-enc* OR *-EncodedCommand* OR *DownloadString*)
  ```
* **Attack Simulation Command (Windows `192.168.120.150`):**
  ```powershell
  powershell.exe "IEX 'Write-Host Test'"
  powershell.exe -EncodedCommand VwByAGkAdAC0ASABvAHMAdAAgACcAVABlAHMAdAAnAA==
  ```

## Rule 02 — Scheduled Task Creation (`T1053.005`)
* **Production SPL Query:**
  ```spl
  index=* sourcetype="WinEventLog:*" (*schtasks* OR EventCode=4698)
  ```
* **Attack Simulation Command:**
  ```powershell
  schtasks /create /tn "SOC_Test_Task" /tr "notepad.exe" /sc once /st 23:59 /f
  ```

## Rule 03 — New Windows Service Created (`T1543.003`)
* **Production SPL Query:**
  ```spl
  index=* sourcetype="WinEventLog:*" (EventCode=7045 OR EventCode=4697 OR *sc.exe*)
  ```
* **Attack Simulation Command:**
  ```powershell
  sc.exe create "SOC_Test_Svc" binPath= "C:\Windows\System32\calc.exe"
  ```

## Rule 04 — LSASS Memory Credential Dumping (`T1003.001`)
* **Production SPL Query:**
  ```spl
  index=* sourcetype="WinEventLog:*" (*lsass* OR *comsvcs* OR *MiniDump*)
  ```
* **Attack Simulation Command:**
  ```powershell
  rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Windows\Temp\lsass.dmp full
  ```

## Rule 05 — Brute Force Followed by Success (Correlation) (`T1110`)
* **Production SPL Query:**
  ```spl
  index=* sourcetype="WinEventLog:*" EventCode IN (4625, 4624) | bucket _time span=10m | stats count(eval(EventCode=4625)) as Failed_Logons, count(eval(EventCode=4624)) as Success_Logons by _time, Account_Name, host | where Failed_Logons >= 3 AND Success_Logons >= 1
  ```
* **Attack Simulation Command:**
  ```powershell
  1..3 | % { net use \\127.0.0.1\ipc$ /user:FakeAdmin WrongPassword123 2>$null }
  ```

## Rule 06 — Clearing Windows Event Logs (`T1070.001` / `T1685.005`)
* **Production SPL Query:**
  ```spl
  index=* sourcetype="WinEventLog:*" (EventCode=1102 OR EventCode=104 OR *wevtutil*)
  ```
* **Attack Simulation Command:**
  ```powershell
  wevtutil cl Application
  ```

## Rule 07 — Rundll32 Proxy Execution (`T1218.011`)
* **Production SPL Query:**
  ```spl
  index=* sourcetype="WinEventLog:*" EventCode=4688 *rundll32*
  ```
* **Attack Simulation Command:**
  ```powershell
  rundll32.exe shell32.dll,Control_RunDLL
  ```

## Rule 08 — Ingress Tool Transfer (`T1105`)
* **Production SPL Query:**
  ```spl
  index=* sourcetype="WinEventLog:*" EventCode=4688 (*certutil* OR *Invoke-WebRequest* OR *curl*)
  ```
* **Attack Simulation Command:**
  ```powershell
  certutil.exe -urlcache -f http://127.0.0.1/test.txt test.txt
  ```

## Rule 09 — Linux Cron Job Persistence (`T1053.003`)
* **Production SPL Query:**
  ```spl
  index=linux_logs sourcetype="linux:audit" "cron_persistence"
  ```
* **Attack Simulation Command (Linux `web`):**
  ```bash
  echo "* * * * * root /bin/sh -c 'id > /tmp/pwn'" | sudo tee -a /etc/crontab
  ```

## Rule 10 — Linux SSH Authorized Keys Modification (`T1098.004`)
* **Production SPL Query:**
  ```spl
  index=linux_logs sourcetype="linux:audit" "ssh_keys"
  ```
* **Attack Simulation Command (Linux `web`):**
  ```bash
  mkdir -p ~/.ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... test@attack" >> ~/.ssh/authorized_keys
  ```
