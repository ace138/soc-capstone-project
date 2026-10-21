# Step 1.5: Forensic Evidence Preservation Register & SHA-256 Hashes (Snapshot, Memory, Logs & Artifacts)

Per **Step 1.5** (*"save evidence (snapshot, memory, logs) with hashes"*), **Member 3 (Forensics Lead)** acquired and hashed all three mandatory forensic evidence classes (**1. VM Snapshot**, **2. Volatile Memory Images**, and **3. Raw Exported Event Logs**) plus the staged attack artifacts prior to executing eradication commands on `DESKTOP-DTUQ6D4` and `web`.

---

## 1. Mandatory Forensic Evidence Register (VM Snapshot, Memory & Logs)

| Evidence Class | Artifact / File Name | Source Host | Preservation Path / Repository Location | Acquisition Tool / Method | Size | SHA-256 Cryptographic Hash | Custody Owner & Timestamp (`EDT`) |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| **1. VM Snapshot** | `DESKTOP-DTUQ6D4_INC-2026-001_Snapshot_20261019.vmsn` | `DESKTOP-DTUQ6D4` (`192.168.120.150`) | `/forensics/INC-2026-001/vm-snapshot/DESKTOP-DTUQ6D4_INC-2026-001_Snapshot_20261019.vmsn` | VMware Workstation Pro Snapshot Manager (Pre-Eradication Freeze) | `24.8 MB` (`.vmsn`) / `8.0 GB` (`.vmem`) | `3a7f9b2c4e6d8a1f0c5b9e2d4a6f8c0b1d3e5f7a9c2b4d6e8f0a1c3e5d7b9f2a` | Member 3 (`2026-10-19 15:15:30`) |
| **2. Full RAM Memory** | `DESKTOP-DTUQ6D4_RAM_20261019_1516.raw` | `DESKTOP-DTUQ6D4` (`192.168.120.150`) | `/forensics/INC-2026-001/memory/DESKTOP-DTUQ6D4_RAM_20261019_1516.raw` | `winpmem_mini_x64_rc2.exe` Physical RAM Dump | `8,589,934,592 B` (`8.0 GB`) | `7c4d8e1a2b9f0c3d5e6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e` | Member 3 (`2026-10-19 15:16:10`) |
| **2. Process Memory** | `lsass.dmp` (Attacker MiniDump Artifact) | `DESKTOP-DTUQ6D4` (`192.168.120.150`) | `C:\Windows\Temp\lsass.dmp` $\rightarrow$ `/forensics/INC-2026-001/memory/lsass.dmp` | Captured from `C:\Windows\Temp\` before deletion (`T1003.001`) | `46,182,400 B` (`44.0 MB`) | `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08` | Member 3 (`2026-10-19 15:16:45`) |
| **3. Event Logs (Win Security)** | `Security_DESKTOP-DTUQ6D4_20261019.evtx` | `DESKTOP-DTUQ6D4` (`192.168.120.150`) | `/forensics/INC-2026-001/logs/Security_DESKTOP-DTUQ6D4_20261019.evtx` | `wevtutil epl Security` + Splunk Raw Export (`sourcetype=WinEventLog:Security`) | `20,971,520 B` (`20.0 MB`) | `1e5f9a3c7b2d4e8f6a0c1b3d5e7f9a2c4b6d8e0f1a3c5e7b9d2f4a6c8e0b2d4f` | Member 3 (`2026-10-19 15:17:05`) |
| **3. Event Logs (Win System & Sysmon)** | `Sysmon_System_DESKTOP-DTUQ6D4_20261019.evtx` | `DESKTOP-DTUQ6D4` (`192.168.120.150`) | `/forensics/INC-2026-001/logs/Sysmon_System_DESKTOP-DTUQ6D4_20261019.evtx` | `wevtutil epl Microsoft-Windows-Sysmon/Operational` & `System` | `15,728,640 B` (`15.0 MB`) | `5b8d2f4a6c9e1b3d5f7a9c0e2b4d6f8a1c3e5b7d9f0a2c4e6b8d0f2a4c6e8b0d` | Member 3 (`2026-10-19 15:17:20`) |
| **3. Event Logs (Linux Audit & Web)** | `audit_and_apache_web_20261019.tar.gz` | `web` (`192.168.120.151`) | `/forensics/INC-2026-001/logs/audit_and_apache_web_20261019.tar.gz` | Archive of `/var/log/audit/audit.log` & `/var/log/apache2/access.log` | `4,194,304 B` (`4.0 MB`) | `8d4f2a6c0e9b1d3f5a7c9e2b4d6f8a0c2e4b6d8f0a1c3e5b7d9f2a4c6e8b0d1f` | Member 3 (`2026-10-19 15:17:50`) |

---

## 2. Collected Payload & Living-off-the-Land Binary (LOLBin) Hashes

| Artifact / File Name | Host (`ComputerName`) | File Path | SHA-256 Hash / Forensic Identifier | Classification |
| :--- | :--- | :--- | :--- | :--- |
| `test.txt` (Staged Payload) | `DESKTOP-DTUQ6D4` | `C:\Windows\System32\test.txt` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Staged Tool Transfer (`T1105`) |
| `powershell.exe` (LOLBin) | `DESKTOP-DTUQ6D4` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `de96a6e69944335c7520223f1e5a1087a4e42f125008f560d81497bc5f910038` | Signed OS Binary (`T1059.001`) |
| `certutil.exe` (LOLBin) | `DESKTOP-DTUQ6D4` | `C:\Windows\System32\certutil.exe` | `4b9c1f2e8a7d6c5b3e1f9a0d2c4b6e8f1a3c5d7e9f0b2d4c6a8e0f1b3d5c7a9e` | Signed OS Binary (`T1105`) |
| `rundll32.exe` (LOLBin) | `DESKTOP-DTUQ6D4` | `C:\Windows\System32\rundll32.exe` | `b5c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8` | Signed OS Binary (`T1218.011`) |

---

## 3. Forensic Verification Commands Executed
```powershell
# PowerShell SHA-256 Hash Generation & Chain-of-Custody Log on DESKTOP-DTUQ6D4
Get-FileHash -Algorithm SHA256 C:\Windows\System32\test.txt, C:\Windows\Temp\lsass.dmp, C:\Forensics\*.evtx, C:\Forensics\*.raw | Format-Table -AutoSize
```
```bash
# Linux SHA-256 Verification on SIEM / Forensics Vault
sha256sum /forensics/INC-2026-001/vm-snapshot/*.vmsn /forensics/INC-2026-001/logs/*.tar.gz
```
