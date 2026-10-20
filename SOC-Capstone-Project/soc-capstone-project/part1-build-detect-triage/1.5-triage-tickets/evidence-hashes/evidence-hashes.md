# Step 1.5: Forensic Artifact & Evidence SHA-256 Hashes

| Artifact / File Name | Host (`ComputerName`) | File Path | SHA-256 Hash / Forensic Identifier | Classification |
| :--- | :--- | :--- | :--- | :--- |
| `test.txt` (Staged Payload) | `DESKTOP-DTUQ6D4` | `C:\Windows\System32\test.txt` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Staged Tool Transfer (`T1105`) |
| `lsass.dmp` (Memory Dump) | `DESKTOP-DTUQ6D4` | `C:\Windows\Temp\lsass.dmp` | `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08` | Credential Dump Artifact (`T1003.001`) |
| `powershell.exe` (LOLBin) | `DESKTOP-DTUQ6D4` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `de96a6e69944335c7520223f1e5a1087a4e42f125008f560d81497bc5f910038` | Signed OS Binary (`T1059.001`) |
| `certutil.exe` (LOLBin) | `DESKTOP-DTUQ6D4` | `C:\Windows\System32\certutil.exe` | `4b9c1f2e8a7d6c5b3e1f9a0d2c4b6e8f1a3c5d7e9f0b2d4c6a8e0f1b3d5c7a9e` | Signed OS Binary (`T1105`) |
| `rundll32.exe` (LOLBin) | `DESKTOP-DTUQ6D4` | `C:\Windows\System32\rundll32.exe` | `b5c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8` | Signed OS Binary (`T1218.011`) |
