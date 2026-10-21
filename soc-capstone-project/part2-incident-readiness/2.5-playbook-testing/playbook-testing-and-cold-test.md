# Step 2.5: Playbook Timed Execution, External Cold Test & Playbook Changelog (6 Points)

**Task Owner:** Member 3 *(Linux & Forensics Lead)* | **Peer Reviewer:** Member 2 *(SIEM Architect)*

---

## 1. Internal Team Timed Execution of All 3 Playbooks ("Fire the Rule and Follow Each Playbook with a Timer")
Each of the 3 playbooks (`PB-01`, `PB-02`, `PB-03`) was tested live in our isolated Splunk lab (`192.168.120.0/24`) by firing its triggering Part 1 detection rule(s) on `DESKTOP-DTUQ6D4` (`192.168.120.150`) and `web` (`192.168.120.151`) while recording stopwatch split times from **Alert Trigger (`T+00:00`)** to **First Containment Action** and **Full Playbook Closure**:

| Playbook ID & Name | Triggering Part 1 Rule Fired | Stage 1–2: Alert & Triage Time | Stage 3: Decision Time | Stage 4: First Correct Containment Action Time *(Team Baseline)* | Stage 5: Evidence Hashing Time | Stage 6–8: Eradication, Recovery & Closure | Total End-to-End Run Time | Proof Screenshot |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **`PB-01`: Credential Dumping (`T1003.001`)** | **Rule 04** (`rundll32 comsvcs.dll MiniDump lsass`) | `01m 55s` | `00m 35s` | **`03m 40s`** (`New-NetFirewallRule SOC_Contain_Outbound_C2`) | `02m 45s` (`Get-FileHash lsass.dmp`) | `04m 55s` (`Remove-Item` + `0 events` check) | **`11m 20s`** | `../../part3-proof/screenshots/proof for part 3.png` |
| **`PB-02`: PowerShell & Tool Staging (`T1059.001` / `T1105`)** | **Rule 01** (`powershell -enc`) & **Rule 08** (`certutil -urlcache`) | `01m 40s` | `00m 30s` | **`03m 10s`** (`Stop-Process` + Outbound C2 Firewall Block) | `02m 05s` (`Get-FileHash test.txt`) | `04m 30s` (`Remove-Item test.txt` + `urlcache delete`) | **`09m 45s`** | `../../part3-proof/screenshots/for part  3 2.png` |
| **`PB-03`: Brute Force & Persistence (`T1110` / `T1053` / `T1098`)** | **Rule 05** (`4625->4624`), **Rule 02/03** (`schtasks`/`sc`), **Rule 09/10** (`cron`/`ssh`) | `02m 15s` | `00m 40s` | **`04m 05s`** (`Disable-LocalUser` + Firewall Block) | `02m 30s` (`tar` + `sha256sum` logs) | `05m 35s` (`schtasks /delete`, `sed -i /etc/crontab`) | **`12m 10s`** | `../../part3-proof/screenshots/recovery_verification_0_events.png` |

---

## 2. External Cold Test Evaluation ("A Student from Another Team Uses One Playbook Alone")
Per **Step 2.5**:
* **Cold Test Rubric Criteria:**
  * External student from another team executes the playbook **alone** after we fire the rule.
  * **Pass Condition 1 (Speed):** Correct first containment action completed within **$2\times$ our team baseline time** ($2 \times 03\text{m }40\text{s} = \mathbf{07\text{m }20\text{s}}$ max allowed for `PB-01`).
  * **Pass Condition 2 (Clarity):** **Maximum 2 questions** asked during execution.

### 2.1 Cold Test Execution Log (`Playbook PB-01: Credential Dumping & Host Containment`)

| Cold Test Parameter | Recorded Details & Stopwatch Measurements | Rubric Requirement | Verdict |
| :--- | :--- | :--- | :---: |
| **External Tester Identity** | Student Analyst from **Team Beta (Group 2)** — had zero prior exposure to our lab rules or `PB-01` draft (`v1.0`) | Student from another team working alone | **Verified** |
| **Trigger Fired (`T+00:00`)** | Fired **Rule 04 (`T1003.001`)** + **Rule 02 (`T1053.005`)** on `DESKTOP-DTUQ6D4` (`192.168.120.150`) | Fire the rule | **Verified** |
| **Team Baseline to First Action** | **`03m 40s`** (`220 seconds`) | Baseline timer recorded | — |
| **Max Allowed Cold-Test Time ($2\times$)** | **`07m 20s`** (`440 seconds`) | $\le 2\times$ team time | — |
| **External Tester Actual Time to Correct First Action** | **`05m 15s`** (`315 seconds` — executed `New-NetFirewallRule -DisplayName "SOC_Contain_Outbound_C2" -Direction Outbound -Action Block` on `DESKTOP-DTUQ6D4`) | $\le 07\text{m }20\text{s}$ ($1.43\times$ baseline) | **PASS** |
| **External Tester Total Completion Time** | **`15m 40s`** (Completed SHA-256 hashing of `lsass.dmp`, deleted `SOC_Test_Task`, and verified `0 events` in Splunk) | Full playbook completion | **PASS** |
| **Number of Questions Asked** | **`1 Question`** *(See exact transcript below)* | **Max 2 questions** ($\le 2$) | **PASS (1 / 2)** |

### 2.2 Verbatim Log of the 1 Question Asked & Observer Notes During Cold Test
* **Question #1 (Asked at `T+02m 10s` during Stage 2 Triage):**
  > *"In Stage 2 of your playbook, the SPL table command references generic Sigma field names `Image` and `CommandLine`, which appear blank in `WinEventLog:Security` EventCode 4688 unless I expand the event—should I use `New_Process_Name` and `Process_Command_Line` instead?"*
  * **Observer Answer Given:** *"Yes, use `New_Process_Name` and `Process_Command_Line`."* (Tester immediately found `rundll32.exe ... comsvcs.dll, MiniDump` and proceeded to Stage 4 Containment without asking any further questions.)
* **Observer Friction Note (Recorded at `T+11m 05s` during Stage 6 Eradication — No question asked):**
  * When the tester ran `sc.exe delete "SOC_Test_Svc"`, Windows returned `[SC] OpenService FAILED 1060` (visible in `../../part3-proof/screenshots/proof for part 3.png`) because the service had already been removed or was in a stopped state, and when running `Remove-Item` on `lsass.dmp` the tester had to confirm the exact `C:\Windows\Temp\` path.

---

## 3. Fixes Applied to Playbooks & Complete Changelog (`v1.0` $\rightarrow$ `v1.1` / `v1.2`)
Per **Step 2.5** (*"Fix the playbooks and list the changes"*), all friction points discovered during the timed runs and the external cold test were immediately fixed in `2.4-playbooks/`:

| Change # | Affected Playbook(s) | Defect / Friction Identified During Testing | Exact Fix Applied to Playbook (`v1.1` / `v1.2`) |
| :---: | :--- | :--- | :--- |
| **Fix 1** | `PB-01`, `PB-02`, `PB-03` (Stage 2 Triage) | Cold-test participant noted that raw `WinEventLog:Security` (`EventCode=4688`) populates `New_Process_Name`, `Creator_Process_Name`, and `Process_Command_Line` rather than unmapped Sigma field names (`Image`, `CommandLine`). | Updated all Stage 2 SPL queries in `PB-01`, `PB-02`, and `PB-03` to explicitly output `Account_Name, Creator_Process_Name, New_Process_Name, Process_Command_Line` so analysts see process details immediately in the statistics table. |
| **Fix 2** | `PB-01`, `PB-02` (Stage 4 Containment) | Draft `v1.0` said *"Block outbound C2 traffic in Windows Firewall"* without providing the exact `-RemoteAddress` parameter, costing ~45 seconds of syntax lookup. | Added the complete copy-pasteable PowerShell one-liner: `New-NetFirewallRule -DisplayName "SOC_Contain_Outbound_C2" -Direction Outbound -Action Block -RemoteAddress 198.51.100.0/24` followed by `Get-NetFirewallRule` verification. |
| **Fix 3** | `PB-01`, `PB-03` (Stage 6 Recovery) | Running `sc.exe delete "SOC_Test_Svc"` directly without stopping a running service or suppressing non-existent service errors caused console warnings (`FAILED 1060`). | Updated Stage 6 to run `Stop-Service -Name "SOC_Test_Svc" -Force -ErrorAction SilentlyContinue ; sc.exe delete "SOC_Test_Svc" 2>$null` and added `-ErrorAction SilentlyContinue` to `Remove-Item`. |
| **Fix 4** | `PB-01`, `PB-02` (Stage 5 Evidence) | Analysts risked running Stage 6 `Remove-Item` before computing the SHA-256 hash of `lsass.dmp` and `test.txt`. | Added a bold warning banner in Stage 5 and moved `Get-FileHash -Algorithm SHA256` directly above the eradication commands so evidence hashing is mandatory before deletion. |
