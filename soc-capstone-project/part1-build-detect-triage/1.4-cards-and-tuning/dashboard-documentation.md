# Step 1.4: 5-Panel SOC Operations Dashboard Documentation

**Dashboard Screenshot:** `dashboard.png` (`SOC Operations Dashboard1` in Splunk Enterprise)

## Overview of the 5 Operational Panels
Per **Step 1.4** (*"Dashboard with 5+ panels"*), our Splunk SOC Operations Dashboard provides real-time situational awareness across Windows (`DESKTOP-DTUQ6D4`), Linux (`web`), and Web/Firewall telemetry:

| Panel # | Panel Title | Visualization Type | Underlying SPL Query | Operational Purpose for SOC Analysts |
| :---: | :--- | :--- | :--- | :--- |
| **Panel 1** | **Top Triggered Event Signatures** | Horizontal Bar Chart | `index=* sourcetype="WinEventLog:*" \| stats count by EventCode \| sort - count \| head 10` | Highlights spikes in process creation (`4688`), object auditing (`4907`), and logons (`4624`/`4625`). |
| **Panel 2** | **Logon Activity (Failed vs. Success)** | Statistics Table | `index=* sourcetype="WinEventLog:Security" EventCode IN (4624, 4625) \| stats count by EventCode, Account_Name, ComputerName \| sort - count` | Tracks authentication volume per account (`SYSTEM`, `SplunkForwarder`, `FakeAdmin`) to spot brute-force anomalies. |
| **Panel 3** | **Alerts & Events by Severity** | Pie Chart | `index=* \| eval Severity=case(EventCode=1102 OR match(_raw,"MiniDump"),"Critical", EventCode IN (4688,4698,7045),"High", EventCode=4625,"Medium", 1=1,"Low") \| stats count by Severity` | Gives shift analysts an immediate breakdown of Critical/High/Medium/Low event proportions. |
| **Panel 4** | **Windows & Linux Event Timeline** | Stacked Area Timeline | `index=* (host="DESKTOP-DTUQ6D4" OR host="web") \| timechart span=1h count by host` | Visualizes cross-host telemetry velocity over time to identify attack bursts or silent forwarder dropouts. |
| **Panel 5** | **Top Targeted Hosts** | Vertical Column Chart | `index=* \| stats count by host \| sort - count` | Compares total security event volume across monitored endpoints (`DESKTOP-DTUQ6D4` vs. `web`). |
