# Project: Log Analysis with SIEM

**Objective:** Mastering Security Information and Event Management (SIEM) concepts, log aggregation, normalization, and executing powerful queries to hunt for threats.

### 🔍 Key Skills Demonstrated
* **Log Aggregation & Normalization:** Understanding how disparate data sources (Windows Event Logs, Sysmon, Firewall, Web Servers) feed into a SIEM and are normalized into cohesive fields
*  (`src_ip`, `user`, `event_code`).
* **Querying & Filtering:** Writing efficient search queries to parse massive datasets, isolate timeframes, and filter out false positives.
* **Triage & Investigation:** Investigating suspicious user account activity, unauthorized process execution, and network anomalies using correlated telemetry.

### 🛠 Tools & Concepts Used
* **SIEM Platforms:** Practical application using Splunk fundamentals and detection engineering syntax.
* **Windows Event Tracking:** Leveraging critical EventCodes (e.g., 4720 for user creation, Sysmon EventCodes 1 and 3 for process execution and network connections).
* **Time Management in SIEMs:** Handling timezone normalization and timestamp discrepancies during incident timeline reconstruction.

### 💡 Core Insight
This lab reinforced that a SIEM is only as good as the data it ingests and the quality of the queries written by the analyst.
Normalization is the bridge that transforms raw noise into actionable intelligence, allowing an analyst to connect the dots across multiple systems during an active incident.

---
[< Back to Index](../README.md)
