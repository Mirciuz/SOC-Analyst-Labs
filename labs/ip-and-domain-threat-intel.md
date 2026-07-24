# Project: IP and Domain Threat Intelligence Analysis

**Objective:** Mastering network-based indicators (IP addresses and domains) to detect, pivot, and investigate adversary infrastructure during incident triage.

### 🔍 Key Skills Demonstrated
* **Network Indicator Triage:** Analyzing IP addresses and fully qualified domain names (FQDNs) extracted from security alerts or logs.
* **Infrastructure Pivoting:** Using passive DNS, WHOIS records, and threat feeds to map out an attacker's related infrastructure and campaign assets.
* **Network Telemetry Correlation:** Correlating outbound traffic anomalies with known malicious IPs/domains to confirm active C2 (Command and Control) communications.

### 🛠 Tools & Concepts Used
* **Reputation & Lookup Tools:** Utilizing VirusTotal, AbuseIPDB, and domain intelligence platforms.
* **Passive DNS & WHOIS:** Tracking historical domain registrations and name server changes to unmask threat actors.
* **The Pyramid of Pain:** Evaluating the impact of blocking IP/Domain indicators versus tracking deeper behavioral patterns.

### 💡 Core Insight
This lab highlighted that IP and domain indicators change more frequently than file hashes due to threat actors using fast-flux networks or disposable infrastructure. Therefore, a SOC analyst must leverage these indicators for immediate containment while focusing on TTPs for long-term detection.

---
[< Back to Index](../README.md)
