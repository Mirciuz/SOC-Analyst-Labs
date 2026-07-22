# Project: File and Hash Threat Intelligence Analysis

**Objective:** Mastering the identification, extraction, and verification of file hashes to assess malicious payloads and leverage threat intelligence platforms effectively.

### 🔍 Key Skills Demonstrated
* **Cryptographic Hashing:** Understanding the role of MD5, SHA-1, and SHA-256 in identifying unique file signatures and tracking malware variants.
* **Reputation Lookup & Triage:** Querying threat intelligence platforms to cross-reference file hashes against known malware databases.
* **Handling Artifacts:** Safely extracting and managing suspicious file samples without risking endpoint integrity.

### 🛠 Tools & Concepts Used
* **Command Line Utilities:** Generating file hashes using native OS tools (`certutil`, `sha256sum`).
* **Threat Intel Aggregators:** Utilizing platforms like VirusTotal and specialized hashing databases for rapid triage.
* **The Pyramid of Pain:** Applying hash analysis as the foundational, yet easily mutable, layer of adversary indicators.

### 💡 Core Insight
This lab demonstrated that while file hashes are powerful for instant identification of known threats, advanced threat actors easily modify files to change their hashes (polymorphism). Therefore, hashing is just the first line of defense; it must be paired with behavioral analysis and TTP tracking.

---
[< Back to Index](../README.md)
