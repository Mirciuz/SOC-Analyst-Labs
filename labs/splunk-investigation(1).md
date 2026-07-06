# Lab Report: Investigating with Splunk

## 📝 Incident Summary
* **Objective:** Investigate anomalous Windows activity and backdoor creation identified by the SOC team.
* **Tooling:** Splunk SIEM.
* **Outcome:** Successfully identified the backdoor user, the persistence mechanism, and the exfiltration/callback vector.

---

## 🔍 Investigation Findings

### 1. Backdoor User Creation (Persistence)
* **Detection:** Utilized Event ID `4720` (User Account Created).
* **Finding:** Identified the creation of user `A1berto`. 
* **Persistence Mechanism:** Confirmed registry modification via Event ID `13` (Registry Event). 
    * **Path:** `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto`

### 2. Attack Execution (Lateral Movement)
* **Technique:** Use of WMI (Windows Management Instrumentation) for remote process creation.
* **Command Identified:**
  `"C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"`
* **Target:** `James.browne` (Host identified as the source of suspicious PowerShell activity).

### 3. PowerShell Analysis & De-obfuscation
* **Logging:** Identified `79` events related to PowerShell execution using Event ID `4103`.
* **Encoded Payload:** Recovered Base64 encoded PowerShell script.
* **De-obfuscation Process:** Extracted Base64 string and processed via CyberChef (From Base64 -> Decode Text).
* **C2/Web Request:** Identified malicious callback to: `hxxp://10.10.10.5/news.php`

---

## 🛠 Investigative Methodology (Reflection)
* **Query Crafting:** Learned the importance of filtering by specific Event IDs (4720, 13, 4103) to reduce noise in the `main` index.
* **Data Correlation:** This lab reinforced how different log sources (Security logs + Sysmon + PowerShell logs) must be correlated to reconstruct the attacker's timeline.
* **Tooling:** Gained proficiency in using Splunk as a primary investigative tool, specifically moving from raw log analysis to targeted search queries.

---
## 💡 Triage Decision Framework
* **Containment:** Host `James.browne` must be isolated.
* **Eradication:** Delete backdoor user `A1berto` and purge malicious registry keys.
* **Remediation:** Investigate the source IP `10.10.10.5` for potential lateral movement across the network.

---
*Return to [Lab Index](/labs)*
