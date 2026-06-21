# Investigative Methodology: Post-Compromise Workflow

When an alert is triggered and I am analyzing a compromised host, I follow a systematic approach to ensure a thorough investigation. My goal is not just to identify the initial alert,
but to understand the full scope of the attacker's actions.

## 🔍 The Investigation Workflow

### 1. Establish the Timeline (Pivot & Trace)
* **Objective:** Create a chronological chain of events.
* **Actions:** 
    * Start from the initial alert (e.g., an unusual process start).
    * Pivot to events immediately *before* and *after* to see what triggered the activity.
    * Identify the origin: Was it a user action, a malicious download, or an automated script?

### 2. Identify Persistence Mechanisms
* **Objective:** Detect backdoors meant to maintain access after a reboot.
* **Actions:**
    * **Scheduled Tasks:** Look for new or suspicious tasks created during the incident window.
    * **Registry Keys:** Inspect `Run` and `RunOnce` keys.
    * **Services:** Investigate any newly created or modified system services.

### 3. Analyze Lateral Movement
* **Objective:** Determine the "Blast Radius"—did the attacker move to other systems?
* **Actions:**
    * Audit authentication logs (Event IDs 4624/4648).
    * Look for connections to internal network shares or RDP/SSH sessions from the compromised host to others.

### 4. Data Exfiltration or Impact
* **Objective:** Identify if sensitive data was targeted or removed.


* **Actions:**
    * Analyze network connection logs (e.g., Sysmon Event ID 3).
    * Look for indicators of staging: Is there evidence of data being compressed (e.g., `.zip`, `.rar`) or accessed in bulk?
    * Check for outbound connections to external/unauthorized IPs.

---

## 💡 Triage Decision Framework
Every investigation must conclude with a professional recommendation. Based on the evidence collected:
* **Containment:** If lateral movement is confirmed, the immediate step is to **Isolate the Host** from the network.
* **Eradication:** Once contained, the next steps include credential rotation and removal of the identified persistence mechanisms.
* **Reporting:** Documenting the findings for the incident response team to ensure a smooth handoff.

---
