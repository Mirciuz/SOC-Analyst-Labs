# Linux Threat Detection 1

## 📝 Lab Overview
* **Focus:** Identifying malicious activity within Linux environments using native logs and command-line tools.
* **Key Skills:** Log Analysis (`/var/log`), CLI parsing (grep, cat, awk), User & Group Auditing.
* **Environment:** TryHackMe Lab.

---

## 🔍 Key Concepts
*   **Log Locations:** Mastering the `/var/log` directory (specifically `auth.log` or `secure` for authentication, and `syslog`).
*   **Command History:** Analyzing `.bash_history` to track an attacker's post-compromise actions.
*   **CLI Triage:** Using commands like `grep` to filter through massive text-based log files efficiently.

---

## 📝 Reflective Analysis

### 🧠 What I Learned (Strengths)
* **Cross-OS Versatility:** Transitioning my detection mindset from Windows (GUI/Event Viewer) to the Linux command line.
* **Authentication Tracking:** Successfully identifying SSH brute-force attacks and unauthorized successful logins by parsing `auth.log`.
* **CLI Fundamentals:** Improving my speed at chaining commands (using pipes `|`) to filter and extract specific indicators of compromise (IOCs) from raw text files.

### ⚠️ Challenges & Areas for Improvement
* **CLI Filtering:** Navigating and filtering text logs without a GUI SIEM requires memorizing syntax for tools like `awk` and complex `grep` regex, which initially slowed down my triage.
* **Artifact Locations:** Unlike Windows where events are centralized, Linux artifacts are scattered across different configuration files and directories. Memorizing these locations takes practice.

### 🛠 Next Steps
* **Advanced CLI Parsing:** I plan to practice my command-line text parsing skills to become faster at carving out specific IP addresses or usernames from log files.
* **Linux Persistence:** I want to dive deeper into how attackers maintain persistence in Linux (e.g., cron jobs, SSH keys) for the upcoming labs.

---
## 💡 Investigation Methodology
*(Link to [Investigative Methodology](/labs/investigative-methodology.md))*

---
*Return to [Lab Index](/labs)*
