# Project: Linux Threat Detection 2

**Objective:** Advanced analysis of malicious activity within a Linux environment, focusing on log inspection and process behavioral analysis.

### 🔍 Key Skills Demonstrated
* **Process Auditing:** Tracing suspicious process execution using `auditd` and monitoring process creation.
* **Log Analysis:** Deep dive into `/var/log/auth.log`, `syslog`, and `journald` to identify anomalous authentication attempts and persistence mechanisms.
* **Forensic Artifacts:** Investigating common Linux persistence locations (cron jobs, systemd services, SSH keys).

### 🛠 Tools Used
* `grep`, `awk`, `sed` (Log filtering)
* `ps`, `top`, `htop` (Live process monitoring)
* `auditd` (System call auditing)

### 💡 Core Insight
This lab highlighted how attackers leverage standard system services for persistence. The ability to distinguish between legitimate system maintenance (e.g., cron jobs) and attacker-controlled persistence is critical for effective threat hunting.
