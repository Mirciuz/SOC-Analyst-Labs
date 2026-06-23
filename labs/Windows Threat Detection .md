📝 Lab Report: Windows Threat Detection 3



🔍 Focus
Advanced Detection: Moving beyond simple alerts to complex behavior analysis.
Log Correlation: Linking Sysmon, Event Logs, and PowerShell logs for a full story.
Hardening: Understanding how to patch the vulnerabilities that allowed these threats.



📝 Reflective Analysis
🧠 What I Learned (Strengths)
Advanced Correlation: I’ve become much faster at linking disparate log sources (e.g., correlating a PowerShell execution with a subsequent network connection event).
Behavioral Analysis: I am now identifying "Living-off-the-Land" (LotL) techniques—where attackers use legitimate system tools (like certutil, vssadmin, or bitsadmin) to perform malicious tasks.
Triage Efficiency: I have significantly reduced the time it takes to "scope" an incident—from detecting the initial compromise to determining if the attacker escalated privileges.

⚠️ Challenges & Areas for Improvement
Encoded Commands: Dealing with heavily obfuscated PowerShell commands is still a challenge; I had to spend extra time de-obfuscating scripts to understand the intent.
Context Blindness: I occasionally struggle to identify why a legitimate admin tool was used. Developing the ability to differentiate between "Admin troubleshooting" and "Attacker activity" is a priority for me.

🛠 Next Steps
De-obfuscation Labs: I need to find specific labs or challenges focused on reversing PowerShell obfuscation techniques.
Detection Engineering: I want to start moving from just detecting these attacks to preventing them by creating custom Sigma Rules or Detection Logic based on what I’ve learned here.

💡 Investigation Methodology
(Link to your investigative-methodology.md here)
Return to Lab Index
