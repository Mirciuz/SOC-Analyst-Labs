Windows Threat Detection 1

📝 Lab Overview
Focus: Identifying malicious activity within Windows environments using native tools.
Key Skills: Windows Event Viewer, Log Analysis, Process Tracking.
Environment: TryHackMe Lab.

🔍 Key Concepts
Log Analysis: Identifying the "Who, What, Where" of system events.
Key Event IDs:
4624: Successful Logon
4688: New Process Created
4625: Failed Logon
Process Masquerading: Identifying malicious processes pretending to be system services.

📝 Reflective Analysis
🧠 What I Learned (Strengths)
Event Log Proficiency: I gained a solid understanding of how to navigate the Windows Event Viewer to identify key events. My ability to distinguish between legitimate system activity and anomalous behavior has significantly improved.
Process Analysis: I developed a better grasp of how attackers often attempt to hide malicious activity by masquerading as legitimate system processes.
Pattern Recognition: I am now more confident in identifying the specific sequence of events that typically precede or follow an unauthorized access attempt.

⚠️ Challenges & Areas for Improvement
Log Volume Management: I initially found it challenging to handle the sheer volume of log data. I realized that without precise filtering, it is easy to get overwhelmed by irrelevant information.
Query Crafting: Writing complex filtering queries does not feel entirely natural yet; I had to perform several iterations before retrieving the correct data. This is an area where I need more practice to improve my triage speed.

🛠 Next Steps
Mastering Sysmon: I want to dive deeper into configuring and reading Sysmon logs, as I’ve learned they provide much more granular visibility compared to standard Windows logs.
SIEM Integration: My next goal is to understand how these Windows logs are ingested into a SIEM (like Splunk) and to start practicing the creation of correlation rules to detect these patterns automatically.

*Return to [Lab Index](/LABS_INDEX.md)*
