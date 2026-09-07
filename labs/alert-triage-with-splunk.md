Alert Triage with Splunk

Lab Overview
Focus: Triage, validation, and investigation of security alerts using Splunk SIEM[cite: 1, 4]
Key Skills: Alert Triage, SPL (Splunk Processing Language), Incident Response, IoC Extraction, True/False Positive Analysis[cite: 1, 4, 7]
Environment: TryHackMe Lab[cite: 1, 3]
Room: https://tryhackme.com/room/alerttriagewithsplunk[cite: 1]

Key Concepts
SIEM Triage Workflow: Filtering out environmental noise, isolating suspicious activity, and verifying if alerts are True Positives[cite: 1, 4]
Key Event IDs & Telemetry:
- 4624: Successful Logon[cite: 3]
- 4688 / Sysmon Event ID 1: Process Creation (CommandLine & Parent Process analysis)[cite: 2, 3]
- Sysmon Event ID 3: Network Connections[cite: 3, 5]
Living-off-the-Land (LotL): Identifying attackers abusing built-in system tools (e.g., PowerShell, net.exe) to execute malicious commands or conduct discovery[cite: 1, 2, 3]

Essential SPL Queries

1. Initial Alert Filtering & Timeline Creation
Goal: Filter by the target index and sort events chronologically to establish a baseline sequence[cite: 1, 2]
index=win-alert OR index=main * | sort + _time[cite: 1, 2]

2. Process Creation & Command Line Analysis
Goal: Extract process creation events to analyze parent/child process relationships and execution arguments[cite: 2, 3]
index=main sourcetype="WinEventLog:Sysmon" EventCode=1 | table _time, host, user, Image, CommandLine, ParentImage | sort + _time[cite: 1, 2]

3. Authentication & Lateral Movement Verification
Goal: Monitor user logons during the attack timeframe to detect potential lateral movement[cite: 2, 3]
index=win-alert EventCode=4624 | table _time, ComputerName, TargetUserName, WorkstationName, IpAddress | sort + _time[cite: 2]

Indicators of Compromise (IoCs)
C2 IP Address: [EXTERNAL_IP] - External destination IP for suspicious outbound connections[cite: 5]
Malicious Binary / Hash: [FILE_HASH] - SHA256 / MD5 cryptographic signature of the dropped payload[cite: 5]
Abused Executable: powershell.exe / net.exe - Legitimate system tools leveraged for execution or discovery[cite: 2, 3]
Target User: [ACCOUNT_NAME] - Account compromised or leveraged during the incident[cite: 1, 2]
Compromised Host: [HOST_NAME] - Target endpoint affected by the initial alert[cite: 1, 2]

Reflective Analysis & Key Observations

What I Learned & Key Observations
Uso Intelligente delle Tabelle (| table): Ho apprezzato particolarmente l'efficacia dell'uso del comando | table per trasformare log grezzi disordinati (_raw) in tabelle pulite, sintetiche e altamente pratiche da consultare durante il triage[cite: 1]. Estrarre solo i campi essenziali per ogni colonna rende l'analisi visivamente immediata e accelera la comprensione degli eventi[cite: 1].
Triage Efficiency: Significantly improved the speed of classifying alerts into True Positives versus False Positives by inspecting process execution trees and command arguments[cite: 1, 3, 4].
SPL Query Construction: Enhanced ability to manipulate Splunk Processing Language (using table, sort, stats, and field filters) to quickly transform raw logs into actionable intelligence[cite: 1, 2, 3].
Attack Scoping: Gained confidence in tracing an incident from initial execution through to discovery and lateral movement verification[cite: 3, 4].

Triage Decision & Remediation
Triage Decision: Isolate the Host from the network immediately and trigger the Incident Response Plan[cite: 3, 4]
Remediation Steps:
1. Force password resets for any affected accounts[cite: 3]
2. Block external C2 IP addresses on the perimeter firewall
3. Inspect scheduled tasks and registry keys for potential persistence mechanisms[cite: 2, 3]
