🛡️ Lab Report: Alert Triage with Splunk

📝 Incident Summary

Objective: Investigate and triage a security alert using Splunk SIEM, validate suspicious activity, identify relevant Indicators of Compromise (IoCs), and determine the appropriate containment action.

Platform: TryHackMe
Room: Alert Triage with Splunk
Primary Tool: Splunk SIEM
Focus: Alert Triage, SPL, Windows Event Logs, Sysmon, IoC Analysis, True/False Positive Classification

🎯 Outcome

The investigation followed a SOC Tier 1 alert-triage workflow:

Established an event timeline from the available telemetry.

Filtered relevant Windows/Sysmon events using SPL.

Investigated process creation and command-line activity.

Reviewed authentication activity for signs of account misuse or lateral movement.

Identified suspicious Living-off-the-Land (LotL) behaviour.

Classified the alert as requiring containment and escalation to Incident Response.

🔍 Investigation Methodology

The investigation was approached using a standard SOC workflow:

Alert → Scope → Timeline → Process Analysis → Authentication Analysis → IoC Extraction → Triage Decision → Containment

The main objective was to reduce SIEM noise and move from broad telemetry to a small set of events that could explain the alert.

1. Establishing the Timeline

The first step was to review the relevant indexes and sort events chronologically.

index=win-alert OR index=main *
| sort + _time

Why this matters

A chronological timeline helps establish:

What happened first

Which process was executed

Which account was involved

Whether network activity followed execution

Whether additional authentication events occurred afterwards

SOC takeaway: Individual events can be benign in isolation. Correlating them chronologically often reveals the attack chain.

2. Process Creation & Command-Line Analysis

Sysmon Event ID 1 was used to investigate process creation.

index=main sourcetype="WinEventLog:Sysmon" EventCode=1
| table _time, host, user, Image, CommandLine, ParentImage
| sort + _time

Investigation focus

The following fields were prioritised:

Field

Why it matters

_time

Establishes the execution timeline

host

Identifies the affected endpoint

user

Shows the account responsible for execution

Image

Identifies the executable

CommandLine

Reveals execution arguments and attacker intent

ParentImage

Helps identify the process execution chain

Key observation

The presence of legitimate Windows utilities such as:

powershell.exe

net.exe

does not automatically indicate malicious activity.

The analyst must assess context, command-line arguments, parent process, user, timing and surrounding events before classifying the activity.

This is particularly important when investigating Living-off-the-Land (LotL) techniques.

3. Authentication & Lateral Movement Verification

Windows Event ID 4624 was reviewed to identify successful logons around the investigation timeframe.

index=win-alert EventCode=4624
| table _time, ComputerName, TargetUserName, WorkstationName, IpAddress
| sort + _time

Investigation focus

The following questions were considered:

Was a successful logon associated with the suspicious activity?

Which account was used?

Did the source workstation/IP make sense?

Was the authentication expected for that user?

Did the activity suggest possible lateral movement?

Authentication telemetry is particularly valuable when correlated with process execution and network events.

4. Key Windows & Sysmon Telemetry

Event ID

Telemetry

SOC Use

4624

Successful Logon

Authentication and lateral movement analysis

4688

Process Creation

Process and command-line investigation

Sysmon 1

Process Creation

Detailed process-tree analysis

Sysmon 3

Network Connection

Outbound connection and C2 investigation

The strongest investigations correlate multiple telemetry sources rather than relying on a single Event ID.

🚨 Indicators of Compromise

The following IoCs/artifacts were relevant to the investigation:

Category

Indicator

Significance

C2 / External IP

[EXTERNAL_IP]

Suspicious external destination identified during network analysis

File Hash

[FILE_HASH]

Cryptographic identifier for the suspicious payload

Executable

powershell.exe / net.exe

Legitimate tools potentially abused for malicious activity

Account

[ACCOUNT_NAME]

User account associated with suspicious activity

Host

[HOST_NAME]

Endpoint associated with the alert

Note: Replace the bracketed values with the exact IoCs obtained from the TryHackMe investigation. Do not invent or generalise IoCs in the final portfolio entry.

🧠 True Positive vs False Positive Analysis

A key part of SOC alert triage is determining whether an alert represents malicious activity.

False Positive indicators

Examples could include:

Expected administrative PowerShell activity

Known IT maintenance scripts

Approved account-management commands

Normal system-generated network connections

True Positive indicators

Examples could include:

Unexpected PowerShell execution

Suspicious or encoded command-line arguments

Unusual parent/child process relationships

Execution under an unexpected account

Connections to suspicious external infrastructure

Authentication activity inconsistent with the user's normal behaviour

Multiple correlated indicators occurring within the same timeframe

Triage conclusion

Based on the correlated telemetry and suspicious execution behaviour observed in the lab, the alert should be treated as a True Positive / suspected compromise and escalated for Incident Response.

🎯 MITRE ATT&CK Mapping

Technique

ID

Relevance

Command and Scripting Interpreter: PowerShell

T1059.001

PowerShell can be abused to execute malicious commands

Windows Command Shell

T1059.003

Command-line utilities can be used for execution and discovery

System Network Connections Discovery

T1049

Network connection telemetry can reveal suspicious communication

Remote Services / Lateral Movement

T1021

Authentication and remote activity can indicate movement between hosts

MITRE mappings should be treated as investigative hypotheses unless the observed evidence clearly supports the technique.

🛑 Triage Decision

Decision: ISOLATE HOST + ESCALATE TO INCIDENT RESPONSE

The affected endpoint should be isolated from the network to prevent:

Further command-and-control communication

Lateral movement

Additional payload execution

Potential data exfiltration

The incident should then be escalated according to the organisation's Incident Response procedure.

🔧 Recommended Response Actions

Immediate Containment

Isolate the affected endpoint from the network.

Preserve relevant logs and forensic evidence.

Identify all accounts involved in the activity.

Review recent authentication events.

Block confirmed malicious external infrastructure where appropriate.

Eradication & Recovery

Reset credentials for confirmed compromised accounts.

Investigate scheduled tasks and startup mechanisms.

Review registry persistence locations.

Inspect suspicious executables and hashes.

Search the wider environment for the same IoCs.

Confirm that no additional endpoints show related activity.

Restore the affected host only after containment and remediation are complete.

🛠️ SPL Skills Demonstrated

This lab strengthened my ability to use:

table

sort

stats

Field filtering

EventCode filtering

Timeline reconstruction

Process-tree analysis

Command-line analysis

Authentication-event investigation

IoC-focused searching

Example of focused field extraction

index=main sourcetype="WinEventLog:Sysmon" EventCode=1
| table _time, host, user, Image, CommandLine, ParentImage
| sort + _time

Using table was particularly useful because it converts noisy raw telemetry into a focused dataset containing only the fields required for investigation.

💡 Key Learning Outcomes

1. Triage is about context

A suspicious executable name alone is not enough to declare an incident.

The analyst needs to correlate:

Process + User + CommandLine + Parent Process + Authentication + Network Activity

2. LotL requires behavioural analysis

Tools such as PowerShell and net.exe are legitimate Windows components. Attackers can abuse them without introducing obviously malicious binaries.

3. SPL reduces investigation time

Efficient field filtering allows an analyst to move quickly from thousands of raw events to a small number of relevant events.

4. Timeline reconstruction is critical

Understanding the order of execution, authentication and network activity helps determine whether events are related to the same incident.

5. A SOC analyst must make a decision

The investigation should ultimately produce an operational outcome:

Benign → Close / document

Suspicious → Escalate / investigate further

Confirmed malicious → Contain / escalate / investigate

📌 Analyst Reflection

This lab improved my understanding of how a Tier 1 SOC analyst approaches an alert in a SIEM.

The most valuable part was learning to avoid investigating events individually. Instead, I focused on building a timeline and correlating process execution, command-line arguments, authentication activity and network telemetry.

I also gained more confidence using SPL to reduce noisy datasets and present only the fields required for an investigation.

Most importantly, the lab reinforced that alert triage is not simply finding a suspicious event — it is deciding whether the evidence supports escalation and what action should happen next.

🧰 Tools Used

Splunk SIEM — log search, filtering and investigation

TryHackMe — controlled SOC investigation environment
