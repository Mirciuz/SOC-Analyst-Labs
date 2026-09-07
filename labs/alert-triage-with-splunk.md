# Alert Triage with Splunk

## 📝 Lab Overview

* **Focus:** Investigating and triaging security alerts using Splunk SIEM.
* **Key Skills:** Alert Triage, SPL, Windows Event Logs, Sysmon, IoC Analysis, True/False Positive Analysis.
* **Environment:** TryHackMe Lab.
* **Room:** [Alert Triage with Splunk](https://tryhackme.com/room/alerttriagewithsplunk)

---

## 🔍 Key Concepts

* **SIEM Triage:** Filtering large amounts of security telemetry to identify events that require further investigation.
* **SPL:** Using Splunk Processing Language to search, filter and organise security events.
* **Process Analysis:** Investigating Windows process creation events, command lines and parent/child relationships.
* **Windows Event IDs:** Understanding Event ID `4624` for successful logons and Event ID `4688` / Sysmon Event ID `1` for process creation.
* **Network Activity:** Using Sysmon Event ID `3` to investigate suspicious network connections.
* **Living-off-the-Land:** Recognising how attackers can abuse legitimate Windows utilities such as `powershell.exe` and `net.exe`.

### 🔎 Useful SPL Queries

```spl
index=win-alert OR index=main *
| sort + _time
```

Used to create a chronological view of the available events and establish an initial timeline.

```spl
index=main sourcetype="WinEventLog:Sysmon" EventCode=1
| table _time, host, user, Image, CommandLine, ParentImage
| sort + _time
```

Used to investigate process creation, command-line arguments and parent/child process relationships.

```spl
index=win-alert EventCode=4624
| table _time, ComputerName, TargetUserName, WorkstationName, IpAddress
| sort + _time
```

Used to review successful logons and identify potentially suspicious authentication activity.

---

## 📝 Reflective Analysis

### 🧠 What I Learned (Strengths)

* **SIEM Triage:** Improved my ability to move from a broad security alert to the specific events that actually require investigation.
* **SPL Query Building:** Became more comfortable using commands such as `table` and `sort` to turn raw Splunk data into a much cleaner investigation view.
* **Process Analysis:** Learned how important the `CommandLine`, `Image` and `ParentImage` fields are when investigating suspicious process execution.
* **Timeline Analysis:** Understanding the order of events helped me connect process execution, authentication and network activity instead of analysing each event in isolation.
* **Living-off-the-Land Detection:** Improved my understanding that legitimate Windows tools such as PowerShell can still be suspicious depending on how and when they are used.
* **True vs False Positive Analysis:** Practiced looking at the surrounding context of an alert before deciding whether it represents malicious activity.

### ⚠️ Challenges & Areas for Improvement

* **SPL Efficiency:** I can perform the basic searches required for triage, but I need more practice with `stats`, `eval`, `rex`, `where` and more advanced filtering.
* **Process Trees:** Understanding parent/child process relationships was initially challenging, especially when legitimate Windows processes were involved.
* **Alert Context:** One of the main challenges was avoiding the assumption that a single suspicious-looking event automatically means compromise. More contextual correlation is needed.
* **Windows Telemetry:** I need to continue building familiarity with Windows Event IDs and Sysmon so that I can recognise suspicious behaviour faster during future investigations.

### 🛠 Next Steps

* **Advanced SPL:** Practice building more complex searches using `stats`, `rex`, `eval`, `where` and `transaction`.
* **Detection Engineering:** Start creating my own Splunk searches for common SOC detections such as suspicious PowerShell, brute-force authentication and unusual network connections.
* **Windows Investigation:** Continue studying Windows Event IDs and Sysmon telemetry to improve endpoint investigation skills.
* **MITRE ATT&CK:** Map observed behaviours to relevant ATT&CK techniques during future investigations.
* **Incident Response:** Practice progressing from alert triage into containment, scoping and remediation decisions.
