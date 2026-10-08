# 🛡️ TryHackMe – Incident Handling With Splunk

**Room:** [Incident Handling With Splunk](https://tryhackme.com/room/splunk201)  
**Platform:** TryHackMe  
**Tools:** Splunk SIEM, Sysmon, VirusTotal, ThreatMiner, Hybrid Analysis  
**Skills:** Log Analysis | Incident Investigation | SPL | Threat Intelligence | IOC Identification

## 🎯 Objective

This lab focused on investigating a simulated cyberattack using **Splunk SIEM** and mapping suspicious activities to the **Cyber Kill Chain**.

The scenario involved a compromised Joomla web server, a brute-force attack, suspicious executable files and potential Command & Control (C2) communications.

The goal was to analyse security events, identify Indicators of Compromise (IOCs) and understand how different log sources help reconstruct an attack.

---

## 🔎 1. Reconnaissance & Exploitation

The investigation started by analysing HTTP traffic related to the target website:

`imreallynotbatman.com`

**Compromised server:** `192.168.250.70`

Using Splunk, the investigation identified two external IP addresses of interest:

- `40.80.148.42`
- `23.22.63.114`

The suspicious activity focused on the Joomla administrator login page:

`/joomla/administrator/index.php`

### SPL Query

```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php"
| table _time uri src_ip dest_ip form_data
```

**Findings:**

- 425 POST events targeting the Joomla administrator endpoint.
- 413 events containing login-related form data.
- Multiple password attempts against the `admin` account.
- 412 filtered events associated with the `Python-urllib/2.7` User-Agent.

To extract attempted passwords, the investigation used:

```spl
index=botsv1 sourcetype=stream:http form_data=*username*passwd*
| rex field=form_data "passwd=(?<creds>\w+)"
| table _time src_ip http_user_agent creds
```

**Analysis:** Repeated login attempts using different passwords, combined with a Python User-Agent, strongly indicated an automated brute-force attack.

---

## 💻 2. Installation – Suspicious Executable

After the compromise, the investigation focused on suspicious files transferred to the web server.

### SPL Query

```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" *.exe
```

The HTTP logs revealed two interesting files:

- `3791.exe`
- `agent.php`

The next step was to determine whether `3791.exe` had been executed.

### Sysmon Investigation

```spl
index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1
```

**Finding:** Sysmon Event ID 1 (Process Creation) provided evidence that `3791.exe` had been executed.

**Key lesson:** Identifying a suspicious file transfer is not enough. Correlating network events with host-based logs helps confirm what actually happened.

---

## 🌐 3. Command & Control Investigation

The investigation then examined suspicious outbound communication from the compromised server.

### SPL Query

```spl
index=botsv1 src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114
```

The Suricata logs showed suspicious HTTP activity involving the external destination.

A follow-up FortiGate search was performed:

```spl
index=botsv1 sourcetype=fortigate_utm "poisonivy-is-coming-for-you-batman.jpeg"
```

### Findings

| Indicator | Value |
|---|---|
| Source IP | `192.168.250.70` |
| Destination IP | `23.22.63.114` |
| Destination port | `1337` |
| Domain | `prankglassinebracket.jumpingcrab.com` |
| FortiGate classification | Malicious Websites |
| Severity | High |

**Analysis:** The outbound connections, combined with the previous compromise evidence and firewall classification, supported the investigation of potential C2 activity.

---

## 🦠 4. Malware Analysis & Threat Intelligence

The guided investigation used OSINT and malware analysis platforms to investigate suspicious infrastructure.

Tools included:

- **Robtex:** DNS and infrastructure relationships.
- **ThreatMiner:** Malware hashes associated with suspicious IPs.
- **VirusTotal:** File reputation and network relationships.
- **Hybrid Analysis:** Sandbox behaviour and malware indicators.

A suspicious executable was identified:

**Filename:** `MirandaTateScreensaver.scr.exe`

**MD5:** `c99131e0169171935c5ac32615ed6261`

VirusTotal showed **48/68 security vendors** detecting the sample as malicious.

Hybrid Analysis also classified the sample as malicious and provided additional behavioural indicators.

The sample had an observed network relationship with `23.22.63.114`, although the evidence did not establish that it was identical to `3791.exe`.

---

## 🎯 5. Actions on Objectives & Delivery

The scenario also explored how malicious content reached the target and how the attacker affected the compromised website.

The investigation demonstrated the importance of correlating:

- Web application activity.
- Suspicious file transfers.
- Host process execution.
- External network communications.
- Evidence of website compromise and defacement.

These findings helped explain the different stages of the Cyber Kill Chain and the importance of investigating beyond initial access.

---

## 📚 Key Takeaways

This room helped me strengthen my understanding of:

- **Splunk/SPL:** Searching, filtering and examining security events.
- **Log correlation:** Connecting HTTP, firewall and Sysmon evidence.
- **Brute-force detection:** Recognising repeated login attempts and automated activity.
- **Sysmon Event ID 1:** Investigating process execution.
- **IOC investigation:** Identifying suspicious IPs, domains, filenames and hashes.
- **Threat Intelligence:** Using OSINT and sandbox reports to enrich findings.
- **Cyber Kill Chain:** Understanding how attacker activities relate across different phases.

## 💡 Personal Reflection

This guided lab helped me become more confident navigating Splunk and analysing security logs.

I found that exploring available fields, examining their values and applying filters often helped me identify the information needed to answer investigation questions.

One of the most valuable lessons was understanding how to move from a suspicious network event to host-based evidence and use different log sources to support an investigation.

My next goal is to improve my ability to write SPL queries independently and investigate security alerts with less guidance.

---

**Lab completed as part of my hands-on cybersecurity training on TryHackMe.**

*This write-up documents a guided training investigation based on the TryHackMe BOTSv1 dataset and its educational walkthrough.*
