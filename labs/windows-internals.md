# Project: Windows Internals Analysis

**Objective:** Understanding the core architecture of Windows to improve detection capabilities against advanced threats.

### 🔍 Key Skills Demonstrated
* **Process & Thread Anatomy:** Investigating the structure of processes (EPROCESS) and their threads to identify anomalies.
* **Memory Management:** Analysis of Virtual Address Space and how malicious code hides in memory.
* **API Hooking & Injection:** Identifying signs of common evasion techniques used by malware to bypass security controls.

### 🛠 Tools Used
* **Process Explorer / Process Hacker:** For deep-dive live system analysis.
* **Volatility / WinDbg:** (If used in the lab) For memory forensics and kernel-level debugging.
* **Windows Event Logs:** Correlating internal system events with security anomalies.

### 💡 Core Insight
This lab provided a clear understanding that "seeing" a process is not enough.
A SOC Analyst must understand the *intent* behind the process behavior—recognizing when a legitimate service is being abused to execute malicious instructions in memory.
