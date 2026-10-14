# Brim — Network Traffic Analysis and Threat Hunting

**Platform:** TryHackMe | **Tools:** Brim, Zeek logs, Suricata alerts | **Author:** Mirko Bracciante

## Overview

In this lab, I practised investigating PCAP files with Brim, searching Zeek logs and correlating Suricata alerts with network connections. The exercises covered command-and-control (C2) traffic and suspected cryptocurrency mining.

## Investigation workflow

- Reviewed available log sources and overall network activity.
- Identified communicating hosts, frequently used ports and long connections.
- Examined transferred bytes, HTTP requests and file activity.
- Used Suricata signatures to identify leads and pivot into related traffic.

## Useful queries

### Identify available log sources
```text
count() by _path | sort -r count
```

### Find communicating hosts
```text
_path=="conn" | cut id.orig_h, id.resp_h | sort | uniq
```

### Review the most frequent alert signatures
```text
event_type=="alert" | cut alert.signature | sort | uniq -c | sort -r count
```

### Review long connections
```text
_path=="conn" | cut id.orig_h, id.resp_h, id.resp_p, duration | sort -r duration
```

## C2 investigation

The Cobalt Strike exercise identified the following findings:

| Finding | Value |
|---|---|
| C2 destination | `104.168.44.45` |
| Downloaded file | `4564.exe` |
| Connections to destination port 443 | `328` |
| Secondary C2 identified in the exercise | `IcedID` |

I used the destination IP and port to count the Cobalt Strike connections:

```text
_path=="conn" id.resp_h==104.168.44.45 id.resp_p==443 | count()
```

To investigate the download, I examined HTTP records associated with the destination:

```text
_path=="http" id.resp_h==104.168.44.45
```

The alert signature `ET MALWARE Win32/IcedID Request Cookie` provided the lead for the secondary C2. The signature mentioning `Meterpreter or Other Reverse Shell` was broader and did not establish Meterpreter as the answer. This reinforced the importance of reading the full signature and validating its meaning.

## Cryptocurrency-mining investigation

I practised counting connections to port 19999, checking the service identified on port 6666, and calculating transferred bytes for `101.201.172.235:8888`.

```text
_path=="conn" id.resp_p==19999 | count()
```

```text
_path=="conn" id.resp_p==6666 | cut service | sort | uniq
```

```text
_path=="conn" id.resp_h==101.201.172.235 id.resp_p==8888
| put total_bytes := orig_bytes + resp_bytes
| cut orig_bytes, resp_bytes, total_bytes
```

The last query calculates bytes in both directions per connection; it does not sum multiple connections together.

Reviewing the full alert details revealed `[T1496]`, associated with **Resource Hijacking**. Although the exercise called this a tactic ID, `T1496` is a technique ID. The associated tactic is **Impact (`TA0040`)**.

## Key lessons

- Field-based filters make searches more precise than unrestricted keyword searches.
- Pipelines let me filter, select fields, count and sort results in stages.
- Frequent connections alone do not prove beaconing: timing and regularity also matter.
- Large transfers, long sessions and unusual ports need context before being classified as malicious.
- Alerts are investigation leads; connection records and other evidence help validate them.

This was a controlled training exercise. The indicators above belong to the lab dataset and are not a statement about their current status.

