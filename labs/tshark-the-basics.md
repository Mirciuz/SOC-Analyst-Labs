# TShark: The Basics — Network Traffic Analysis

**Platform:** TryHackMe  
**Room:** [TShark: The Basics](https://tryhackme.com/room/tsharkthebasics)  
**Focus:** Packet capture, TCP flags, BPF capture filters, display filters and command-line PCAP analysis.

## Objective

Practise using TShark to inspect network traffic, identify TCP behaviour, and extract relevant packet evidence from a PCAP file. This lab reinforced the difference between live packet capture and offline analysis.

## Environment

- **Tool:** TShark (Wireshark CLI)
- **OS:** Ubuntu lab machine
- **Sample capture:** `demo.pcapng`
- **Traffic generation:** `curl`

## Key Commands

### Inspect a PCAP

```bash
tshark -r demo.pcapng | head
```

### Identify packets with the SYN flag set

```bash
tshark -r demo.pcapng -Y 'tcp.flags.syn == 1' | wc -l
```

### Identify packets with the ACK flag set

```bash
tshark -r demo.pcapng -Y 'tcp.flags.ack == 1' | wc -l
```

### Filter by source or destination IPv4 address

```bash
tshark -r demo.pcapng -Y 'ip.src == 145.254.160.237' | wc -l
tshark -r demo.pcapng -Y 'ip.dst == 10.10.10.10' | wc -l
```

`ip.addr` can be used to match an address in either direction; `ip.src` and `ip.dst` distinguish the direction of traffic.

### Identify duplicate TCP acknowledgments

```bash
tshark -r demo.pcapng -Y 'tcp.analysis.duplicate_ack'
```

**Observed evidence:** Packet **37** was reported as `[TCP Dup ACK 28#1]`, from `145.254.160.237` to `216.239.59.99`. Duplicate ACKs can indicate missing or out-of-order segments, but do not prove packet loss on their own.

### Combine conditions

```bash
tshark -r demo.pcapng -Y 'ip.src == 145.254.160.237 && tcp.dstport == 80'
```

### Live capture using BPF

```bash
tshark -f 'dst host 10.10.10.10'
tshark -f 'tcp[tcpflags] & tcp-ack != 0'
```

The `-f` option applies a **capture filter** while recording traffic; `-Y` applies a **display filter** to available packets. Use `Ctrl+C` to stop a live capture.

## Investigation Notes

During live testing, an HTTP connection attempt to `10.10.10.10:80` timed out. The capture showed an initial SYN followed by SYN retransmissions, with no SYN-ACK observed. This suggests an incomplete TCP handshake; it does **not** establish whether the cause was routing, filtering, or a non-responsive host.

```bash
curl -v --connect-timeout 5 10.10.10.10
```

To validate successful network connectivity separately, an HTTPS request to TryHackMe returned `HTTP/2 200`:

```bash
curl -I https://tryhackme.com
```

A separate live HTTPS capture displayed ACK-bearing packets. **Its packet total must not be treated as the answer to a question about a different capture.**

## TCP Concepts Reinforced

- **SYN:** initiates a TCP connection.
- **SYN, ACK:** acknowledges the opening request and sends the server's own SYN.
- **ACK:** acknowledges received TCP sequence numbers; it can appear alongside other flags, such as `PSH` or `FIN`.
- **TCP retransmission:** may occur when an expected response or acknowledgment is not received.
- **Three-way handshake:** `SYN → SYN, ACK → ACK`.
- **Packet count ≠ connection count:** one TCP connection can contain many ACK-bearing packets.

## SOC Analyst Takeaways

1. Verify the **correct PCAP or live capture source** before interpreting a zero-result query.
2. Distinguish **source** and **destination** addresses when investigating traffic direction.
3. Separate **observed evidence** from hypotheses about connectivity or malicious activity.
4. Use targeted filters and `wc -l` for efficient packet counting.
5. Interpret TCP flags in context rather than assuming that retransmissions or duplicate ACKs automatically indicate an attack.

## Skills Practised

`TShark` · `Wireshark display filters` · `BPF capture filters` · `TCP flags` · `PCAP analysis` · `Network troubleshooting` · `SOC alert investigation`

---

*Hands-on learning notes from TryHackMe. Commands and observations are documented for educational and portfolio purposes.*
