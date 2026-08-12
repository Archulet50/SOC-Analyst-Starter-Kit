# Lab 03 — Network Reconnaissance Detection

## SOC Analyst Starter Kit v1

**Difficulty:** Beginner / Intermediate
**Platform:** Linux / Network
**Primary Telemetry:** Packet Capture
**SIEM:** Splunk
**Detection Focus:** Multi-Port Connection Attempts
**MITRE ATT&CK:** T1046 — Network Service Discovery

---

# 1. Lab Objective

In this lab, the analyst will generate controlled network reconnaissance
activity from one lab endpoint toward Sentinel, capture the traffic from the
defender side, transform the telemetry into a searchable format, and develop
a Splunk detection for multi-port service discovery.

The analyst will learn how to:

- Establish a network baseline
- Identify listening services
- Perform controlled service discovery
- Capture traffic with tcpdump
- Read and interpret PCAP evidence
- Distinguish packet count from unique-port count
- Identify a multi-port reconnaissance pattern
- Map the behavior to MITRE ATT&CK T1046
- Create a Splunk-searchable network dataset
- Develop SPL for reconnaissance detection
- Investigate and disposition the alert

---

# 2. Scenario

You are a SOC analyst monitoring a Linux-based SOC system named Sentinel.

A remote lab endpoint begins attempting TCP connections to multiple services
on Sentinel.

Your job is to determine:

- Which source generated the traffic?
- Which destination was targeted?
- Which ports were contacted?
- How many unique ports were targeted?
- Did retransmissions inflate the packet count?
- Was the activity authorized?
- Does the activity require escalation?

---

# 3. Lab Architecture

Remote Lab Endpoint
        |
        v
Controlled TCP Connection Attempts
        |
        v
Sentinel Network Interface
        |
        v
tcpdump
        |
        v
PCAP Evidence
        |
        v
Text / Structured Telemetry
        |
        v
Splunk
        |
        v
SPL Detection
        |
        v
SOC Investigation
        |
        v
Disposition

---

# 4. Lab Environment

Sentinel target:

192.168.1.149

Remote source observed during testing:

192.168.1.226

Sentinel interface:

enx00e04c6800cf

Network:

192.168.1.0/24

---

# 5. Pre-Scan Baseline

The target system was inspected before reconnaissance activity.

Command:

    sudo ss -lntup

Evidence:

    02-Splunk-Labs/evidence/LAB-03/Test-A-PreScan-Baseline.txt

Externally bound services included:

- TCP/22
- TCP/5432
- TCP/8000
- TCP/8089
- TCP/8191
- TCP/9997

The baseline provides host-side truth about what Sentinel is listening on.

---

# 6. Test A — Default TCP Connect Scan

Command:

    nmap -sT 192.168.1.149

Evidence:

    Test-A-TCP-Connect-Scan.txt

Observed services:

- 22/tcp
- 5432/tcp
- 8000/tcp
- 8089/tcp

The default scan did not display every listening service.

Analyst lesson:

A default port scan does not necessarily test every TCP port.

---

# 7. Test B — Targeted Service Discovery

Command:

    nmap -sT -p 22,5432,8000,8089,8191,9997 192.168.1.149

Evidence:

    Test-B-Targeted-Port-Scan.txt

Observed result:

All six explicitly tested ports were open.

This demonstrated the difference between:

Host Listener Inventory

and:

Default Scanner Visibility

and:

Targeted Scanner Visibility

---

# 8. Test C — Defender-Side Reconnaissance Capture

The remote lab endpoint generated controlled TCP connection attempts against
Sentinel.

Defender-side telemetry was collected with tcpdump.

Source:

192.168.1.226

Destination:

192.168.1.149

Observed destination ports:

- 22
- 5432
- 8000
- 8089
- 8191
- 9997

Primary evidence:

    Test-C-Remote-Recon.pcap

Readable evidence:

    Test-C-Remote-Recon.txt

---

# 9. SYN Count Analysis

Observed SYN counts:

| Destination Port | SYN Count |
|---|---:|
| 22 | 1 |
| 5432 | 5 |
| 8000 | 5 |
| 8089 | 5 |
| 8191 | 5 |
| 9997 | 2 |

The packet count is larger than the number of unique ports because connection
retry behavior generated repeated SYN packets.

Detection logic should therefore emphasize:

- Source IP
- Destination IP
- Unique destination ports
- Time window

rather than raw packet count alone.

---

# 10. Detection Concept

A useful reconnaissance pattern is:

One source IP
        +
One destination host
        +
Multiple unique destination ports
        +
Short time window
        =
Possible Network Service Discovery

Initial Lab 03 threshold:

- At least 5 unique destination ports
- Same source
- Same destination
- Within 2 minutes

---

# 11. MITRE ATT&CK

Primary technique:

T1046 — Network Service Discovery

The observed behavior matches this technique because one remote host attempted
to identify services exposed on a target system.

ATT&CK mapping describes behavior.

It does not determine final disposition.

---

# 12. Create Splunk-Searchable Telemetry

PCAP files are excellent evidence artifacts, but Splunk search is easier when
events are represented as text or structured fields.

The Lab 03 dataset should expose fields conceptually equivalent to:

- timestamp
- src_ip
- src_port
- dest_ip
- dest_port
- protocol
- tcp_flags

Example event:

    timestamp=2026-08-12T06:16:24
    src_ip=192.168.1.226
    src_port=30723
    dest_ip=192.168.1.149
    dest_port=22
    protocol=tcp
    tcp_flags=S

---

# 13. Basic SPL Search

Conceptual search:

    index=main
    src_ip=192.168.1.226
    dest_ip=192.168.1.149

Review destination ports:

    index=main
    src_ip=192.168.1.226
    dest_ip=192.168.1.149
    | stats count by dest_port
    | sort dest_port

---

# 14. Reconnaissance Detection SPL

Conceptual detection:

    index=main
    protocol=tcp
    tcp_flags=S
    | bin _time span=2m
    | stats dc(dest_port) as unique_ports
            values(dest_port) as destination_ports
            count as syn_count
      by _time src_ip dest_ip
    | where unique_ports >= 5

The important field is:

    dc(dest_port)

This counts distinct destination ports instead of counting every packet.

---

# 15. Expected Detection Result

Observed Lab 03 activity:

Source:

192.168.1.226

Destination:

192.168.1.149

Unique destination ports:

6

Ports:

22, 5432, 8000, 8089, 8191, 9997

Expected detection:

NETWORK RECONNAISSANCE PATTERN DETECTED

Severity:

MEDIUM

---

# 16. Analyst Investigation

Review:

- Source ownership
- Destination asset role
- Unique destination ports
- Scan time window
- Retry behavior
- Authorized scanner status
- Additional target systems
- Follow-on authentication
- Exploitation attempts
- Other correlated telemetry

---

# 17. False-Positive Considerations

Legitimate activity can include:

- Vulnerability scanning
- Monitoring
- Asset discovery
- Troubleshooting
- Authorized penetration testing
- Configuration validation

A detection should trigger investigation, not automatic escalation.

---

# 18. Final Lab Disposition

The observed activity was intentionally generated from an authorized lab
endpoint.

Final disposition:

BENIGN / AUTHORIZED TRAINING ACTIVITY

Escalation:

NOT REQUIRED

---

# 19. Evidence

Lab 03 evidence directory:

    02-Splunk-Labs/evidence/LAB-03/

Expected artifacts:

- Test-A-PreScan-Baseline.txt
- Test-A-TCP-Connect-Scan.txt
- Test-B-Targeted-Port-Scan.txt
- Test-C-Remote-Recon.pcap
- Test-C-Remote-Recon.txt

---

# 20. Lab Completion Checklist

- [x] Establish network baseline
- [x] Identify listening services
- [x] Install and validate Nmap
- [x] Perform default service discovery
- [x] Perform targeted service discovery
- [x] Validate remote source connectivity
- [x] Capture defender-side traffic
- [x] Create PCAP evidence
- [x] Create readable packet evidence
- [x] Identify unique destination ports
- [x] Map activity to T1046
- [x] Create detection-engineering document
- [x] Create investigation report
- [x] Create analyst triage checklist
- [ ] Create structured Splunk-ready telemetry
- [ ] Ingest Lab 03 telemetry into Splunk
- [ ] Execute SPL detection
- [ ] Capture Splunk evidence
- [ ] Sanitize evidence package
- [ ] Create SHA-256 manifest
- [ ] Complete Git QA
- [ ] Commit Lab 03

---

# 21. Skills Demonstrated

- Linux networking
- Nmap
- tcpdump
- Packet capture analysis
- TCP SYN interpretation
- Network reconnaissance detection
- Splunk
- SPL
- Distinct-count detection logic
- MITRE ATT&CK
- Alert triage
- Incident investigation
- Evidence handling

---

# 22. Key Lesson

Raw packet volume is not the same thing as reconnaissance scope.

A better SOC question is:

How many unique services did one source attempt to discover
on one destination within a defined time window?

That produces a more useful detection than simply counting packets.
# 23. Splunk Validation Status

Structured network telemetry was successfully created from the defender-side
PCAP and independently validated prior to Splunk analysis.

Validated dataset characteristics:

- Source IP: 192.168.1.226
- Destination IP: 192.168.1.149
- Unique destination ports: 6
- Destination ports: 22, 5432, 8000, 8089, 8191, 9997
- TCP SYN telemetry successfully extracted
- Splunk-ready CSV successfully created
- MITRE ATT&CK mapping: T1046 — Network Service Discovery

The Splunk Search application and SPL execution capability were validated
using `makeresults`.

Final indexed-event detection validation could not be completed because the
Splunk instance was temporarily preventing indexed searches due to historical
license-warning state.

The active Splunk Free license was verified with a 500 MiB daily ingestion
quota.

No attempt was made to bypass the licensing restriction or repeatedly ingest
the dataset.

Final detection validation remains pending.

Planned validation SPL:

    index=main sourcetype=lab03_network_recon
    | bin _time span=2m
    | stats dc('tcp.dstport') as unique_ports
            values('tcp.dstport') as destination_ports
            count as syn_count
      by _time 'ip.src' 'ip.dst'
    | where unique_ports >= 5

Expected result:

    Source: 192.168.1.226
    Destination: 192.168.1.149
    Unique Ports: 6
    Detection: Network Service Discovery
    MITRE ATT&CK: T1046

**Validation Status: PENDING — SPLUNK INDEXED SEARCH AVAILABILITY**
---

**SOC Analyst Starter Kit v1**

**Lab 03 — Network Reconnaissance Detection**
