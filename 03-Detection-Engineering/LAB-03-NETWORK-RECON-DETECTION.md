# Detection Engineering — Lab 03

## Network Reconnaissance Detection

**SOC Analyst Starter Kit v1**
**Platform:** Linux / Network
**Primary Telemetry:** Packet Capture
**Detection Focus:** Multi-Port Connection Attempts
**MITRE ATT&CK:** T1046 — Network Service Discovery

---

# 1. Detection Objective

Identify a source host that attempts connections to multiple destination ports
on the same target within a short period of time.

This behavior can represent:

- Network service discovery
- Port scanning
- Administrative troubleshooting
- Monitoring activity
- Vulnerability scanning
- Security testing

The detection identifies reconnaissance-like behavior.

It does not by itself prove malicious intent.

---

# 2. Data Source

Primary evidence:

Test-C-Remote-Recon.pcap

Readable companion file:

Test-C-Remote-Recon.txt

Observed source:

192.168.1.226

Observed destination:

192.168.1.149

Observed destination ports:

- 22
- 5432
- 8000
- 8089
- 8191
- 9997

---

# 3. Observed Pattern

The source host attempted TCP connections to multiple services on Sentinel.

Observed SYN counts:

| Destination Port | SYN Count |
|---|---:|
| 22 | 1 |
| 5432 | 5 |
| 8000 | 5 |
| 8089 | 5 |
| 8191 | 5 |
| 9997 | 2 |

The differing counts resulted from connection behavior and retries.

---

# 4. Detection Concept

Conceptual detection logic:

IF one source IP
    connects to one destination host
    across multiple destination ports
    within a short time window

THEN
    flag for network reconnaissance investigation

---

# 5. Detection Threshold

Example starting threshold:

- At least 5 unique destination ports
- Same source IP
- Same destination IP
- Within 2 minutes

This threshold is for lab validation and should be tuned for the environment.

---

# 6. Severity Model

## Informational

Normal single-service access.

## Low

Small number of ports contacted with expected administrative context.

## Medium

Multiple destination ports contacted in a short period.

Example:

5 or more unique ports on the same destination.

## High

Reconnaissance behavior combined with additional suspicious context such as:

- Multiple target hosts
- Repeated scans
- Unexpected source
- Follow-on exploitation attempts
- Authentication attacks
- Malware activity

Severity prioritizes investigation.

It does not determine final disposition.

---

# 7. MITRE ATT&CK Mapping

**T1046 — Network Service Discovery**

This technique covers attempts to identify services running on remote systems.

The observed Lab 03 behavior matches the detection pattern because one source
host contacted multiple ports on a single target.

The lab activity was authorized and controlled.

---

# 8. Defender-Side Telemetry

The packet capture was collected on Sentinel:

Interface:

enx00e04c6800cf

Target:

192.168.1.149

Source:

192.168.1.226

The capture showed inbound TCP SYN packets to multiple destination ports.

This represents defender-side visibility rather than scanner-side output.

---

# 9. Scanner-Side vs. Defender-Side Evidence

Scanner-side evidence answers:

What did the scanning host attempt?

Defender-side evidence answers:

What did the target actually observe?

Preferred SOC model:

Scanner Activity
      |
      v
Network Traffic
      |
      v
Defender Telemetry
      |
      v
Detection
      |
      v
Investigation
      |
      v
Disposition

---

# 10. False-Positive Considerations

Legitimate causes may include:

- Vulnerability scanners
- Network monitoring
- IT troubleshooting
- Asset discovery
- Security testing
- Configuration validation
- Application health checks

Analysts should review:

- Source system
- Source ownership
- Timing
- Scan frequency
- Destination systems
- Change-management context
- Authorized scanning windows

---

# 11. Analyst Triage Questions

1. Which source IP generated the activity?
2. Which destination host was targeted?
3. How many unique ports were contacted?
4. Over what time period?
5. Were the ports sequential or targeted?
6. Was the source expected to perform scanning?
7. Did the source target additional hosts?
8. Were any connections successful?
9. Did authentication attempts follow?
10. Was there any follow-on exploitation activity?
11. Is the activity authorized?
12. Does the activity require escalation?

---

# 12. Lab 03 Observed Result

Source:

192.168.1.226

Destination:

192.168.1.149

Unique destination ports:

6

Ports:

22, 5432, 8000, 8089, 8191, 9997

Observed behavior:

Remote host performed repeated connection attempts across multiple services on
Sentinel.

Detection result:

NETWORK RECONNAISSANCE PATTERN DETECTED

Expected severity:

MEDIUM

Final disposition:

BENIGN / AUTHORIZED TRAINING ACTIVITY

---

# 13. Detection Improvement Opportunities

Future versions can incorporate:

- Unique-port counts
- Time-window correlation
- Source-host baselines
- Multiple-destination scanning
- TCP SYN-only analysis
- Failed vs. successful connections
- Network IDS telemetry
- Zeek
- Suricata
- Firewall logs
- Splunk correlation
- Threat-intelligence enrichment

---

# 14. Detection Maturity

Level 1 — Multi-Port Pattern Recognition

Level 2 — Time-Window Correlation

Level 3 — Multi-Host Recon Detection

Level 4 — IDS / SIEM Correlation

Level 5 — Risk-Based Network Detection

---

# 15. Key Detection Principle

Port activity alone is not enough.

The useful pattern is:

Source
   +
Destination
   +
Unique Destination Ports
   +
Time Window
   +
Context
   =
Reconnaissance Assessment

---

**SOC Analyst Starter Kit v1**

**Detection Engineering — Lab 03**
