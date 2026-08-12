# SOC Investigation Report — Lab 03

## Network Reconnaissance Investigation

**SOC Analyst Starter Kit v1**
**Classification:** Training Exercise
**Platform:** Linux / Network
**Primary Telemetry:** Packet Capture
**MITRE ATT&CK:** T1046 — Network Service Discovery
**Status:** Closed
**Disposition:** Benign / Authorized Training Activity

---

# 1. Executive Summary

Controlled network reconnaissance activity was generated from a remote lab
endpoint against Sentinel to evaluate network telemetry, detection logic, and
SOC investigation workflow.

The source host at 192.168.1.226 initiated TCP connection attempts against
Sentinel at 192.168.1.149.

Six unique destination ports were observed:

- 22
- 5432
- 8000
- 8089
- 8191
- 9997

Defender-side packet capture successfully recorded the inbound activity.

The observed behavior met the Lab 03 detection criteria for a network
reconnaissance pattern.

Investigation determined that the activity was intentionally generated as
part of an authorized cybersecurity training exercise.

**Final Disposition: Benign / Authorized Training Activity**

---

# 2. Environment

## Target System

Role:

Sentinel / SOC monitoring system

IP address:

192.168.1.149

Capture interface:

enx00e04c6800cf

## Source System

Observed source IP:

192.168.1.226

Role:

Authorized remote lab endpoint

## Network

192.168.1.0/24

---

# 3. Investigation Trigger

Defender-side telemetry showed one remote source contacting multiple TCP
services on the same destination within a short period.

Observed relationship:

192.168.1.226
      |
      v
192.168.1.149
      |
      +-- TCP/22
      +-- TCP/5432
      +-- TCP/8000
      +-- TCP/8089
      +-- TCP/8191
      +-- TCP/9997

This behavior warranted investigation as possible network service discovery.

---

# 4. Evidence Reviewed

Primary packet capture:

`02-Splunk-Labs/evidence/LAB-03/Test-C-Remote-Recon.pcap`

Readable packet evidence:

`02-Splunk-Labs/evidence/LAB-03/Test-C-Remote-Recon.txt`

Additional scanner-side evidence:

`02-Splunk-Labs/evidence/LAB-03/Test-A-TCP-Connect-Scan.txt`

`02-Splunk-Labs/evidence/LAB-03/Test-B-Targeted-Port-Scan.txt`

Pre-scan system baseline:

`02-Splunk-Labs/evidence/LAB-03/Test-A-PreScan-Baseline.txt`

---

# 5. Packet Analysis

The packet capture showed TCP SYN activity originating from:

192.168.1.226

and targeting:

192.168.1.149

Observed SYN counts:

| Destination Port | SYN Count |
|---|---:|
| 22 | 1 |
| 5432 | 5 |
| 8000 | 5 |
| 8089 | 5 |
| 8191 | 5 |
| 9997 | 2 |

Six unique destination ports were observed.

Repeated SYN packets were associated with connection retry behavior.

---

# 6. Service Context

The target system baseline showed listening services including:

| Port | Observed Service Context |
|---|---|
| 22 | SSH |
| 5432 | PostgreSQL |
| 8000 | Splunk Web |
| 8089 | Splunk management |
| 8191 | Application/service listener |
| 9997 | Splunk receiving |

A targeted service-discovery test confirmed that all six ports were reachable
during the controlled lab exercise.

---

# 7. Detection Assessment

Detection condition:

One source IP contacted multiple destination ports on the same target within
a short period.

Observed result:

- Source hosts: 1
- Destination hosts: 1
- Unique destination ports: 6
- Pattern: Multi-port connection attempts

Detection:

**NETWORK RECONNAISSANCE PATTERN DETECTED**

Initial Severity:

**MEDIUM**

The severity reflects activity requiring analyst review and does not establish
malicious intent.

---

# 8. Investigation

The analyst reviewed:

- Source IP
- Destination IP
- Destination ports
- TCP flags
- Connection frequency
- Retry behavior
- Target listening services
- Scanner-side evidence
- Defender-side packet evidence
- Lab authorization context

The source was identified as an authorized lab endpoint.

The destination was the Sentinel lab system.

The connection attempts were intentionally generated for Lab 03.

No unauthorized scanning was identified.

---

# 9. Scope Analysis

The reviewed evidence demonstrated:

- One source host
- One target host
- Six unique destination ports
- Repeated TCP SYN activity

No evidence was identified in the reviewed Lab 03 dataset demonstrating:

- Broad subnet scanning
- Multiple target hosts
- Credential attacks
- Exploitation attempts
- Malware execution
- Persistence
- Unauthorized access

The investigation scope was limited to the telemetry collected for this
controlled exercise.

---

# 10. MITRE ATT&CK Mapping

**T1046 — Network Service Discovery**

The observed behavior is consistent with network service discovery because a
remote host attempted connections to multiple services on a target system.

ATT&CK mapping describes the observed behavioral pattern.

It does not independently establish malicious intent.

---

# 11. False-Positive Analysis

Potential legitimate sources of similar behavior include:

- Vulnerability scanners
- Network monitoring systems
- Asset discovery tools
- Administrative troubleshooting
- Configuration validation
- Security assessments
- Authorized penetration testing

Analyst context is therefore required before escalation.

---

# 12. Analyst Assessment

The telemetry successfully demonstrated a reconnaissance-like network pattern.

The detection correctly identified activity worthy of investigation.

The investigation established that the source and activity were authorized
components of a controlled cybersecurity lab.

No evidence of malicious follow-on activity was identified in the reviewed
Lab 03 evidence.

---

# 13. Disposition

**BENIGN / AUTHORIZED TRAINING ACTIVITY**

Escalation:

**NOT REQUIRED**

Case Status:

**CLOSED**

---

# 14. Analyst Lessons

## Lesson 1

A detection identifies behavior requiring investigation.

It does not automatically identify malicious intent.

## Lesson 2

Unique destination-port counts provide stronger reconnaissance context than
raw packet counts alone.

TCP retransmissions can otherwise inflate event volume.

## Lesson 3

Scanner-side and defender-side evidence answer different questions.

Scanner-side evidence shows what the source attempted to discover.

Defender-side evidence shows what the target actually observed.

## Lesson 4

Network detections require environmental context.

Administrative tools, monitoring platforms, vulnerability scanners, and
authorized testing can produce reconnaissance-like telemetry.

## Lesson 5

MITRE ATT&CK mapping describes behavior, not final disposition.

---

# 15. SOC Workflow

Telemetry
   |
   v
Multi-Port Pattern
   |
   v
Detection
   |
   v
Triage
   |
   v
Source / Destination Analysis
   |
   v
Context
   |
   v
Investigation
   |
   v
Disposition

---

# 16. Final Case Status

Network Telemetry: VALIDATED

Remote Source Visibility: VALIDATED

Destination Port Visibility: VALIDATED

Multi-Port Detection: VALIDATED

Defender-Side PCAP: VALIDATED

MITRE ATT&CK T1046 Mapping: VALIDATED

Malicious Activity: NOT IDENTIFIED

Escalation: NOT REQUIRED

Disposition: BENIGN / AUTHORIZED TRAINING ACTIVITY

Case Status: CLOSED

---

**SOC Analyst Starter Kit v1**

**Lab 03 — Network Reconnaissance Investigation Report**
