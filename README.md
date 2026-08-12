# SOC Analyst Starter Kit

Hands-on SOC analyst portfolio demonstrating practical detection engineering, network and endpoint telemetry analysis, incident investigation, evidence handling, MITRE ATT&CK mapping, and repeatable analyst triage workflows.

This repository is built around controlled lab activity and documented analyst methodology rather than screenshots alone.

---

## Current Labs

### Lab 01 — Linux Authentication Detection

Focus:

* Linux authentication telemetry
* PAM authentication failures
* Detection severity
* Triage and investigation
* MITRE ATT&CK T1110 — Brute Force
* Benign vs. malicious disposition

Key artifacts:

* Linux authentication telemetry lab
* Detection engineering documentation
* Investigation report
* Authentication alert triage checklist

---

### Lab 02 — Suspicious PowerShell

Focus:

* Windows PowerShell 5.1
* Script Block Logging
* Event ID 4104
* Process Creation Event ID 4688
* Encoded PowerShell
* Parent/child process analysis
* MITRE ATT&CK T1059.001 — PowerShell
* Evidence sanitization
* SHA-256 integrity verification

Key artifacts:

* PowerShell telemetry lab
* Detection engineering documentation
* Investigation report
* PowerShell alert triage checklist
* Sanitized evidence package
* SHA-256 integrity manifest

---

### Lab 03 — Network Reconnaissance Detection

Focus:

* Linux networking
* Nmap
* tcpdump
* PCAP analysis
* TCP SYN interpretation
* Structured network telemetry
* Splunk-ready CSV generation
* Multi-port reconnaissance logic
* MITRE ATT&CK T1046 — Network Service Discovery
* Evidence sanitization
* SHA-256 verification

Observed Lab 03 pattern:

```text
Source:       192.168.1.226
Destination:  192.168.1.149
Unique Ports: 6
Ports:        22, 5432, 8000, 8089, 8191, 9997
```

The detection model emphasizes unique destination ports rather than raw packet
count so TCP retransmissions do not inflate reconnaissance scope.

Final indexed-event validation in Splunk remains pending due to a temporary
historical Splunk Free license-warning restriction. The PCAP, structured
telemetry, detection logic, and investigation were independently validated.

---
### Lab 04 — SSH Brute-Force Detection

Detects and investigates repeated SSH authentication failures using Linux authentication telemetry and Splunk.

**Detection focus**
- Repeated failed SSH authentication
- Source/destination/account correlation
- Time-window aggregation
- Threshold-based detection
- Success-after-failure analysis
- Syslog repeated-message handling

**SOC workflow**
- Validate the OpenSSH service and TCP/22 listener
- Establish a pre-attack baseline
- Generate controlled authentication failures
- Capture remote brute-force-like activity
- Review `/var/log/auth.log`
- Normalize authentication telemetry
- Develop Splunk SPL detection logic
- Evaluate detection thresholds
- Investigate source, destination, and account context
- Map activity to MITRE ATT&CK
- Assign severity and disposition
- Preserve sanitized evidence with SHA-256 integrity verification

**MITRE ATT&CK**

`T1110 — Brute Force`

**Final disposition**

`True Positive — Authorized Security Testing`

**Lab artifacts**
- [Lab Walkthrough](02-Splunk-Labs/LAB-04-SSH-BRUTE-FORCE.md)
- [Detection Engineering](03-Detection-Engineering/LAB-04-SSH-BRUTE-FORCE-DETECTION.md)
- [Incident Investigation Report](04-Incident-Response/LAB-04-SSH-BRUTE-FORCE-INVESTIGATION-REPORT.md)
- [SOC Alert Triage Checklist](05-SOC-Checklists/SSH-BRUTE-FORCE-ALERT-TRIAGE.md)
- [Evidence Package](02-Splunk-Labs/evidence/LAB-04/)

**Key analyst lesson**

Authentication detections become more useful when individual events are evaluated as behavior:

```text
source
+
destination
+
account
+
failure frequency
+
time window
+
authentication outcome
+
surrounding context
```

---
## Repository Structure

```text
00-Start-Here/
    Project orientation and introductory material

01-Home-SOC/
    Home SOC architecture and lab environment

02-Splunk-Labs/
    Hands-on telemetry and SIEM labs

03-Detection-Engineering/
    Detection objectives, thresholds, logic, tuning, and MITRE mapping

04-Incident-Response/
    Investigation reports and analyst dispositions

05-SOC-Checklists/
    Repeatable SOC triage workflows

06-Portfolio-Builder/
    Portfolio development material

07-Templates/
    Reusable analyst and documentation templates

08-Screenshots/
    Supporting visual evidence

09-Final-Product/
    Final packaged product material
```

---

## SOC Workflow Demonstrated

```text
Telemetry
    |
    v
Detection
    |
    v
Triage
    |
    v
Investigation
    |
    v
Correlation
    |
    v
Context
    |
    v
Evidence-Based Disposition
```

The labs are designed to reinforce a core analyst principle:

**Detection severity identifies activity worthy of attention. It does not, by itself, establish malicious intent.**

---

## Technical Skills Demonstrated

* Splunk
* SPL detection logic
* Linux
* Windows security telemetry
* PowerShell logging
* Event ID 4104
* Event ID 4688
* Nmap
* tcpdump
* PCAP analysis
* Network service discovery
* Detection engineering
* Incident investigation
* Alert triage
* MITRE ATT&CK
* Evidence sanitization
* SHA-256 integrity verification
* Git
* GitHub
* SOC documentation

---

## Evidence Handling

Lab evidence is reviewed before publication.

Where appropriate, the workflow includes:

```text
Raw Evidence
     |
     v
Preserve Original
     |
     v
Sanitize Portfolio Copy
     |
     v
Verify Content
     |
     v
Generate SHA-256 Hash
     |
     v
Git QA
     |
     v
Publish
```

Personal identifiers, unnecessary host information, credentials, tokens, and
other sensitive values are removed before public publication where applicable.

---

## Detection Engineering Approach

Each detection is developed around:

* Detection objective
* Required telemetry
* Behavioral indicators
* Threshold selection
* Severity model
* False-positive considerations
* MITRE ATT&CK mapping
* Investigation questions
* Disposition logic
* Detection improvement opportunities

The goal is not simply to produce alerts.

The goal is to produce alerts that an analyst can explain, investigate, and
defend with evidence.

---

## Start Here

Recommended review order:

1. `00-Start-Here/`
2. `01-Home-SOC/`
3. `02-Splunk-Labs/`
4. `03-Detection-Engineering/`
5. `04-Incident-Response/`
6. `05-SOC-Checklists/`

For a quick technical review, begin with:

* Lab 01 — Linux Authentication Detection
* Lab 02 — Suspicious PowerShell
* Lab 03 — Network Reconnaissance Detection

---

## Project Status

Completed:

* Lab 01 — Linux Authentication Detection
* Lab 02 — Suspicious PowerShell
* Lab 03 — Network Reconnaissance Detection

In progress:

* Additional SOC labs
* Splunk detection validation
* Detection maturity expansion
* Portfolio packaging

---

## Purpose

This project demonstrates practical SOC analyst capability through repeatable,
documented, evidence-backed lab work.

The emphasis is on:

**telemetry → detection → investigation → evidence → disposition**

rather than tool usage alone.

---

**SOC Analyst Starter Kit v1**
