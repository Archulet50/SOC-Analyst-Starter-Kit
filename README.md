# SOC Analyst Starter Kit

Hands-on SOC analyst portfolio demonstrating practical detection engineering, network and endpoint telemetry analysis, incident investigation, evidence handling, MITRE ATT&CK mapping, and repeatable analyst triage workflows.

This repository is built around controlled lab activity and documented analyst methodology rather than screenshots alone.

## Portfolio Highlights

**10 hands-on SOC labs completed and documented**, progressing from foundational telemetry analysis through behavioral detection, event correlation, analyst triage, incident investigation, and final SOC reporting.

### Core Capabilities Demonstrated

- Splunk investigation and SPL
- Linux and Windows security telemetry analysis
- Detection engineering and validation
- PowerShell behavioral analysis
- Windows Event ID correlation
- Authentication and network reconnaissance detection
- Parent/child process analysis
- Multi-stage behavioral correlation
- Tier 1 SOC alert triage
- Incident investigation and disposition
- MITRE ATT&CK mapping
- Evidence preservation and integrity verification
- Technical incident reporting

### Featured Capstone — Lab 10

The [Lab 10 — Capstone SOC Investigation](03-Detection-Engineering/Lab-10-Capstone-SOC-Investigation/) demonstrates an end-to-end SOC investigation using Windows process, PowerShell, authentication, privilege, and session telemetry.

The investigation includes:

- Windows Event IDs 4104, 4688, 4624, and 4672
- PowerShell and process-tree analysis
- Logon-session and privilege correlation
- Multi-source event correlation
- MITRE ATT&CK mapping
- Tier 1 triage and evidence assessment
- Competing-hypothesis analysis
- Incident disposition and final SOC reporting

| Investigation Result | Disposition |
|---|---|
| Detection Result | TRUE POSITIVE |
| Activity Classification | AUTHORIZED CONTROLLED ACTIVITY |
| Security Incident | NO |
| Case Status | CLOSED |

**Start with the evidence:** [Final SOC Incident Report](03-Detection-Engineering/Lab-10-Capstone-SOC-Investigation/report/final-soc-incident-report.md)

### Core Technical Areas

`Splunk` · `Detection Engineering` · `Windows Event Logs` · `Linux Authentication` · `PowerShell` · `MITRE ATT&CK` · `Incident Investigation` · `Event Correlation` · `Evidence Handling`

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
### Lab 05 — SSH Success-After-Failure Correlation

Correlates repeated SSH authentication failures with a later successful authentication using normalized Linux authentication telemetry and Splunk-oriented detection logic.

**Detection focus**

- Repeated failed SSH authentication
- Success-after-failure correlation
- Source/destination/account matching
- Temporal correlation windows
- Defensive-control interaction
- Fail2Ban response analysis

**Validation results**

- 4 normalized authentication failures
- 1 subsequent successful authentication
- Same source, destination, and account
- Failure-to-success interval: 18 minutes 02 seconds
- 5-minute window: NOT DETECTED
- 15-minute window: NOT DETECTED
- 30-minute window: DETECTED

**SOC workflow**

- Establish authentication baseline
- Generate controlled failed authentication
- Generate repeated authentication failures
- Observe Fail2Ban defensive response
- Preserve OpenSSH and Fail2Ban evidence
- Normalize authentication telemetry
- Correlate failures and successful authentication
- Evaluate multiple temporal windows
- Develop Splunk SPL detection logic
- Perform incident-response analysis
- Assign final disposition
- Preserve sanitized evidence with SHA-256 verification

**MITRE ATT&CK**

`T1110 — Brute Force`

**Final disposition**

TRUE POSITIVE — AUTHORIZED CONTROLLED ACTIVITY

Lab 05 demonstrates that authentication failures become higher-priority investigative activity when correlated with a subsequent successful authentication as a behavioral sequence.

---

### Lab 06 — Windows Privileged Administrative Discovery

Correlates Windows authentication, privilege-assignment, and process-creation telemetry to identify administrative discovery performed within a privileged logon context.

**Detection focus**

- Windows identity and privilege correlation
- Event ID 4624 successful authentication
- Event ID 4672 special privilege assignment
- Event ID 4688 process creation
- Logon ID correlation
- Parent-child process relationships
- Command-line behavioral context
- Benign elevated-process comparison

**Validation results**

- Interactive authentication observed
- Linked privileged logon context confirmed
- Special privileges correlated through Logon ID `0x1F23B71`
- Benign elevated `notepad.exe` control preserved
- `net.exe localgroup Administrators` discovery activity observed
- `powershell.exe -> net.exe -> net1.exe` process chain confirmed
- Primary Windows evidence: SHA-256 verified
- Derived detection artifacts: SHA-256 verified
- Splunk dataset ingestion: COMPLETED
- Live Splunk correlation search: PENDING

**SOC workflow**

- Establish Windows Security auditing baseline
- Generate benign elevated-process control
- Generate controlled administrative discovery
- Preserve Windows Security Event evidence
- Correlate authentication and privilege telemetry
- Associate privileged context with process creation
- Compare benign and security-relevant elevated execution
- Normalize Windows telemetry for SIEM analysis
- Develop Splunk SPL correlation logic
- Ingest normalized telemetry into Splunk
- Perform analyst assessment and assign disposition
- Preserve primary and derived artifacts with SHA-256 verification

**MITRE ATT&CK**

`T1087 — Account Discovery`

**Final disposition**

TRUE POSITIVE — AUTHORIZED CONTROLLED ACTIVITY

Lab 06 demonstrates that elevated process execution becomes a higher-value detection signal when identity, privilege, process ancestry, and command-line behavior are correlated through the Windows logon context.

---

### Lab 07 — PowerShell Behavioral Detection

Develops and validates a behavioral PowerShell analytic using Windows process-creation and PowerShell script-block telemetry.

**Detection focus**

- Windows Security Event ID 4688
- PowerShell Operational Event ID 4104
- Process and script-block correlation
- Encoded PowerShell analysis
- Weighted behavioral scoring
- Controlled baseline and positive testing
- False-positive considerations
- Detection validation and query troubleshooting

**Behavioral scoring**

| Signal | Score |
|---|---:|
| `EncodedCommand` | +3 |
| `NonInteractive` | +1 |
| `NoProfile` | +1 |

**Validation results**

| Test | Score | Disposition |
|---|---:|---|
| E1 | 1 | BASELINE |
| E2 | 2 | REVIEW |
| E3 | 5 | INVESTIGATE |

The validation process identified a blind spot in the original Event ID 4688 investigation query: the E3 marker was contained inside Base64-encoded command-line content and therefore was not visible as plaintext.

The query was corrected and successfully retested.

**MITRE ATT&CK**

`T1059.001 — PowerShell`

**Key analyst lesson**

Event ID 4688 provides process and command-line context, while Event ID 4104 can reveal the PowerShell script content behind encoded execution.

```text
4688 → How was PowerShell launched?
4104 → What did PowerShell execute?
```

Security-relevant PowerShell behavior warrants investigation but does not, by itself, establish malicious intent.

**Lab artifacts**

- [Lab 07 — PowerShell Behavioral Detection](03-Detection-Engineering/Lab-07-PowerShell-Behavioral-Detection/)
- [Detection Script](03-Detection-Engineering/Lab-07-PowerShell-Behavioral-Detection/detection/powershell-behavioral-detection.ps1)
- [Analyst Findings](03-Detection-Engineering/Lab-07-PowerShell-Behavioral-Detection/docs/analyst-findings.md)
- [Validation Evidence](03-Detection-Engineering/Lab-07-PowerShell-Behavioral-Detection/evidence/)

**Final disposition**

TRUE POSITIVE — AUTHORIZED CONTROLLED ACTIVITY

---

### Lab 08 — Windows Multi-Stage Behavioral Correlation

Correlates multiple Windows security behaviors into a higher-context detection rather than evaluating individual events in isolation.

**Detection focus**

- Multi-stage Windows behavioral correlation
- Process-creation telemetry
- PowerShell activity
- Identity and execution context
- Parent/child process relationships
- Temporal event correlation
- Behavioral detection logic
- Controlled validation

**Key analyst lesson**

Individual security events may have limited investigative value on their own. Correlating related behaviors across a bounded time window can reveal a more meaningful activity sequence.

**Lab artifacts**

- [Lab 08 — Windows Multi-Stage Behavioral Correlation](03-Detection-Engineering/Lab-08-Windows-Multi-Stage-Behavioral-Correlation/)

---

### Lab 09 — Detection-to-Incident Workflow

Extends detection engineering into a complete SOC workflow from alert generation through analyst triage, investigation, and incident handoff.

**Detection focus**

- Detection alert creation
- Tier 1 analyst triage
- Evidence review
- Investigation timeline development
- Detection-to-incident workflow
- Analyst escalation and handoff
- Evidence-based disposition

**Key analyst lesson**

A detection becomes operationally useful when an analyst can validate it, establish context, document findings, and make a defensible escalation or disposition decision.

**Lab artifacts**

- [Lab 09 — Detection-to-Incident Workflow](03-Detection-Engineering/Lab-09-Detection-to-Incident-Workflow/)

---

### Lab 10 — Capstone SOC Investigation

Integrates the Starter Kit detection, correlation, triage, investigation, ATT&CK mapping, evidence assessment, and incident-reporting workflows into a complete SOC case.

**Investigation focus**

- Windows Event ID 4104 PowerShell telemetry
- Windows Event ID 4688 process creation
- Event ID 4624 logon correlation
- Event ID 4672 privilege correlation
- Logon ID correlation
- Parent/child process analysis
- Bounded incident timeline
- Cross-source corroboration
- MITRE ATT&CK mapping
- Tier 1 triage
- Competing-hypothesis analysis
- Incident disposition
- Final SOC incident reporting

**Observed discovery sequence**

```text
powershell.exe
|
+-- whoami.exe
+-- HOSTNAME.EXE
+-- whoami.exe /groups
+-- ipconfig.exe
```

**Final disposition**

TRUE POSITIVE — AUTHORIZED CONTROLLED ACTIVITY

**Security incident**

NO

**Case status**

CLOSED

**Key analyst lesson**

ATT&CK-mapped discovery behavior can represent legitimate administration, security testing, or adversary activity. Telemetry establishes what occurred; correlation and contextual investigation establish the appropriate disposition.

**Lab artifacts**

- [Lab 10 — Capstone SOC Investigation](03-Detection-Engineering/Lab-10-Capstone-SOC-Investigation/)
- [Final SOC Incident Report](03-Detection-Engineering/Lab-10-Capstone-SOC-Investigation/report/final-soc-incident-report.md)
- [Correlated Event Timeline](03-Detection-Engineering/Lab-10-Capstone-SOC-Investigation/evidence/correlated-event-timeline.md)
- [Investigation Analysis](03-Detection-Engineering/Lab-10-Capstone-SOC-Investigation/investigation/investigation-analysis.md)
- [MITRE ATT&CK Mapping](03-Detection-Engineering/Lab-10-Capstone-SOC-Investigation/investigation/mitre-attack-mapping.md)

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
* Behavioral detection scoring
* Event correlation
* Controlled detection validation
* Detection tuning and query troubleshooting
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

Personal identifiers, unnecessary host information, credentials, tokens, and other sensitive values are removed before public publication where applicable.

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

The goal is to produce alerts that an analyst can explain, investigate, and defend with evidence.

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

1. [Lab 01 — Linux Authentication Telemetry](02-Splunk-Labs/LAB-01-LINUX-AUTH-TELEMETRY.md)
2. [Lab 02 — Suspicious PowerShell](02-Splunk-Labs/LAB-02-SUSPICIOUS-POWERSHELL.md)
3. [Lab 03 — Network Reconnaissance](02-Splunk-Labs/LAB-03-NETWORK-RECONNAISSANCE.md)
4. [Lab 04 — SSH Brute Force](02-Splunk-Labs/LAB-04-SSH-BRUTE-FORCE.md)
5. [Lab 05 — SSH Success After Failure](02-Splunk-Labs/LAB-05-SSH-SUCCESS-AFTER-FAILURE.md)
6. [Lab 06 — Windows Identity, Privilege & Process Correlation](03-Detection-Engineering/Lab-06-Windows-Identity-Privilege-Process-Correlation/)
7. [Lab 07 — PowerShell Behavioral Detection](03-Detection-Engineering/Lab-07-PowerShell-Behavioral-Detection/)
8. [Lab 08 — Windows Multi-Stage Behavioral Correlation](03-Detection-Engineering/Lab-08-Windows-Multi-Stage-Behavioral-Correlation/)
9. [Lab 09 — Detection-to-Incident Workflow](03-Detection-Engineering/Lab-09-Detection-to-Incident-Workflow/)
10. [Lab 10 — Capstone SOC Investigation](03-Detection-Engineering/Lab-10-Capstone-SOC-Investigation/)

For the strongest single end-to-end example, review the [Lab 10 Final SOC Incident Report](03-Detection-Engineering/Lab-10-Capstone-SOC-Investigation/report/final-soc-incident-report.md).

---

## Purpose

This project demonstrates practical SOC analyst capability through repeatable, documented, evidence-backed lab work.

The emphasis is on:

**telemetry → detection → investigation → evidence → disposition**

rather than tool usage alone.

---

**SOC Analyst Starter Kit v1**
