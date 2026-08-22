# Lab 10 — Capstone SOC Investigation

## Overview

This capstone demonstrates an end-to-end SOC investigation beginning with a behavioral detection and progressing through evidence validation, analyst triage, cross-source correlation, MITRE ATT&CK mapping, incident determination, response decision, and final reporting.

The scenario investigates multiple Windows discovery processes originating from a common PowerShell parent on `MATTS-VAIO`.

The objective is not simply to identify suspicious commands. The analyst must determine what the telemetry proves, distinguish evidence from inference, reject unsupported correlations, evaluate competing hypotheses, and reach a defensible disposition.

## Investigation Workflow

```text
Behavioral Detection
        |
        v
Initial Alert
        |
        v
Tier-1 Triage
        |
        v
Evidence Validation
        |
        v
Process + Session Correlation
        |
        v
Contextual Investigation
        |
        v
MITRE ATT&CK Mapping
        |
        v
Incident Determination
        |
        v
Response Decision
        |
        v
Final SOC Report
```

## Observed Activity

The investigation confirmed four discovery processes executing from PowerShell Creator PID `0x2e94`:

- `whoami.exe` — identity discovery
- `HOSTNAME.EXE` — host discovery
- `whoami.exe /groups` — group and privilege discovery
- `ipconfig.exe` — network configuration discovery

All four process-creation events shared Logon ID `0x13b3e7cc`.

PowerShell Event ID 4104 independently corroborated the command sequence.

## Correlation Findings

The investigation established the following relationships:

- All four discovery processes shared Creator PID `0x2e94`.
- All four shared Logon ID `0x13b3e7cc`.
- Event ID 4104 corroborated the PowerShell command sequence.
- Event ID 4624 associated the Logon ID with a Type 2 interactive session.
- Event ID 4672 associated special privileges with the same Logon ID.
- No additional child processes from Creator PID `0x2e94` were observed inside the bounded investigation window.

Correlation was based on persistent identifiers and process relationships rather than timestamp proximity alone.

## MITRE ATT&CK Mapping

| Behavior | Technique | ID |
|---|---|---|
| Identity discovery | System Owner/User Discovery | T1033 |
| Host discovery | System Information Discovery | T1082 |
| Group discovery | Permission Groups Discovery: Local Groups | T1069.001 |
| Network discovery | System Network Configuration Discovery | T1016 |
| PowerShell execution | Command and Scripting Interpreter: PowerShell | T1059.001 |

ATT&CK mapping describes observed behavior and does not independently establish malicious intent.

## Final Disposition

**Detection Result:** TRUE POSITIVE

**Activity Classification:** AUTHORIZED CONTROLLED ACTIVITY

**Security Incident:** NO

**Case Status:** CLOSED

The detection correctly identified the targeted behavior. Contextual investigation established that the behavior was intentionally generated during an authorized security-lab exercise.

The case therefore remains a true-positive detection rather than being reclassified as a false positive.

## Skills Demonstrated

- Windows Event Log investigation
- Event ID 4688 process analysis
- PowerShell Event ID 4104 analysis
- Event ID 4624 and 4672 session correlation
- Parent-child process analysis
- Logon ID correlation
- Behavioral detection validation
- Evidence scoping
- Hypothesis-driven investigation
- MITRE ATT&CK mapping
- Incident triage and escalation
- Incident disposition
- Detection engineering analysis
- SOC reporting

## Capstone Artifacts

| Artifact | Purpose |
|---|---|
| `scenario/incident-scenario.md` | Defines the unknown-event investigation scenario |
| `detection/detection-alert.md` | Presents the initial behavioral alert |
| `triage/tier1-triage.md` | Documents initial analyst validation and escalation |
| `evidence/correlated-event-timeline.md` | Preserves correlated telemetry and evidence findings |
| `investigation/investigation-analysis.md` | Documents hypotheses, correlation, and contextual analysis |
| `investigation/mitre-attack-mapping.md` | Maps observed behavior to ATT&CK techniques |
| `incident/incident-disposition.md` | Records response decision and case closure |
| `report/final-soc-incident-report.md` | Provides the completed SOC investigation report |

## Key Takeaway

A detection can be completely accurate without representing malicious activity.

Effective SOC analysis requires validating what occurred, establishing defensible relationships between events, determining context and scope, and separating detection fidelity from maliciousness.

This capstone demonstrates that complete workflow from alert through final disposition.
