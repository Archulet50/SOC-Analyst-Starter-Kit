# Lab 09 — Detection-to-Incident Workflow

## Overview

This lab demonstrates the operational lifecycle of a security detection
after an analytic generates an alert.

Rather than ending with detection logic, the lab follows a validated
Windows behavioral alert through SOC triage, evidence reconstruction,
severity assessment, analyst disposition, and the decision whether to
escalate the case to formal incident response.

The source detection is Lab 08 — Windows Multi-Stage Behavioral
Correlation.

## Objective

Demonstrate an evidence-driven SOC workflow that answers:

> A detection fired. What should the analyst do next?

The workflow is:

```text
Windows Telemetry
       |
       v
Behavioral Detection
       |
       v
Alert
       |
       v
Initial Triage
       |
       v
Evidence Correlation
       |
       v
Scope and Severity Assessment
       |
       v
Analyst Disposition
       |
       v
Incident Escalation Decision
```

## Source Detection

Lab 08 correlated four Windows discovery behaviors originating from a
common PowerShell parent process:

```text
powershell.exe — PID 0x46ec
    ├── whoami.exe
    ├── HOSTNAME.EXE
    ├── whoami.exe /groups
    └── ipconfig.exe
```

The source analytic produced:

| Field | Result |
|---|---|
| Behavioral Score | `8` |
| Detection Threshold | `5` |
| Detection Disposition | `INVESTIGATE` |
| Correlated Behaviors | Identity, Host, Groups, Network |

The detection result establishes that the activity warrants
investigation. It does not independently establish malicious intent.

## SOC Alert

Lab 09 converts the detection result into:

`LAB09-ALERT-001`

Initial case state:

| Field | Initial Value |
|---|---|
| Alert Status | OPEN — INVESTIGATION REQUIRED |
| Severity | MEDIUM |
| Detection Validity | Not yet determined by analyst |
| Authorization | Not yet established |
| IR Escalation | Pending investigation |

This preserves separation between detection and analyst judgment.

## Analyst Investigation

The investigation evaluates:

- User identity
- Endpoint context
- Parent-child process relationships
- Event ID 4688 process creation
- Event ID 4104 PowerShell telemetry
- Possible privilege context
- Behavioral scope
- Evidence of additional malicious activity
- Authorization context

The four discovery processes shared PowerShell Creator PID `0x46ec`,
supporting treatment of the activity as one behavioral sequence.

## Privilege-Correlation Finding

Nearby Event ID 4672 records were investigated as possible evidence of
privileged execution.

The observed privilege events belonged to:

- Account: `SYSTEM`
- Domain: `NT AUTHORITY`
- Logon ID: `0x3E7`

No corresponding Event ID 4624 evidence was identified that linked the
controlled user to those privilege events during the validation window.

The 4672 events were therefore rejected from the alert correlation.

This demonstrates a central principle of the workflow:

> Temporal proximity alone does not establish event correlation.

Security context should be supported by identity, session identifiers,
process relationships, or other corroborating evidence before unrelated
events are incorporated into an investigation.

## Scope Assessment

The investigation established:

- One identified user context
- One PowerShell parent process
- Four correlated discovery processes
- Identity discovery
- Host discovery
- Group discovery
- Network configuration discovery

The reviewed evidence did not establish:

- Credential access
- Privilege escalation
- Persistence
- Lateral movement
- Remote execution
- Command-and-control activity
- Collection or exfiltration
- Additional affected endpoints

These findings define the boundaries of the available evidence and do
not assert that unobserved activity would be impossible.

## Authorization and Disposition

Investigation established that the discovery sequence was intentionally
generated during the authorized Lab 08 controlled validation exercise.

This changed the operational assessment without invalidating the
detection.

| Decision | Result |
|---|---|
| Detection Validity | TRUE POSITIVE |
| Activity Classification | AUTHORIZED CONTROLLED ACTIVITY |
| Initial Severity | MEDIUM |
| Final Severity | INFORMATIONAL |
| Incident Declared | NO |
| IR Handoff | NOT REQUIRED |
| Case Status | CLOSED |

The distinction is important:

**A true-positive detection does not necessarily represent malicious
activity or a security incident.**

The detection correctly identified the behavior it was designed to
detect. Analyst investigation supplied the authorization and impact
context required for final disposition.

## MITRE ATT&CK Mapping

| Observed Behavior | ATT&CK Technique |
|---|---|
| User identity discovery | T1033 — System Owner/User Discovery |
| Permission group discovery | T1069 — Permission Groups Discovery |
| Host discovery | T1082 — System Information Discovery |
| Network configuration discovery | T1016 — System Network Configuration Discovery |
| PowerShell execution context | T1059.001 — PowerShell |

ATT&CK mappings describe observed behavior and do not independently
establish malicious intent.

## Detection-to-Incident Decision Model

```text
Detection fires
      |
      v
Is the detection behavior supported by telemetry?
      |
     YES
      |
      v
Investigate identity, process, scope, and context
      |
      v
Is malicious or unauthorized activity established?
      |
   NO — Authorized controlled activity
      |
      v
TRUE POSITIVE
      |
      v
No incident declared
      |
      v
Close case and preserve evidence
```

If investigation instead established unauthorized execution, compromise,
impact, or progression into additional attack behaviors, the case would
cross the incident threshold and require escalation.

## Repository Contents

```text
Lab-09-Detection-to-Incident-Workflow/
├── README.md
├── alert/
│   └── detection-alert.md
├── triage/
│   └── analyst-triage.md
├── evidence/
│   └── investigation-timeline.md
├── incident/
│   └── incident-handoff.md
└── docs/
```

## Final Result

`LAB09-ALERT-001` completed the full SOC decision workflow:

**DETECTION → ALERT → TRIAGE → INVESTIGATION → DISPOSITION → IR DECISION**

Final disposition:

**TRUE POSITIVE — AUTHORIZED CONTROLLED ACTIVITY**

Final severity:

**INFORMATIONAL**

Incident response handoff:

**NOT REQUIRED**

Lab 09 demonstrates that effective SOC analysis requires both reliable
detection logic and disciplined interpretation of the evidence after an
alert fires.
