# Lab 08 — Windows Multi-Stage Behavioral Correlation

## Overview

This lab develops and validates a Windows behavioral detection analytic
that correlates multiple discovery activities originating from a common
PowerShell parent process.

Rather than treating individual commands as inherently malicious, the
analytic evaluates the combined behavior using Windows process-creation
telemetry, PowerShell logging, parent-process relationships, account
context, behavioral diversity, and a bounded time window.

The result is a three-tier analyst disposition model:

| Score | Disposition |
|---:|---|
| 0-2 | BASELINE |
| 3-4 | REVIEW |
| 5+ | INVESTIGATE |

## Detection Objective

Identify clusters of Windows discovery activity that become increasingly
significant when several behaviors originate from the same PowerShell
parent process within a limited period.

The analytic currently evaluates:

- Identity discovery using `whoami`
- Group and privilege discovery using `whoami /groups`
- Host discovery using `hostname`
- Network configuration discovery using `ipconfig`
- Behavioral diversity across the correlated sequence
- PowerShell as the common parent process

## Primary Telemetry

| Event ID | Log | Purpose |
|---|---|---|
| 4688 | Windows Security | Process creation and parent-child correlation |
| 4104 | PowerShell Operational | PowerShell script-block visibility |

Supporting Events 4624 and 4672 were also evaluated during validation,
but were not automatically incorporated into the final Test C correlation.

## Behavioral Scoring

The analytic applies weighted scoring to the correlated process group:

| Detection Behavior | Score |
|---|---:|
| Identity discovery — `whoami` | +1 |
| Group/privilege discovery — `whoami /groups` | +2 |
| Host discovery — `hostname` | +1 |
| Network configuration discovery — `ipconfig` | +1 |
| Three or more distinct discovery behaviors | +2 |
| PowerShell common parent | +1 |

This approach allows common administrative commands to remain lower
severity when observed individually while increasing detection confidence
when several related behaviors occur together.

## Controlled Validation

Three controlled tests were performed against the analytic.

### Test A — Baseline

A PowerShell marker was generated without launching the monitored
discovery processes.

**Observed result:**

- Score: 0
- Disposition: BASELINE
- Discovery processes: 0

### Test B — Partial Correlation

The controlled session executed:

- `whoami`
- `hostname`

Both child processes were recorded by Event ID 4688 with the same
PowerShell Creator PID.

**Observed result:**

- Score: 3
- Disposition: REVIEW
- Behaviors: Identity, Host

### Test C — Full Correlation

The controlled session executed:

- `whoami`
- `hostname`
- `whoami /groups`
- `ipconfig`

All four Event ID 4688 records shared PowerShell Creator PID `0x46ec`.

```text
powershell.exe — PID 0x46ec
    ├── whoami.exe
    ├── HOSTNAME.EXE
    ├── whoami.exe /groups
    └── ipconfig.exe

```
**Observed result:**

- Score: 8
- Disposition: INVESTIGATE
- Behaviors: Identity, Groups, Host, Network

## Analyst Finding — Correlation Requires Evidence

During validation, Event ID 4672 was investigated as potential evidence
of privileged-session context.

Nearby Event ID 4672 records belonged to:

- Account: `SYSTEM`
- Domain: `NT AUTHORITY`
- Logon ID: `0x3E7`

No corresponding Event ID 4624 for the controlled user was identified
during the validation window.

Those events were therefore rejected from the Test C correlation.

This demonstrates an important detection-engineering principle:

> Temporal proximity alone does not establish correlation.

Account identity, Logon ID, parent-child process relationships, session
context, and other corroborating attributes should be validated before
events are treated as part of the same activity.

## MITRE ATT&CK Mapping

The controlled behaviors correspond to Windows discovery techniques,
including:

| Behavior | ATT&CK Technique |
|---|---|
| Account and identity discovery | T1033 — System Owner/User Discovery |
| Group discovery | T1069 — Permission Groups Discovery |
| Hostname discovery | T1082 — System Information Discovery |
| Network configuration discovery | T1016 — System Network Configuration Discovery |
| PowerShell execution context | T1059.001 — PowerShell |

ATT&CK mappings describe observed behavior and do not establish malicious
intent by themselves.

## Detection Limitations

This lab intentionally uses a focused command set for controlled validation.

The analytic does not currently cover every Windows discovery mechanism,
PowerShell equivalent, LOLBin, renamed binary, or alternate method of
collecting the same information.

Parent PID correlation is also bounded by the configured lookback window.
A long-running PowerShell process could otherwise cause unrelated activity
to be aggregated into the same behavioral sequence.

Production deployment would require additional tuning, environment-specific
baselining, allowlisting strategy, and broader command coverage.

## Repository Contents

```text
Lab-08-Windows-Multi-Stage-Behavioral-Correlation/
├── README.md
├── detection/
│   └── windows-multi-stage-behavioral-correlation.ps1
├── evidence/
│   └── validation-results.md
├── queries/
│   └── windows-event-correlation-queries.ps1
└── docs/
```

- `detection/` contains the behavioral scoring analytic.
- `evidence/` contains controlled validation results and analyst findings.
- `queries/` contains reproducible Windows event investigation queries.
- `docs/` is reserved for supporting documentation and future diagrams.

## Final Validation

| Test | Score | Disposition |
|---|---:|---|
| A | 0 | BASELINE |
| B | 3 | REVIEW |
| C | 8 | INVESTIGATE |

**Final Test C disposition: TRUE POSITIVE — AUTHORIZED CONTROLLED ACTIVITY**

The analytic successfully distinguished baseline activity, partial
discovery behavior, and a higher-confidence multi-stage discovery sequence.
