# Lab 06 — Windows Identity, Privilege, and Process Correlation

## Overview

This detection-engineering lab correlates Windows authentication,
privilege-assignment, and process-creation telemetry to identify
administrative discovery occurring within a validated privileged logon
context.

The detection was derived from the controlled telemetry generated and
validated in Splunk Lab 06 — Windows Privileged Administrative Discovery.

Rather than correlating events solely because they occur near one another
in time, the analytic requires a shared Windows Logon ID relationship
across the authentication, privilege, and process telemetry.

## Detection Objective

Detect administrative discovery only when the process responsible for
the activity can be associated with a privileged Windows logon context.

The validated correlation chain is:

```text
4624 — Interactive Logon
New Logon ID: 0x1F23C58
        |
        +-- Linked Logon ID: 0x1F23B71
                         |
                         +-- 4672 — Special Privileges
                         |   Logon ID: 0x1F23B71
                         |
                         +-- 4688 — Process Creation
                             Creator Logon ID: 0x1F23B71
```

The shared identifier `0x1F23B71` establishes the relationship between
the linked privileged session, assignment of special privileges, and
subsequent process activity.

## Primary Telemetry

| Event ID | Purpose |
|---|---|
| 4624 | Successful authentication and linked logon context |
| 4672 | Assignment of special privileges |
| 4688 | Process creation and creator logon context |

## Detection Logic

The Splunk analytic builds three correlation values:

- Event 4672 `logon_id` identifies privileged logon sessions.
- Event 4624 `linked_logon_id` identifies linked privileged contexts.
- Event 4688 `logon_id` identifies the session responsible for process creation.

A process is considered privilege-correlated only when its Event 4688
Logon ID appears in both the privileged-logon and linked-logon sets.

The detection then requires administrative discovery using `net.exe` or
`net1.exe` with a command line containing `localgroup Administrators`.

```

## Controlled Validation

The correlation was validated using controlled Windows activity preserved
from Splunk Lab 06.

The validated identifiers were:

| Telemetry | Correlation Value |
|---|---|
| 4624 New Logon ID | `0x1F23C58` |
| 4624 Linked Logon ID | `0x1F23B71` |
| 4672 Logon ID | `0x1F23B71` |
| 4688 Creator Logon ID | `0x1F23B71` |

The 4624 event recorded an interactive Logon Type 2 session for the
controlled user.

Its Linked Logon ID matched both the Event 4672 privileged-session
identifier and the Creator Logon ID associated with the Event 4688
process activity.

**Validation result:**

`IDENTITY-PRIVILEGE-PROCESS CORRELATION CONFIRMED`

## Analyst Significance

This lab demonstrates why security-event correlation should be based on
shared contextual identifiers rather than timestamp proximity alone.

A nearby Event 4672 does not automatically prove that a process executed
within that privileged session.

The analytic requires the process Logon ID to match evidence from both:

1. the linked privileged context recorded by Event 4624; and
2. the special-privilege assignment recorded by Event 4672.

Only after establishing that relationship does the analytic evaluate the
administrative discovery behavior recorded by Event 4688.

This reduces the risk of attributing unrelated operating-system or user
activity to the wrong security context.

## MITRE ATT&CK Mapping

| Behavior | ATT&CK Technique |
|---|---|
| Account discovery | T1087 — Account Discovery |
| Permission group discovery | T1069 — Permission Groups Discovery |

The validated `net localgroup Administrators` activity represents
administrative group discovery. ATT&CK mappings describe observed
behavior and do not independently establish malicious intent.

## Detection Limitations

The analytic is intentionally scoped to the controlled Lab 06 telemetry
and the validated administrative discovery command.

Current detection logic specifically evaluates:

- Windows Events 4624, 4672, and 4688;
- linked and privileged Logon ID relationships;
- `net.exe` or `net1.exe`; and
- command lines containing `localgroup Administrators`.

Production deployment would require environment-specific baselining,
additional discovery-command coverage, service-account considerations,
normal administrative workflow analysis, and tuning for expected
privileged activity.

## Artifact Provenance

The detection and validation evidence in this directory were copied from
the previously validated Splunk Lab 06 artifacts without modification.

SHA-256 verification confirmed byte-for-byte preservation.

```text
Detection SPL
11d3bc8ebf6b5677fcfd7697f6e52801999e69fe2c59f824692363c6dd2c7d37

Validation Evidence
740d692614bf972ed4838cf5d9815c6da076356c2d0569675fb92b4ef56bedfa
```

## Repository Contents

```text
Lab-06-Windows-Identity-Privilege-Process-Correlation/
├── README.md
├── detection/
│   └── identity-privilege-process-correlation.spl
├── evidence/
│   └── Test-D-Identity-Privilege-Correlation.txt
├── queries/
└── docs/
```

- `detection/` contains the validated Splunk correlation analytic.
- `evidence/` contains the preserved Windows validation evidence.
- `queries/` is reserved for supporting investigation queries.
- `docs/` is reserved for supporting documentation.

## Final Assessment

**IDENTITY-PRIVILEGE-PROCESS CORRELATION CONFIRMED**

Lab 06 demonstrates correlation of authentication, privilege assignment,
and process execution through Windows Logon IDs before applying
behavioral detection logic to administrative discovery activity.

```
