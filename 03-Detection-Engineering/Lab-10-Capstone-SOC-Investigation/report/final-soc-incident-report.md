# Lab 10 — Final SOC Incident Report

## Executive Summary

On August 22, 2026, a behavioral detection identified multiple Windows discovery processes executing from a common PowerShell parent on host `MATTS-VAIO`.

The observed sequence consisted of identity, host, group/privilege, and network configuration discovery. Windows Security Event ID 4688 confirmed the process executions, while PowerShell Event ID 4104 independently corroborated the command activity.

All four discovery processes shared Creator PID `0x2e94` and Logon ID `0x13b3e7cc`. The Logon ID correlated directly to Event ID 4624 for an interactive logon and Event ID 4672 for special privileges.

Investigation established that the detected activity was intentionally generated during an authorized controlled security-lab exercise.

**Final Disposition:** TRUE POSITIVE — AUTHORIZED CONTROLLED ACTIVITY

**Security Incident:** NO

**Case Status:** CLOSED

## Alert Details

**Alert:** Multi-Stage Windows Discovery from PowerShell

**Initial Severity:** Medium

**Host:** `MATTS-VAIO`

**Account:** `MATTS-VAIO\Matt Archuleta`

**Investigation Window:** August 22, 2026 — 15:41:14 through 15:43:13

**PowerShell PID:** `11924` / `0x2e94`

**Logon ID:** `0x13b3e7cc`

## Evidence Summary

### Process Creation — Event ID 4688

Four discovery processes were confirmed beneath PowerShell Creator PID `0x2e94`:

| Time | Process | Process ID | Creator PID |
|---|---|---|---|
| 15:42:32 | `whoami.exe` | `0xccc` | `0x2e94` |
| 15:42:39 | `HOSTNAME.EXE` | `0x34d4` | `0x2e94` |
| 15:42:55 | `whoami.exe /groups` | `0x4d18` | `0x2e94` |
| 15:43:05 | `ipconfig.exe` | `0x42e4` | `0x2e94` |

All four events shared Logon ID `0x13b3e7cc`.

### PowerShell — Event ID 4104

Script Block Logging independently recorded the case marker and corresponding discovery commands. The command timestamps aligned with the Event ID 4688 process-creation timestamps.

### Session Correlation

Logon ID `0x13b3e7cc` correlated directly to:

- Event ID 4624 at 11:37:57 — successful Logon Type 2 (Interactive)
- Event ID 4672 at 11:37:57 — special privileges assigned

The relationship was established through the exact Logon ID rather than temporal proximity alone.

### Scope

All Event ID 4688 child processes from Creator PID `0x2e94` within the bounded investigation window were reviewed. Only the four discovery processes were observed.

No additional child processes from that PowerShell parent were identified within the defined window.

## Investigation Timeline

| Time | Activity |
|---|---|
| 11:37:57 | Interactive logon recorded under Logon ID `0x13b3e7cc` |
| 11:37:57 | Special privileges assigned to the same Logon ID |
| 15:41:15 | `LAB10-CAPSTONE-INCIDENT` marker recorded by PowerShell telemetry |
| 15:42:32 | Identity discovery — `whoami` |
| 15:42:39 | Host discovery — `hostname` |
| 15:42:55 | Group/privilege discovery — `whoami /groups` |
| 15:43:05 | Network configuration discovery — `ipconfig` |

## MITRE ATT&CK Assessment

The observed activity maps to the following ATT&CK techniques:

| Behavior | Technique | ID |
|---|---|---|
| Identity discovery | System Owner/User Discovery | T1033 |
| Host discovery | System Information Discovery | T1082 |
| Group discovery | Permission Groups Discovery: Local Groups | T1069.001 |
| Network discovery | System Network Configuration Discovery | T1016 |
| PowerShell execution context | Command and Scripting Interpreter: PowerShell | T1059.001 |

ATT&CK classification describes observed behavior and does not independently establish malicious intent.

## Analyst Assessment

The detection was validated as a true positive because the targeted multi-stage discovery behavior occurred and was corroborated across Windows Security and PowerShell telemetry.

During initial triage, maliciousness remained undetermined. The sequence was compatible with both legitimate administrative or security activity and post-compromise discovery.

Investigation established common process ancestry, a shared logon session, cross-source command corroboration, and bounded scope. No reviewed evidence established persistence, credential theft, lateral movement, malware execution, command-and-control, or data exfiltration.

Contextual validation subsequently established that the activity was intentionally generated as part of an authorized controlled security-lab exercise.

## Final Disposition

**Detection Result:** TRUE POSITIVE

**Activity Classification:** AUTHORIZED CONTROLLED ACTIVITY

**Security Incident:** NO

**Case Status:** CLOSED

The case is not classified as a false positive. The detection correctly identified the behavior it was designed to identify; investigation determined that the correctly detected activity was authorized.

## Response Actions

Containment and eradication are not required for this case.

The investigation does not support host isolation, account disablement, credential reset, or other disruptive response actions.

The evidence and investigation artifacts should be retained as validation material for the behavioral detection and SOC workflow.

## Detection Engineering Recommendation

Retain the behavioral detection.

In an operational environment, authorized administrative or security-testing context may be used for enrichment or narrowly scoped suppression where appropriate. Broad suppression of PowerShell or discovery commands should be avoided because similar behavior may represent genuine post-compromise discovery.

## Lessons Learned

- A true-positive detection does not automatically represent a malicious incident.
- Process ancestry strengthens behavioral correlation.
- Logon IDs provide stronger session correlation than timestamp proximity alone.
- Cross-source telemetry can independently corroborate execution behavior.
- ATT&CK mapping describes behavior rather than intent.
- Bounded scope findings must not be generalized beyond the queried evidence.
- Unsupported correlations should be rejected rather than forced into an investigation narrative.

## Analyst Conclusion

The investigation confirmed a real multi-stage Windows discovery sequence originating from a common PowerShell parent within a privileged interactive session. The behavior was accurately detected and independently corroborated by multiple telemetry sources.

Context established that the sequence was authorized controlled activity. No malicious compromise was established from the reviewed evidence.

**Final case disposition: TRUE POSITIVE — AUTHORIZED CONTROLLED ACTIVITY — CLOSED.**
