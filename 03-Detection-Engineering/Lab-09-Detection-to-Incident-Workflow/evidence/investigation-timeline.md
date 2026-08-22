# Investigation Timeline — LAB09-ALERT-001

## Purpose

This timeline reconstructs the Windows discovery activity associated with
LAB09-ALERT-001 using validated telemetry preserved from Lab 08.

Times reflect the controlled validation session on August 22, 2026.

## Evidence Sources

- Windows Security Event ID 4688 — Process Creation
- PowerShell Operational Event ID 4104 — Script Block Logging
- Lab 08 behavioral-correlation results
- Lab 08 validation evidence

## Timeline

| Time | Source | Observation | Analyst Assessment |
|---|---|---|---|
| 12:38:55 PM | 4104 | Lab 08 PowerShell activity observed | Beginning of relevant PowerShell telemetry |
| 12:39:06 PM | 4688 | `whoami.exe` created by PowerShell PID `0x46ec` | Identity discovery |
| 12:39:06 PM | 4688 | `HOSTNAME.EXE` created by PowerShell PID `0x46ec` | Host discovery |
| 12:39:06 PM | 4688 | `whoami.exe /groups` created by PowerShell PID `0x46ec` | Group discovery |
| 12:39:35 PM | 4104 | Additional PowerShell script-block activity observed | Continued session activity |
| 12:40:27 PM | 4688 | `ipconfig.exe` created by PowerShell PID `0x46ec` | Network configuration discovery |
| 12:40:27 PM | 4104 | PowerShell telemetry observed near final discovery activity | Cross-source corroboration |

## Correlated Process Sequence

```text
PowerShell PID 0x46ec
    |
    +-- 12:39:06 — whoami.exe
    |
    +-- 12:39:06 — HOSTNAME.EXE
    |
    +-- 12:39:06 — whoami.exe /groups
    |
    +-- 12:40:27 — ipconfig.exe

```
## Privilege-Correlation Review

Nearby Event ID 4672 records were examined for possible association with
the discovery sequence.

Observed 4672 context:

- Account: `SYSTEM`
- Domain: `NT AUTHORITY`
- Logon ID: `0x3E7`

These attributes did not establish a relationship to the identified user
executing the discovery processes.

No corresponding Event ID 4624 was identified during the validation
window that linked the controlled user to those Event ID 4672 records.

The privilege events were therefore excluded from the correlated activity
timeline.

**Finding:** Temporal proximity did not provide sufficient evidence to
associate the 4672 events with the discovery sequence.

## Evidence Boundaries

The validated evidence establishes:

- A common PowerShell parent process
- Four related discovery processes
- One identified user context
- Event ID 4688 process-creation telemetry
- Event ID 4104 PowerShell telemetry
- Identity, host, group, and network discovery

The reviewed evidence does not establish:

- Privilege escalation
- Credential access
- Persistence
- Lateral movement
- Remote execution
- Command-and-control
- Collection or exfiltration
- Additional affected endpoints

These are evidence boundaries rather than assertions that such activity
could never have occurred.

## Timeline Assessment

The chronological evidence supports a coherent multi-stage discovery
sequence originating from PowerShell PID `0x46ec`.

The process relationship, behavioral diversity, and cross-source telemetry
justify the original `INVESTIGATE` disposition.

Subsequent analyst review established that the sequence was generated
during the authorized Lab 08 controlled validation exercise.

**Detection assessment:** TRUE POSITIVE  
**Activity assessment:** AUTHORIZED CONTROLLED ACTIVITY  
**Incident escalation:** NOT REQUIRED

The timeline therefore supports case closure while preserving the original
detection as valid.
