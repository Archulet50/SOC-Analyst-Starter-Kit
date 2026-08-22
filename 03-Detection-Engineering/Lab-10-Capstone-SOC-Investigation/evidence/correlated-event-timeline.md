# Lab 10 — Correlated Event Timeline

## Case

**Case Marker:** `LAB10-CAPSTONE-INCIDENT`
**Host:** `MATTS-VAIO`
**Investigation Window:** August 22, 2026 — 15:41:14 through 15:43:13

## Session Context

- Account: `MATTS-VAIO\Matt Archuleta`
- Logon ID: `0x13b3e7cc`
- PowerShell PID: `11924` / `0x2e94`

## Correlated Timeline

| Time | Event | Observation | Correlation |
|---|---|---|---|
| 11:37:57 | 4624 | Successful interactive logon | Logon ID `0x13b3e7cc`; Logon Type 2 |
| 11:37:57 | 4672 | Special privileges assigned | Logon ID `0x13b3e7cc` |
| 15:41:15 | 4104 | `LAB10-CAPSTONE-INCIDENT` marker | PowerShell activity recorded |
| 15:42:32 | 4104 / 4688 | `whoami` / `whoami.exe` | Creator PID `0x2e94`; Logon ID `0x13b3e7cc` |
| 15:42:39 | 4104 / 4688 | `hostname` / `HOSTNAME.EXE` | Creator PID `0x2e94`; Logon ID `0x13b3e7cc` |
| 15:42:55 | 4104 / 4688 | `whoami /groups` / `whoami.exe /groups` | Creator PID `0x2e94`; Logon ID `0x13b3e7cc` |
| 15:43:05 | 4104 / 4688 | `ipconfig` / `ipconfig.exe` | Creator PID `0x2e94`; Logon ID `0x13b3e7cc` |

## Process Evidence

```text
powershell.exe — PID 11924 / 0x2e94
|
+-- whoami.exe          PID 0xccc   15:42:32
+-- HOSTNAME.EXE        PID 0x34d4  15:42:39
+-- whoami.exe /groups  PID 0x4d18  15:42:55
+-- ipconfig.exe        PID 0x42e4  15:43:05
```

## Logon Correlation

The four Event ID 4688 records shared Logon ID `0x13b3e7cc`.

That exact Logon ID was also identified in:

- Event ID 4624 at 11:37:57 — successful Logon Type 2 (Interactive)
- Event ID 4672 at 11:37:57 — special privileges assigned

This establishes session context using a persistent Logon ID rather than timestamp proximity alone.

## PowerShell Corroboration

Event ID 4104 recorded the case marker and all four discovery commands.

- 15:41:15 — `LAB10-CAPSTONE-INCIDENT`
- 15:42:32 — `whoami`
- 15:42:39 — `hostname`
- 15:42:55 — `whoami /groups`
- 15:43:05 — `ipconfig`

The four command timestamps aligned with the corresponding Event ID 4688 process-creation timestamps.

## Scope Check

All Event ID 4688 child processes from Creator PID `0x2e94` inside the bounded incident window were enumerated.

Exactly four were observed:

1. `whoami.exe`
2. `HOSTNAME.EXE`
3. `whoami.exe /groups`
4. `ipconfig.exe`

No additional child processes from that parent were observed inside the defined window.

This finding is limited to the queried time window and available telemetry.

## Telemetry Gap

The investigation did not locate the Event ID 4688 record representing creation of PowerShell PID `0x2e94` within the queried range.

This does not invalidate the child-process relationship because all four confirmed child events independently identify `0x2e94` as their Creator PID.

## Evidence Assessment

### Observed Facts

- Four discovery processes executed during the incident window.
- All four shared Creator PID `0x2e94`.
- All four shared Logon ID `0x13b3e7cc`.
- Event ID 4104 corroborated the command sequence.
- Event IDs 4624 and 4672 matched the exact Logon ID.
- No additional child processes from `0x2e94` were observed in the bounded window.

### Supported Inference

The discovery sequence occurred within the same privileged interactive Windows logon session represented by Logon ID `0x13b3e7cc`.

### Not Established

The collected evidence does not by itself establish malware execution, credential theft, persistence, lateral movement, command-and-control, data exfiltration, or malicious intent.

## Evidence Integrity

Temporal proximity was not used as the sole basis for correlation. The investigation relied on Logon ID, Creator PID, account identity, parent-child process relationships, command-line evidence, and cross-log timestamp agreement.
