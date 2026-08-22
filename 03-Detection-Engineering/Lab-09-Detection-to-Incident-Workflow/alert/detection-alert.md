# Detection Alert — Windows Multi-Stage Discovery

## Alert Summary

**Alert ID:** LAB09-ALERT-001  
**Detection Source:** Lab 08 — Windows Multi-Stage Behavioral Correlation  
**Alert Status:** OPEN — INVESTIGATION REQUIRED  
**Detection Score:** 8  
**Detection Disposition:** INVESTIGATE  
**Initial Severity:** MEDIUM  
**Platform:** Windows  
**Detection Parent:** PowerShell

## Trigger Condition

The alert was generated after multiple Windows discovery behaviors were
correlated to the same PowerShell parent process within the detection
window.

The source analytic assigned a score of 8, exceeding the investigation
threshold of 5.

## Observed Behaviors

The correlated process sequence contained:

- Identity discovery using `whoami`
- Host discovery using `hostname`
- Group discovery using `whoami /groups`
- Network configuration discovery using `ipconfig`

All four processes were associated with the same PowerShell parent
process.

```text
powershell.exe — PID 0x46ec
    ├── whoami.exe
    ├── HOSTNAME.EXE
    ├── whoami.exe /groups
    └── ipconfig.exe

```

## Required Analyst Triage

The receiving analyst should validate the following before assigning a
final disposition:

1. Confirm the affected user and endpoint.
2. Validate the PowerShell parent process and Creator PID.
3. Review the complete Event ID 4688 process sequence.
4. Review relevant Event ID 4104 PowerShell telemetry.
5. Determine whether additional child processes were created.
6. Evaluate whether the activity occurred within an expected
   administrative or troubleshooting workflow.
7. Search for related authentication, privilege, persistence, execution,
   or network activity.
8. Determine whether the behavior was authorized.

## Investigation Questions

The analyst should answer:

- Who executed the activity?
- On which endpoint did it occur?
- When did the sequence begin and end?
- What process initiated the discovery commands?
- Which discovery behaviors were observed?
- Did all discovery processes share the same parent?
- Was elevated or privileged execution involved?
- Did activity continue beyond discovery?
- Is there evidence of persistence, credential access, lateral movement,
  command-and-control, or data collection?
- Can the activity be associated with an approved administrative action
  or controlled security test?

## Escalation Criteria

Escalate the alert when one or more of the following are identified:

- The user cannot be validated.
- The activity is unauthorized or unexplained.
- Additional suspicious PowerShell activity is identified.
- Discovery is followed by credential access or privilege escalation.
- Remote execution or lateral movement is observed.
- Persistence mechanisms are created.
- Suspicious external network communication is identified.
- The activity affects additional endpoints.
- Evidence suggests the discovery sequence is part of a larger intrusion.

## Alert-to-Case Transition

Because the analytic produced an `INVESTIGATE` disposition, this alert
should proceed to analyst triage rather than being automatically closed.

**Current case state:** `OPEN — TRIAGE REQUIRED`

The final alert disposition will be assigned only after the evidence is
reviewed and authorization context is established.
