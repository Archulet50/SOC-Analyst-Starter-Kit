# Lab 10 — SOC Investigation Analysis

## Investigation Question

Does the validated multi-stage discovery sequence represent malicious post-compromise activity or authorized activity?

## Evidence Reviewed

The investigation reviewed:

- Windows Security Event ID 4688 process creation
- PowerShell Operational Event ID 4104
- Windows Security Event ID 4624 successful logon
- Windows Security Event ID 4672 special privileges
- Account and Logon ID relationships
- Parent-child process relationships
- Command-line telemetry
- Bounded process scope

## Process Correlation

Four discovery processes were confirmed beneath PowerShell Creator PID `0x2e94`:

- `whoami.exe`
- `HOSTNAME.EXE`
- `whoami.exe /groups`
- `ipconfig.exe`

All four shared Logon ID `0x13b3e7cc`.

The sequence occurred over approximately 33 seconds.

## Cross-Source Corroboration

Event ID 4104 independently recorded the corresponding PowerShell activity at timestamps matching the Event ID 4688 process executions.

This supports the conclusion that the observed process sequence originated from the investigated PowerShell activity.

## Session Analysis

Logon ID `0x13b3e7cc` correlated directly to Event IDs 4624 and 4672.

Event ID 4624 identified Logon Type 2, representing an interactive session. Event ID 4672 showed special privileges associated with the same Logon ID.

The correlation was accepted because the session identifier matched exactly. Temporal proximity alone was not used as evidence of session membership.

## Scope Analysis

A query for all Event ID 4688 child processes from Creator PID `0x2e94` during the bounded incident window returned only the four discovery processes under investigation.

No additional process activity from that parent was observed within the defined window.

This does not prove that no other activity occurred outside the queried scope.

## Competing Hypotheses

### Hypothesis 1 — Malicious Post-Compromise Discovery

The command sequence is compatible with discovery behavior an attacker could perform after obtaining interactive access.

Evidence supporting consideration of this hypothesis includes rapid execution of multiple discovery commands from PowerShell within a privileged session.

However, the reviewed evidence did not establish malware execution, persistence, credential theft, lateral movement, command-and-control, or exfiltration.

### Hypothesis 2 — Authorized Administrative or Security Activity

The same commands are commonly used during administration, troubleshooting, security validation, and laboratory exercises.

The bounded scope and absence of additional suspicious child processes are consistent with controlled activity, although those facts alone cannot establish authorization.

## Contextual Resolution

The activity was confirmed as an authorized controlled security-lab exercise associated with `LAB10-CAPSTONE-INCIDENT`.

This context resolves the maliciousness question without changing the detection-fidelity assessment: the detection correctly identified the behavior it was designed to detect.

## Final Investigation Determination

**Detection Result:** TRUE POSITIVE

**Activity Classification:** AUTHORIZED CONTROLLED ACTIVITY

**Malicious Incident:** NO

**Escalation Outcome:** CLOSE AS AUTHORIZED ACTIVITY

## Analyst Rationale

The telemetry proves that multi-stage discovery occurred within a privileged interactive session and was correctly detected. Cross-source evidence supports the process and session relationships. Contextual validation establishes that the activity was intentionally generated for an authorized security exercise.

The case should therefore be closed as a true-positive detection of authorized activity rather than reclassified as a false positive.
