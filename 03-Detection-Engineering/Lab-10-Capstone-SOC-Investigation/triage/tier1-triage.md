# Lab 10 — Tier-1 Analyst Triage

## Alert

**Multi-Stage Windows Discovery from PowerShell**

**Initial Severity:** Medium

**Host:** `MATTS-VAIO`

**Account:** `MATTS-VAIO\Matt Archuleta`

## Initial Triage

The alert identified four discovery processes originating from a common PowerShell parent during a 33-second execution sequence.

The observed commands were:

1. `whoami.exe`
2. `HOSTNAME.EXE`
3. `whoami.exe /groups`
4. `ipconfig.exe`

These commands can occur during legitimate administration, troubleshooting, or security testing. They are also consistent with system discovery activity that may follow unauthorized access.

Command presence alone is therefore insufficient to determine intent.

## Validation

Event ID 4688 confirmed all four process executions.

Each process shared:

- Creator PID `0x2e94`
- Logon ID `0x13b3e7cc`
- Local account context

Event ID 4104 independently corroborated the PowerShell command sequence.

## Session Context

Logon ID `0x13b3e7cc` correlated directly to:

- Event ID 4624 — Logon Type 2 (Interactive)
- Event ID 4672 — Special privileges assigned

The session correlation is based on the exact Logon ID rather than temporal proximity alone.

## Scope

All Event ID 4688 child processes from Creator PID `0x2e94` within the investigation window were reviewed.

No additional child processes from that parent were observed in the bounded window.

No evidence reviewed during initial triage established persistence, credential theft, lateral movement, command-and-control, malware execution, or data exfiltration.

## Triage Assessment

**Detection Fidelity:** True Positive

The behavior described by the detection occurred and was independently corroborated.

**Maliciousness:** Undetermined during initial triage

The available evidence establishes discovery behavior but does not establish malicious intent.

## Triage Decision

**Escalate for contextual investigation.**

Reason: the detection is valid and occurred within a privileged interactive session, but additional context is required to distinguish authorized administrative or testing activity from post-compromise discovery.
