# Lab 10 — MITRE ATT&CK Mapping

## Overview

The observed activity maps primarily to the MITRE ATT&CK Discovery tactic. Mapping is based on the behavior demonstrated by each command rather than an assumption of malicious intent.

| Observed Command | ATT&CK Technique | Technique ID | Rationale |
|---|---|---|---|
| `whoami.exe` | System Owner/User Discovery | T1033 | Identifies the account associated with the current execution context |
| `HOSTNAME.EXE` | System Information Discovery | T1082 | Identifies the local host/computer name |
| `whoami.exe /groups` | Permission Groups Discovery: Local Groups | T1069.001 | Enumerates group membership associated with the current user context |
| `ipconfig.exe` | System Network Configuration Discovery | T1016 | Retrieves local network configuration information |
| PowerShell parent process | Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell provided the execution context for the discovery sequence |

## Tactic

**Discovery — TA0007**

The sequence collected information about the user context, host identity, group membership, and network configuration.

## Interpretation

ATT&CK mapping describes observable behavior. It does not establish intent or prove compromise.

The same techniques can appear during legitimate administration, troubleshooting, security testing, and adversary activity.

For this case, contextual investigation established that the ATT&CK-mapped behavior resulted from authorized controlled activity.

## Detection Engineering Value

The detection remains useful because a similar sequence without authorized context could warrant investigation for post-compromise discovery.

Analysts should combine ATT&CK classification with process ancestry, account and session context, command-line telemetry, surrounding activity, and authorization information before determining maliciousness.
