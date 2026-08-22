# Incident Handoff Decision — LAB09-ALERT-001

## Case Summary

**Alert:** Windows Multi-Stage Discovery  
**Detection Score:** 8  
**Original Detection Disposition:** INVESTIGATE  
**Initial Severity:** MEDIUM  
**Detection Validity:** TRUE POSITIVE  
**Activity Classification:** AUTHORIZED CONTROLLED ACTIVITY  
**Final Severity:** INFORMATIONAL  
**IR Escalation Decision:** NOT REQUIRED  
**Case Status:** CLOSED

## Handoff Objective

Determine whether the evidence associated with LAB09-ALERT-001 meets the
threshold for escalation from SOC alert investigation to formal incident
response.

An `INVESTIGATE` detection disposition does not automatically establish
a security incident. Escalation requires analysis of scope, authorization,
impact, and supporting evidence.

## Evidence Considered

The handoff decision considered:

- Windows Security Event ID 4688 process telemetry
- PowerShell Operational Event ID 4104 telemetry
- Common PowerShell Creator PID `0x46ec`
- Identified user context
- Four correlated discovery behaviors
- Analyst review of nearby Event ID 4672 activity
- Search for supporting Event ID 4624 context
- Authorization context from the controlled Lab 08 exercise

## Confirmed Activity

The evidence confirms the following process sequence:

```text
powershell.exe — PID 0x46ec
    ├── whoami.exe
    ├── HOSTNAME.EXE
    ├── whoami.exe /groups
    └── ipconfig.exe

```
## Incident Threshold Decision Matrix

| Decision Factor | Finding | Supports IR Escalation |
|---|---|---|
| Detection validity | True positive | No — establishes detection accuracy |
| Authorization | Authorized controlled activity | No |
| User context | Identified | No |
| Process correlation | Four discovery processes share PowerShell PID `0x46ec` | Investigation warranted |
| Privileged-session evidence | Not established | No |
| Credential access | Not established | No |
| Persistence | Not established | No |
| Lateral movement | Not established | No |
| Command-and-control | Not established | No |
| Collection / exfiltration | Not established | No |
| Additional endpoints | Not established | No |
| Confirmed impact | None established | No |

## Privilege Evidence Decision

Nearby Event ID 4672 records were reviewed during investigation.

Those records belonged to:

- Account: `SYSTEM`
- Domain: `NT AUTHORITY`
- Logon ID: `0x3E7`

The investigation did not identify corresponding Event ID 4624 evidence
linking the controlled user to those privilege events.

The 4672 activity was therefore excluded from the incident assessment.

This prevents unrelated privileged operating-system activity from
artificially increasing the apparent severity of the case.

## Authorization Determination

The observed discovery sequence corresponds to the activity intentionally
generated during the authorized Lab 08 validation exercise.

Authorization was established during investigation rather than assumed
when the alert fired.

This distinction is important:

**The detection was correct even though the activity was authorized.**

The alert is therefore classified as a true positive rather than a false
positive.

## SOC-to-IR Decision

**Formal incident response handoff: NOT REQUIRED**

The investigation established a valid detection of authorized controlled
activity without evidence of additional malicious behavior, compromise,
or impact requiring formal incident response.

The case can be closed at the SOC investigation stage.

## Recommended Actions

1. Close `LAB09-ALERT-001`.
2. Record the disposition as `TRUE POSITIVE — AUTHORIZED CONTROLLED ACTIVITY`.
3. Record final severity as `INFORMATIONAL`.
4. Preserve the investigation evidence and timeline.
5. Keep the Lab 08 analytic enabled.
6. Do not suppress the detection solely because this instance was authorized.
7. Use authorization and environmental context during future alert triage.

## Final Handoff Record

**Alert ID:** LAB09-ALERT-001  
**Detection:** Windows Multi-Stage Behavioral Correlation  
**Detection Score:** 8  
**Detection Result:** INVESTIGATE  
**Analyst Disposition:** TRUE POSITIVE — AUTHORIZED CONTROLLED ACTIVITY  
**Final Severity:** INFORMATIONAL  
**Incident Declared:** NO  
**IR Handoff:** NOT REQUIRED  
**Case Status:** CLOSED

### Final Analyst Statement

The behavioral detection operated as designed and identified a correlated
Windows discovery sequence requiring investigation.

Analyst review confirmed the activity was generated during an authorized
controlled exercise and found no reviewed evidence establishing a broader
security incident.

The alert is closed as a true-positive detection of authorized activity.
