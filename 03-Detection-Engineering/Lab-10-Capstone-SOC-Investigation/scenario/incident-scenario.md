# Lab 10 — Capstone SOC Investigation Scenario

## Scenario

A behavioral detection identifies multiple Windows discovery processes
originating from a PowerShell parent process within a bounded time window.

Observed activity may include:

- Identity discovery
- Group and privilege discovery
- Host discovery
- Network configuration discovery

The activity must be investigated as an unknown security event.

The analyst must not assume that the activity is malicious or benign before
reviewing the available evidence.

---

## Initial Alert Context

The detection indicates that multiple discovery behaviors were observed from
a common PowerShell parent process.

Initial severity:

**Medium — Investigation Required**

The alert establishes that security-relevant behavior occurred. It does not
establish malicious intent.

---

## Investigation Objectives

The analyst must determine:

1. What processes executed?
2. Which account executed the activity?
3. What process created the discovery processes?
4. Did the processes share a common parent?
5. How tightly were the events grouped in time?
6. What PowerShell telemetry corroborates the process activity?
7. Is privilege or logon telemetry available and valid for correlation?
8. Are there unsupported correlations that must be rejected?
9. Which MITRE ATT&CK techniques describe the observed behavior?
10. Does the evidence support escalation to an incident?
11. What containment or response actions are appropriate?
12. What is the final analyst disposition?

---

## Evidence Requirements

Conclusions must be based on observable telemetry.

Primary evidence sources:

- Windows Security Event ID 4688 — Process Creation
- PowerShell Operational Event ID 4104 — Script Block Logging

Supporting evidence may include:

- Windows Security Event ID 4624 — Successful Logon
- Windows Security Event ID 4672 — Special Privileges Assigned to New Logon
- Account context
- Process IDs
- Parent/creator process IDs
- Command-line data
- Event timestamps

Supporting telemetry must only be incorporated when identity, session,
process, time, or other corroborating attributes establish a defensible
relationship.

**Temporal proximity alone is not sufficient evidence of correlation.**

---

## Analyst Standard

The investigation must distinguish among:

- Observed fact
- Supported inference
- Investigative hypothesis
- Unsupported assumption

An event must not be attributed to the investigated activity solely because
it occurred near the same time.

---

## Expected Deliverables

The completed capstone will contain:

- Detection artifact
- Initial alert
- Analyst triage record
- Investigation notes
- Correlated event timeline
- Preserved evidence
- MITRE ATT&CK mapping
- Incident determination
- Response recommendations
- Final SOC incident report

---

## Success Criteria

Lab 10 is complete when an analyst can begin with the alert, reproduce the
investigation from the preserved evidence, understand why each correlation
was accepted or rejected, and reach the documented disposition without
requiring undocumented assumptions.
