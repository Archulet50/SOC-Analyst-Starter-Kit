# Authentication Alert Triage Checklist

## SOC Analyst Starter Kit v1

Use this checklist when investigating repeated authentication failures.

---

## Alert Validation

- [ ] Confirm the detection timestamp
- [ ] Confirm the affected host
- [ ] Identify the affected user
- [ ] Determine the failure count
- [ ] Review detection severity

## Authentication Context

- [ ] Identify authentication mechanism
- [ ] Determine whether activity is local or remote
- [ ] Identify source IP or remote host when available
- [ ] Determine whether privileged access is involved
- [ ] Review the event timeline

## Investigation

- [ ] Look for repeated failures
- [ ] Look for multiple targeted accounts
- [ ] Look for successful authentication after failures
- [ ] Determine whether the pattern appears automated
- [ ] Compare activity with known administrative actions
- [ ] Determine whether behavior is expected

## Analyst Decision

Choose one:

- [ ] Benign / Authorized Activity
- [ ] False Positive
- [ ] Suspicious — Continue Investigation
- [ ] True Positive — Security Incident
- [ ] Escalate to Tier 2 / Incident Response

## Documentation

- [ ] Record supporting evidence
- [ ] Document investigation steps
- [ ] Record final disposition
- [ ] Explain disposition rationale
- [ ] Sanitize portfolio evidence
- [ ] Capture screenshots when appropriate

---

## Analyst Principle

```text
Alert
  ↓
Validate
  ↓
Investigate
  ↓
Add Context
  ↓
Make Decision
  ↓
Document

```
