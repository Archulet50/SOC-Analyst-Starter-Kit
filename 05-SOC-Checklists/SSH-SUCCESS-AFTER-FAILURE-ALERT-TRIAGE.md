# SOC Alert Triage Checklist

## SSH Success After Repeated Authentication Failures

**SOC Analyst Starter Kit v1**
**Alert Type:** Authentication Correlation
**Platform:** Linux / OpenSSH
**Detection Focus:** Successful SSH authentication following repeated failures
**MITRE ATT&CK:** T1110 — Brute Force

---

## 1. Triage Objective

Use this checklist when an alert identifies a successful SSH authentication following repeated failed authentication attempts involving the same source, destination, and account.

The objective is to determine whether the activity represents:

- legitimate user behavior;
- password or authentication issues;
- expected administrative activity;
- automated or scripted authentication;
- security testing;
- suspicious credential use; or
- potential credential compromise.

The detection should initiate investigation rather than automatically establish malicious intent.

---

## 2. Initial Alert Validation

Confirm the alert contains sufficient information for investigation.

- [ ] Identify the source IP.
- [ ] Identify the destination IP or hostname.
- [ ] Identify the destination port.
- [ ] Identify the affected account.
- [ ] Confirm the authentication method.
- [ ] Confirm the number of failed authentications.
- [ ] Confirm a subsequent successful authentication exists.
- [ ] Record the timestamp of the final failure.
- [ ] Record the timestamp of the successful authentication.
- [ ] Calculate the interval between failure and success.
- [ ] Confirm the activity satisfies the configured correlation window.

Minimum correlation entities:

src_ip + dest_ip + user

Do not proceed solely from the alert title. Validate the underlying authentication telemetry.

---

## 3. Authentication Review

Review the authentication sequence surrounding the alert.

- [ ] Examine authentication events preceding the failure sequence.
- [ ] Confirm the failures originated from the reported source.
- [ ] Determine whether failures targeted one or multiple accounts.
- [ ] Determine whether the source contacted one or multiple systems.
- [ ] Confirm the successful login occurred after the failures.
- [ ] Determine whether the successful login originated from the same source.
- [ ] Review authentication activity immediately after the successful login.
- [ ] Look for additional successful or failed authentication attempts.
- [ ] Check for account lockouts or password-reset activity.
- [ ] Determine whether the timing is consistent with expected user behavior.

Document any inconsistencies between the alert and the underlying telemetry.

---

## 4. Source and Account Enrichment

Determine whether the source and account context supports legitimate or suspicious activity.

### Source Review

- [ ] Determine whether the source IP is internal or external.
- [ ] Identify the system associated with the source when possible.
- [ ] Determine whether the source is expected to access the destination.
- [ ] Review previous authentication activity from the source.
- [ ] Search for authentication attempts against additional accounts.
- [ ] Search for authentication attempts against additional systems.
- [ ] Check whether the source has triggered other security detections.
- [ ] Review available reputation or threat-intelligence context when appropriate.

### Account Review

- [ ] Confirm whether the account is active and expected on the destination.
- [ ] Determine whether the account has administrative or privileged access.
- [ ] Review recent password changes or resets.
- [ ] Review recent account lockouts.
- [ ] Identify other systems recently accessed by the account.
- [ ] Determine whether the account normally uses password-based SSH authentication.
- [ ] Compare the activity with established account behavior when historical telemetry is available.

Unexpected source, account, or access patterns should increase investigative priority.

---

## 5. Defensive Control Review

Determine whether host, network, or identity controls responded to the authentication failures.

- [ ] Check for Fail2Ban activity.
- [ ] Check for firewall blocks or connection resets.
- [ ] Check for account lockout events.
- [ ] Check for endpoint security detections.
- [ ] Determine when any defensive action began.
- [ ] Determine when the defensive action ended.
- [ ] Determine whether the successful authentication occurred before or after the defensive action.
- [ ] Record whether the control altered the authentication sequence.

Defensive controls can affect the timing of subsequent activity and should be considered when evaluating the correlation interval.

In Lab 05, Fail2Ban temporarily banned the test source before the later successful authentication.

---

## 6. Post-Authentication Review

A successful authentication after repeated failures should trigger review of activity occurring after login.

- [ ] Identify the SSH session associated with the successful authentication.
- [ ] Determine the session start and end times.
- [ ] Review commands executed during the session when telemetry is available.
- [ ] Check for privilege escalation.
- [ ] Check for creation or modification of user accounts.
- [ ] Check for changes to SSH configuration.
- [ ] Check for modification of authorized_keys files.
- [ ] Check for new services, scheduled tasks, or persistence mechanisms.
- [ ] Review process execution associated with the session.
- [ ] Review outbound network connections following authentication.
- [ ] Check for access to sensitive files or directories.
- [ ] Look for evidence of lateral movement.
- [ ] Look for evidence of staging or data exfiltration.
- [ ] Correlate related endpoint, network, and identity alerts.

Absence of suspicious post-authentication activity may reduce incident severity but does not eliminate the need to establish why the successful authentication followed repeated failures.

---

## 7. Correlation Assessment

Record the temporal relationship between the authentication failures and success.

- [ ] Record the total number of qualifying failures.
- [ ] Record the final failure timestamp.
- [ ] Record the successful authentication timestamp.
- [ ] Calculate the failure-to-success interval.
- [ ] Compare the interval with the configured detection window.
- [ ] Determine whether a shorter correlation window would have missed the sequence.
- [ ] Determine whether the configured window produces excessive unrelated correlations.

For the validated Lab 05 dataset:

| Window | Result |
|---|---|
| 5 minutes | NOT DETECTED |
| 15 minutes | NOT DETECTED |
| 30 minutes | DETECTED |

The observed failure-to-success interval was 18 minutes 02 seconds.

Correlation-window selection should be based on validated telemetry and environmental behavior rather than an arbitrary value.

---

## 8. Escalation Criteria

Escalate the alert when investigation identifies evidence that increases the likelihood of unauthorized credential use or compromise.

Potential escalation indicators include:

- [ ] Source IP is unexpected or unauthorized.
- [ ] Account owner cannot explain the authentication activity.
- [ ] Successful authentication occurs from an unusual system or location.
- [ ] Multiple accounts are targeted by the same source.
- [ ] Multiple systems are targeted by the same source.
- [ ] Privileged or administrative accounts are involved.
- [ ] Successful authentication is followed by privilege escalation.
- [ ] Suspicious commands or processes occur after authentication.
- [ ] Persistence mechanisms are created or modified.
- [ ] Additional security detections correlate with the activity.
- [ ] Lateral movement is observed.
- [ ] Sensitive files or systems are accessed unexpectedly.
- [ ] Data staging or exfiltration indicators are present.
- [ ] Similar authentication activity continues after defensive action.
- [ ] Threat-intelligence context increases concern regarding the source.

Multiple corroborating indicators should increase incident priority.

---

## 9. Containment Considerations

Containment should be based on investigation findings, asset criticality, account privilege, and organizational procedure.

Potential actions include:

- [ ] Temporarily disable or restrict the affected account.
- [ ] Require a password reset.
- [ ] Revoke active sessions when supported.
- [ ] Block the suspicious source IP.
- [ ] Apply temporary firewall restrictions.
- [ ] Isolate the affected endpoint when compromise is suspected.
- [ ] Preserve volatile and authentication evidence before disruptive action when appropriate.
- [ ] Increase monitoring for the affected account.
- [ ] Increase monitoring for the source IP.
- [ ] Search the environment for related authentication activity.

Do not perform disruptive containment solely because the success-after-failure detection fired.

Containment should be proportional to the evidence and follow approved incident-response procedures.

---

## 10. Alert Disposition

Assign a disposition after sufficient investigation.

### True Positive — Security Incident

Use when the detection correctly identified the behavior and investigation supports unauthorized or malicious activity.

### True Positive — Benign or Authorized Activity

Use when the detection correctly identified the behavior but investigation establishes an authorized or non-malicious explanation.

Examples may include:

- controlled security testing;
- authorized administrative activity;
- known automation;
- expected password-recovery behavior; or
- documented user authentication errors.

### False Positive

Use when the detection logic incorrectly associated events or produced an alert that did not represent the behavior the rule was designed to identify.

Potential causes include:

- incorrect field extraction;
- incorrect event normalization;
- unrelated events grouped under the same correlation key;
- timestamp problems; or
- an excessively broad correlation condition.

For Lab 05:

Detection disposition:

TRUE POSITIVE — AUTHORIZED CONTROLLED ACTIVITY

Security incident classification:

NO CONFIRMED COMPROMISE

---

## 11. Investigation Documentation

Before closing or escalating the alert, document:

- [ ] Alert name and identifier.
- [ ] Investigation start time.
- [ ] Analyst name or identifier.
- [ ] Source IP.
- [ ] Destination IP or hostname.
- [ ] Destination port.
- [ ] Affected account.
- [ ] Authentication method.
- [ ] Number of qualifying failures.
- [ ] Final failure timestamp.
- [ ] Successful authentication timestamp.
- [ ] Failure-to-success interval.
- [ ] Correlation window used.
- [ ] Defensive controls observed.
- [ ] Relevant enrichment results.
- [ ] Post-authentication activity reviewed.
- [ ] Supporting evidence locations.
- [ ] Containment actions taken, if any.
- [ ] Escalation actions taken, if any.
- [ ] Final disposition.
- [ ] Rationale for the disposition.

Documentation should allow another analyst to understand how the conclusion was reached without reconstructing the investigation from the beginning.

---

## 12. Closure Checklist

Before closing the alert:

- [ ] Underlying telemetry has been reviewed.
- [ ] Correlation entities have been validated.
- [ ] Failure and success timestamps have been confirmed.
- [ ] The correlation interval has been calculated.
- [ ] Source context has been reviewed.
- [ ] Account context has been reviewed.
- [ ] Defensive-control activity has been reviewed.
- [ ] Post-authentication activity has been reviewed when available.
- [ ] Related alerts or events have been searched.
- [ ] Escalation criteria have been evaluated.
- [ ] Containment requirements have been evaluated.
- [ ] Evidence has been preserved as required.
- [ ] Final disposition has been documented.
- [ ] Investigation rationale has been documented.

The alert may be closed when the analyst has sufficient evidence to support and document the final disposition.

---

## Lab 05 Validation Reference

The controlled Lab 05 dataset demonstrated:

- four normalized SSH authentication failures;
- one subsequent successful authentication;
- the same source, destination, and account;
- an 18-minute, 02-second failure-to-success interval;
- a Fail2Ban defensive response;
- negative results using 5-minute and 15-minute windows; and
- a positive result using the 30-minute correlation window.

Validated Lab 05 result:

DETECTED

Validated Lab 05 disposition:

TRUE POSITIVE — AUTHORIZED CONTROLLED ACTIVITY

**Checklist Status: VALIDATED**
