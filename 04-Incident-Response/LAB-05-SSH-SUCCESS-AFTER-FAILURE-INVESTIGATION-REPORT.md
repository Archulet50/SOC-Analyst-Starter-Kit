# Incident Response Investigation Report — Lab 05

## SSH Success After Repeated Authentication Failures

**SOC Analyst Starter Kit v1**
**Incident Type:** Suspicious Authentication Activity
**Platform:** Linux / OpenSSH
**Detection Source:** SSH Authentication Telemetry
**Defensive Control:** Fail2Ban
**SIEM:** Splunk
**MITRE ATT&CK:** T1110 — Brute Force
**Investigation Status:** Closed — Controlled Lab Activity

---

## 1. Executive Summary

Lab 05 investigated repeated failed SSH password authentications followed by a successful authentication involving the same normalized source, destination, and account.

The observed sequence consisted of four normalized authentication failures followed by one successful authentication.

The final failure occurred at 09:58:32 and the successful authentication occurred at 10:16:34, producing an interval of 18 minutes 02 seconds.

Correlation testing demonstrated that the activity did not satisfy 5-minute or 15-minute detection windows but did satisfy the 30-minute detection window.

Fail2Ban independently responded to the repeated authentication failures by temporarily banning the test source for approximately 10 minutes.

The activity was generated as part of an authorized controlled security lab. No evidence from the Lab 05 dataset establishes unauthorized access or malicious compromise.

---

## 2. Alert Context

The behavioral condition under investigation was:

Repeated SSH authentication failures followed by a successful authentication involving the same source IP, destination IP, and account.

Normalized entities:

| Field | Value |
|---|---|
| Source IP | 192.168.1.226 |
| Destination IP | 192.168.1.149 |
| Destination Port | 22 |
| Account | analyst |
| Authentication Method | password |
| Protocol | SSH |

The detection correlation key was:

src_ip + dest_ip + user

The Lab 05 detection threshold required four or more failures followed by a successful authentication within 30 minutes of the final failure.

---

## 3. Investigation Timeline

The following timeline summarizes the principal Lab 05 events.

| Time | Event |
|---|---|
| 09:55:10 | Controlled SSH authentication failure observed |
| 09:57:54 | Additional failed authentication observed |
| 09:58:00 | Repeated failure activity continued |
| 09:58:05 | Repeated failure activity continued |
| 09:58:32 | Final normalized failure observed |
| 09:58:32 | Fail2Ban banned source 192.168.1.226 |
| 10:08:32 | Fail2Ban removed temporary ban |
| 10:16:34 | Successful SSH authentication observed |

The interval between the final normalized failure and subsequent successful authentication was 18 minutes 02 seconds.

---

## 4. Evidence Reviewed

The investigation reviewed the following evidence artifacts:

- Test-A-PreAttack-Baseline.txt
- Test-B-Failed-Authentication.txt
- Test-C-Brute-Force-Threshold.txt
- Test-C-Fail2Ban-Response.txt
- Test-D-Success-After-Failure.txt
- Test-D-Splunk-Telemetry.csv
- Test-D-Correlation-Analysis.txt
- Test-D-Success-After-Failure.spl

The evidence included raw OpenSSH authentication telemetry, Fail2Ban response logs, normalized authentication events, temporal correlation analysis, and Splunk detection logic.

Evidence integrity was supported by the SHA256SUMS.txt manifest.

All eight primary evidence artifacts successfully passed SHA-256 verification at the time the manifest was generated.

---

## 5. Analyst Analysis

The investigation identified repeated failed SSH password authentications originating from the same controlled source.

The repeated failures were sufficient to trigger the configured Fail2Ban SSH jail, resulting in a temporary source ban.

The host-level defensive response demonstrates that the authentication failures were independently recognized by an active defensive control.

A subsequent successful SSH password authentication was observed after the temporary Fail2Ban ban had expired.

Normalized telemetry correlated the authentication events using the same:

- source IP;
- destination IP; and
- account.

Four normalized failures preceded one normalized successful authentication.

Temporal analysis determined that the successful authentication occurred 18 minutes 02 seconds after the final normalized failure.

The sequence therefore did not satisfy the tested 5-minute or 15-minute correlation windows.

It did satisfy the tested 30-minute correlation window.

This behavior warrants analyst review because repeated authentication failures followed by success may be consistent with several possibilities, including legitimate user error, password recovery, administrative activity, automated authentication behavior, or credential compromise.

The detection alone does not determine which explanation is correct.

Additional context is required before assigning malicious intent.

---

## 6. Investigation Findings

The investigation produced the following findings:

1. Repeated SSH password authentication failures were observed from source 192.168.1.226.

2. The authentication activity targeted the controlled SSH service associated with destination 192.168.1.149.

3. The normalized Lab 05 dataset contained four failure events associated with the analyst account.

4. Fail2Ban independently detected qualifying authentication failures and temporarily banned source 192.168.1.226.

5. The Fail2Ban ban began at approximately 09:58:32 and ended at approximately 10:08:32.

6. A successful SSH password authentication was subsequently observed at 10:16:34.

7. The interval between the final normalized failure and the successful authentication was 18 minutes 02 seconds.

8. The sequence did not satisfy the tested 5-minute or 15-minute correlation windows.

9. The sequence satisfied the tested 30-minute correlation window.

10. The Lab 05 evidence was generated during authorized controlled testing.

No evidence reviewed during this lab established unauthorized persistence, privilege escalation, lateral movement, data exfiltration, or other post-authentication malicious activity.

---

## 7. Incident Disposition

The observed behavior satisfied the Lab 05 SSH success-after-failure detection condition.

Detection result:

DETECTED

Investigation disposition:

AUTHORIZED CONTROLLED LAB ACTIVITY

The alert behavior is considered a true positive for the behavioral detection because the expected success-after-failure sequence occurred and was correctly identified using the validated 30-minute correlation window.

The activity is not classified as a confirmed security compromise because the authentication sequence was intentionally generated as part of the controlled Lab 05 exercise.

This distinction is important:

- detection accuracy describes whether the rule identified the behavior it was designed to identify;
- incident classification describes the security meaning of that behavior after investigation.

A true-positive detection does not automatically represent a true-positive security incident.

---

## 8. Recommended Analyst Actions

If equivalent activity were observed in a production environment, the analyst should:

1. Validate the source IP and determine whether it is expected for the affected account.

2. Confirm the destination system and determine its business function and criticality.

3. Review the account for recent password changes, resets, lockouts, or administrative activity.

4. Determine whether the successful authentication originated from the same source responsible for the failures.

5. Review authentication telemetry immediately before and after the successful login.

6. Examine the resulting SSH session for suspicious commands or administrative activity.

7. Review endpoint, process, network, and privilege-escalation telemetry when available.

8. Determine whether the source has generated similar authentication activity against other systems or accounts.

9. Review defensive-control activity, including bans, blocks, lockouts, or other automated responses.

10. Escalate the investigation if additional indicators suggest credential compromise or unauthorized access.

Potential containment actions should be based on corroborating evidence and organizational procedure rather than the success-after-failure detection alone.

---

## 9. Lessons Learned

Lab 05 demonstrates that authentication detections become more useful when individual events are evaluated as part of a behavioral sequence.

The exercise demonstrated several SOC and detection-engineering principles:

- isolated authentication failures provide limited context;
- correlation across source, destination, account, and time improves behavioral visibility;
- temporal thresholds directly affect detection coverage;
- defensive controls such as Fail2Ban can alter subsequent attacker or tester behavior;
- successful authentication after repeated failures warrants investigation but does not independently establish compromise;
- normalized telemetry simplifies SIEM correlation;
- controlled testing is necessary to validate both positive and negative detection outcomes; and
- evidence integrity improves reproducibility and supports defensible investigation documentation.

The 18-minute, 02-second interval was particularly important because it demonstrated that the same event sequence produced different results under different correlation windows.

This provides a concrete example of detection tuning rather than relying on an arbitrary threshold.

---

## 10. Final Assessment

Lab 05 successfully reproduced and investigated an SSH success-after-failure behavioral sequence.

The controlled test demonstrated:

- repeated failed SSH password authentications;
- an automated Fail2Ban defensive response;
- a subsequent successful authentication;
- correlation across the same source, destination, and account;
- validation against multiple temporal windows;
- a positive detection using the 30-minute window; and
- preservation and hashing of supporting evidence.

Final detection result:

DETECTED

Final incident classification:

AUTHORIZED CONTROLLED LAB ACTIVITY

**Investigation Status: CLOSED — VALIDATED**
