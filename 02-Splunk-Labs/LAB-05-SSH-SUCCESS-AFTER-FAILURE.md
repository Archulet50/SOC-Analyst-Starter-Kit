# Lab 05 — SSH Success After Repeated Authentication Failures

## SOC Analyst Starter Kit v1

**Platform:** Linux / OpenSSH
**SIEM:** Splunk
**Defensive Control:** Fail2Ban
**Detection Focus:** SSH success-after-failure correlation
**MITRE ATT&CK:** T1110 — Brute Force

---

## 1. Objective

The objective of Lab 05 is to detect and investigate a successful SSH authentication that occurs after repeated failed authentication attempts.

Rather than treating individual login failures as isolated events, the lab correlates authentication activity across a common source, destination, and account.

The behavioral sequence evaluated is:

- repeated SSH password failures;
- same source IP;
- same destination IP;
- same account;
- subsequent successful authentication; and
- a defined temporal correlation window.

A successful authentication following repeated failures may indicate valid user behavior, password recovery, administrative activity, or potential credential compromise.

The detection therefore identifies activity requiring analyst investigation rather than establishing malicious intent by itself.

---

## 2. Lab Environment

The controlled Lab 05 dataset uses the following normalized entities:

| Field | Value |
|---|---|
| Source IP | 192.168.1.226 |
| Destination IP | 192.168.1.149 |
| Destination Port | 22 |
| Account | analyst |
| Authentication Method | password |
| Protocol | SSH |

Authentication telemetry originated from Linux OpenSSH logs and was normalized for correlation analysis.

---

## 3. Test Sequence

### Test A — Baseline

Established the state of the monitored SSH service and reviewed available authentication telemetry before the controlled test sequence.

Result: Baseline established. No Lab 05 success-after-failure condition was asserted.

### Test B — Failed Authentication

Generated a controlled failed SSH password authentication.

Result: Authentication failure observed. Correlation threshold was not satisfied.

### Test C — Repeated Authentication Failures

Generated repeated failed SSH authentication activity from the same source.

Fail2Ban independently detected the repeated failures and temporarily banned the source IP.

Observed defensive response:

- Ban: 09:58:32
- Unban: 10:08:32
- Duration: approximately 10 minutes

### Test D — Successful Authentication After Failures

A successful SSH authentication was subsequently observed using the same source, destination, and account represented in the normalized dataset.

Normalized Test D telemetry contained:

- Failures: 4
- Successes: 1

---

## 4. Correlation Analysis

The final normalized failed authentication occurred at:

2026-08-12T09:58:32-06:00

The successful authentication occurred at:

2026-08-12T10:16:34-06:00

Observed interval:

18 minutes 02 seconds

Three correlation windows were evaluated:

| Correlation Window | Result |
|---|---|
| 5 minutes | NOT DETECTED |
| 15 minutes | NOT DETECTED |
| 30 minutes | DETECTED |

The test demonstrates that correlation-window selection directly affects detection coverage.

---

## 5. Detection Condition

The Lab 05 detection condition requires:

- failure_count greater than or equal to 4;
- a successful authentication exists;
- the success occurs after the final failure; and
- the success occurs within 30 minutes of the final failure.

The correlation key is:

src_ip + dest_ip + user

The threshold is specific to the controlled Lab 05 dataset and is not intended to represent a universal production threshold.

---

## 6. Splunk Detection

The detection logic is preserved in:

02-Splunk-Labs/evidence/LAB-05/Test-D-Success-After-Failure.spl

The SPL correlates normalized authentication events by source IP, destination IP, and user.

For each correlation group, it calculates:

- failure_count;
- last_failure;
- first_success;
- correlation_seconds; and
- correlation_minutes.

The controlled dataset contains four normalized failures followed by one successful authentication.

The observed interval is 18 minutes 02 seconds, satisfying the 30-minute correlation condition.

---

## 7. Defensive Control Observation

Fail2Ban detected repeated SSH authentication failures from the controlled test source and applied a temporary ban.

This created a defensive-control artifact independent of the Splunk correlation analysis.

The lab therefore demonstrates interaction between:

- OpenSSH authentication telemetry;
- host-based defensive controls;
- normalized SIEM telemetry;
- behavioral correlation; and
- analyst investigation.

The Fail2Ban response also demonstrates an important testing consideration: defensive controls can influence the timing and behavior of controlled security testing.

---

## 8. Evidence

Lab evidence is stored in:

02-Splunk-Labs/evidence/LAB-05/

Artifacts include:

- Test-A-PreAttack-Baseline.txt
- Test-B-Failed-Authentication.txt
- Test-C-Brute-Force-Threshold.txt
- Test-C-Fail2Ban-Response.txt
- Test-D-Correlation-Analysis.txt
- Test-D-Splunk-Telemetry.csv
- Test-D-Success-After-Failure.spl
- Test-D-Success-After-Failure.txt
- SHA256SUMS.txt

The evidence artifacts were sanitized before repository publication.

SHA-256 hashes were generated for the eight primary evidence artifacts and stored in SHA256SUMS.txt.

Integrity verification was performed using the SHA-256 manifest.

All eight primary evidence artifacts successfully passed verification.

---

## 9. Detection Engineering

Detailed detection design, correlation logic, threshold analysis, SPL, and validation are documented in:

03-Detection-Engineering/LAB-05-SSH-SUCCESS-AFTER-FAILURE-DETECTION.md

The detection-engineering artifact documents the behavioral hypothesis, data sources, correlation key, threshold selection, Splunk logic, and controlled validation results.

---

## 10. Incident Response

The analyst investigation and incident-response workflow for the observed behavior is documented in:

04-Incident-Response/LAB-05-SSH-SUCCESS-AFTER-FAILURE-INVESTIGATION-REPORT.md

The investigation report provides a structured location for documenting alert context, evidence review, analysis, findings, and disposition.

---

## 11. Analyst Triage

A reusable SOC triage checklist for SSH success-after-failure alerts is maintained in:

05-SOC-Checklists/SSH-SUCCESS-AFTER-FAILURE-ALERT-TRIAGE.md

The checklist is intended to support consistent analyst review of similar authentication alerts.

---

## 12. Key Takeaways

Lab 05 demonstrates the ability to:

- analyze Linux authentication telemetry;
- identify repeated SSH authentication failures;
- observe host-based defensive response through Fail2Ban;
- normalize authentication events for SIEM analysis;
- correlate failures and successes across common entities;
- evaluate multiple temporal correlation windows;
- develop SPL-based behavioral detection logic;
- distinguish detection from determination of malicious intent;
- preserve and hash supporting evidence; and
- document the workflow as a reproducible SOC investigation.

---

## Validation Result

The controlled Lab 05 sequence produced:

- 4 normalized authentication failures;
- the same source, destination, and account;
- a subsequent successful authentication;
- an interval of 18 minutes 02 seconds; and
- a positive result using the 30-minute correlation window.

Result:

DETECTED

**Lab 05 Status: VALIDATED**
