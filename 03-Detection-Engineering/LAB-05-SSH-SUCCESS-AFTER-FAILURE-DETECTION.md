# Detection Engineering — Lab 05

## SSH Success-After-Failure Correlation

**SOC Analyst Starter Kit v1**
**Platform:** Linux / OpenSSH
**Primary Telemetry:** Linux authentication events
**SIEM:** Splunk
**Detection Focus:** Successful SSH authentication following repeated failures
**MITRE ATT&CK:** T1110 — Brute Force
**Detection Type:** Behavioral Correlation

---

# 1. Detection Objective

The objective of this detection is to identify a successful SSH authentication
that occurs after repeated failed authentication attempts involving the same:

- Source IP address
- Destination IP address
- Target account

Repeated authentication failures may represent password guessing, credential
testing, user error, administrative activity, or authorized security testing.

A subsequent successful authentication materially changes the investigative
context.

The detection therefore evaluates a behavioral sequence rather than an
individual authentication event:

```text
Repeated Authentication Failures
              ↓
      Same Source IP
              ↓
    Same Destination IP
              ↓
       Same Account
              ↓
 Successful Authentication
              ↓
     Correlation Window
              ↓
Potential Credential Compromise
```

The detection does not establish malicious intent by itself.

It identifies behavior requiring analyst investigation.

---

# 2. Detection Hypothesis

The detection hypothesis is:

> If repeated failed SSH password authentications from the same source against
> the same destination and account are followed by a successful authentication
> within a meaningful time window, the activity warrants increased
> investigative priority.

Lab 05 evaluates this hypothesis using controlled authentication telemetry.

---

# 3. Data Sources

Primary telemetry:

```text
Linux OpenSSH authentication logs
```

Original authentication evidence was obtained from:

```text
/var/log/auth.log
```

Relevant OpenSSH messages include:

```text
Failed password
Accepted password
authentication failure
session opened
```

For SIEM analysis, selected authentication events were normalized into:

```text
Test-D-Splunk-Telemetry.csv
```

Normalized fields:

```text
timestamp
host
src_ip
dest_ip
dest_port
user
action
auth_method
event_type
```

The normalized event model allows failure and success events to be correlated
using common fields.

---

# 4. Correlation Key

Lab 05 correlates authentication activity using:

```text
src_ip + dest_ip + user
```

For the controlled test:

```text
src_ip  = 192.168.1.226
dest_ip = 192.168.1.149
user    = analyst
```

This prevents unrelated authentication events from different systems or
accounts from being treated as part of the same sequence.

In a production environment, additional fields may be incorporated depending
on telemetry quality and authentication architecture.

---

# 5. Lab 05 Test Model

Lab 05 uses four test stages.

## Test A — Pre-Attack Baseline

Purpose:

Establish the state of the monitored SSH service and review existing
authentication telemetry before generating new test activity.

Expected result:

```text
No Lab 05 success-after-failure condition established
```

## Test B — Failed Authentication

Purpose:

Generate a controlled failed SSH password authentication.

Expected result:

```text
Authentication failure observed
Correlation threshold not satisfied
```

## Test C — Repeated Authentication Failures

Purpose:

Generate repeated failed authentication activity sufficient to model
brute-force-like behavior.

Expected result:

```text
Repeated authentication failures observed
Defensive response may occur
No successful authentication yet correlated
```

During Lab 05, Fail2Ban responded to repeated authentication failures,
demonstrating an active host-level defensive control.

## Test D — Success After Failure

Purpose:

Generate a successful authentication following the repeated failure sequence.

Expected result:

```text
Repeated failures
        ↓
Successful authentication
        ↓
Evaluate temporal relationship
        ↓
Apply correlation logic
```
---

# 6. Observed Test D Telemetry

Normalized Test D telemetry contained:

```text
4 failure events
1 success event
```

All five normalized authentication events shared:

```text
Source:      192.168.1.226
Destination: 192.168.1.149
Port:        22
Account:     analyst
Method:      password
```

The final failed authentication occurred at:

```text
2026-08-12T09:58:32-06:00
```

The successful authentication occurred at:

```text
2026-08-12T10:16:34-06:00
```

Observed gap:

```text
18 minutes 02 seconds
```
---

# 7. Correlation Window Analysis

Lab 05 explicitly evaluated multiple correlation windows.

Results:

```text
5-minute window  → NOT DETECTED
15-minute window → NOT DETECTED
30-minute window → DETECTED
```

The successful authentication occurred approximately 18 minutes after the
final observed failure.

Therefore:

```text
5 minutes  < 18:02 → no correlation
15 minutes < 18:02 → no correlation
30 minutes > 18:02 → correlation
```

This demonstrates an important detection-engineering principle:

**Correlation-window selection directly affects detection coverage.**

A window that is too short may miss meaningful relationships between events.

A window that is too long may associate unrelated authentication activity and
increase false positives.

The appropriate production threshold should therefore be based on environment,
authentication behavior, threat model, and historical telemetry rather than
selected arbitrarily.

---
# 8. Detection Threshold

For the Lab 05 dataset, the behavioral condition is:

```text
failure_count >= 4
AND
successful authentication exists
AND
success occurs after the final failure
AND
success occurs within 30 minutes of the final failure
```

The correlation key is:

```text
src_ip + dest_ip + user
```

Conceptually:

```text
4+ failures
     +
same source
     +
same destination
     +
same account
     +
subsequent success
     +
≤ 30 minutes
     =
SUCCESS-AFTER-FAILURE DETECTION
```

The threshold is designed for the controlled Lab 05 dataset and should not be
interpreted as a universal production threshold.

---

# 9. Splunk Detection Logic

The Lab 05 correlation logic is represented by the following SPL:

```spl
index=main sourcetype="lab05:ssh:normalized"
| eval failure_time=if(action="failure",_time,null())
| eval success_time=if(action="success",_time,null())
| eventstats
    count(eval(action="failure")) AS failure_count
    max(failure_time) AS last_failure
    min(success_time) AS first_success
    BY src_ip dest_ip user
| where failure_count >= 4
    AND isnotnull(first_success)
    AND first_success > last_failure
    AND first_success-last_failure <= 1800
| eval correlation_seconds=first_success-last_failure
| eval correlation_minutes=round(correlation_seconds/60,2)
| convert ctime(last_failure) ctime(first_success)
| table
    src_ip
    dest_ip
    user
    failure_count
    last_failure
    first_success
    correlation_seconds
    correlation_minutes
```

The query performs four primary operations.

## 9.1 Event Classification

Authentication events are classified by action:

```text
failure → failure_time
success → success_time
```

This allows failure and success timestamps to be evaluated independently while
retaining the original normalized events.

## 9.2 Correlation Grouping

The `eventstats` operation groups authentication activity by:

```text
src_ip
dest_ip
user
```

For each correlation group, the query calculates:

```text
failure_count
last_failure
first_success
```

This provides the values required to evaluate the Lab 05 detection hypothesis.

## 9.3 Detection Conditions

The `where` clause requires:

```text
failure_count >= 4
first_success exists
first_success > last_failure
first_success - last_failure <= 1800 seconds
```

The value `1800` represents the 30-minute correlation window established during
Lab 05 testing.

## 9.4 Analyst Output

For matching activity, the query returns:

```text
src_ip
dest_ip
user
failure_count
last_failure
first_success
correlation_seconds
correlation_minutes
```

These fields provide an analyst with the principal entities and temporal
relationship responsible for the detection.

For the controlled Lab 05 dataset, the expected correlation interval is:

```text
18 minutes 02 seconds
```

Therefore, the event sequence satisfies the 30-minute correlation condition.

The SPL is intentionally scoped to the controlled Lab 05 dataset. Production
deployment would require additional validation, tuning, and consideration of
multiple authentication sequences within the same correlation group.

---
# 10. Detection Validation

The Lab 05 detection hypothesis was evaluated through a controlled sequence of
SSH authentication tests.

Validation was performed against both the authentication telemetry and the
host-level defensive response.

## 10.1 Test A — Baseline

The baseline established the state of the SSH service and reviewed existing
authentication activity before the controlled Lab 05 sequence.

Result:

```text
Baseline established
SSH telemetry available
No Lab 05 success-after-failure condition asserted
```

Evidence:

```text
Test-A-PreAttack-Baseline.txt
```

## 10.2 Test B — Isolated Authentication Failure

A controlled failed SSH authentication was generated from the test source.

Observed behavior:

```text
Source: 192.168.1.226
Account: analyst
Result: authentication failure
```

A single failed authentication did not satisfy the Lab 05 detection threshold.

Result:

```text
NO DETECTION
```

Evidence:

```text
Test-B-Failed-Authentication.txt
```

## 10.3 Test C — Repeated Authentication Failures

Repeated failed SSH authentication attempts were generated from the same
source against the monitored system.

OpenSSH telemetry recorded the repeated failure sequence.

Fail2Ban independently identified qualifying authentication failures and
responded by banning the source:

```text
Source:   192.168.1.226
Ban:      09:58:32
Unban:    10:08:32
Duration: approximately 10 minutes
```

This demonstrated that an active host-level defensive control could influence
both attack simulation and subsequent authentication testing.

At this stage, repeated failures existed, but the Lab 05 success-after-failure
condition was not yet complete because no subsequent successful authentication
had been correlated.

Result:

```text
FAILURE THRESHOLD OBSERVED
HOST DEFENSIVE RESPONSE OBSERVED
SUCCESS-AFTER-FAILURE CONDITION NOT YET COMPLETE
```

Evidence:

```text
Test-C-Brute-Force-Threshold.txt
Test-C-Fail2Ban-Response.txt
```

## 10.4 Test D — Successful Authentication After Failures

Following the repeated failure sequence and defensive response, a successful
SSH password authentication was observed.

Normalized telemetry contained:

```text
Failures: 4
Successes: 1
Source: 192.168.1.226
Destination: 192.168.1.149
Account: analyst
```

Temporal analysis produced:

```text
Last failure: 2026-08-12T09:58:32-06:00
Success:      2026-08-12T10:16:34-06:00
Gap:          18 minutes 02 seconds
```

The sequence therefore satisfied the Lab 05 behavioral hypothesis when a
30-minute correlation window was applied.

Evidence:

```text
Test-D-Success-After-Failure.txt
Test-D-Splunk-Telemetry.csv
Test-D-Correlation-Analysis.txt
```

## 10.5 Correlation Window Validation

The same event sequence was evaluated against three correlation windows:

```text
 5-minute window → NOT DETECTED
15-minute window → NOT DETECTED
30-minute window → DETECTED
```

The observed 18-minute, 02-second interval demonstrates that detection behavior
changes as the correlation window changes.

This validates both a positive and negative aspect of the detection logic:

```text
5 minutes  → negative test
15 minutes → negative test
30 minutes → positive test
```

The result demonstrates why temporal thresholds should be validated rather than
selected without testing.

## 10.6 Validation Result

The controlled Lab 05 dataset supports the detection hypothesis:

```text
Repeated SSH authentication failures
                +
same source, destination, and account
                +
subsequent successful authentication
                +
30-minute correlation window
                =
DETECTED
```

The validation does not establish that every matching production event is
malicious. It establishes that the detection logic successfully identifies the
behavioral sequence represented by the controlled Lab 05 dataset.

## 10.7 Evidence Integrity

The finalized Lab 05 evidence artifacts were hashed using SHA-256.

The manifest is stored as:

```text
02-Splunk-Labs/evidence/LAB-05/SHA256SUMS.txt
```

Integrity verification was performed with:

```text
sha256sum -c SHA256SUMS.txt
```

All eight evidence artifacts returned:

```text
OK
```

The manifest provides a reproducible method for detecting subsequent changes to
the finalized Lab 05 evidence artifacts.

---
