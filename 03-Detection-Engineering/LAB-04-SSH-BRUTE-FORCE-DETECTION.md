# Detection Engineering — Lab 04

## SSH Brute-Force Detection

**SOC Analyst Starter Kit v1**
**Platform:** Linux / OpenSSH
**Primary Telemetry:** `/var/log/auth.log`
**Detection Focus:** Repeated Failed SSH Authentication
**MITRE ATT&CK:** T1110 — Brute Force

---

# 1. Detection Objective

Identify repeated failed SSH password authentication attempts originating from
the same source IP within a short period of time.

A single authentication failure does not establish malicious activity.

The detection should identify repeated authentication failures that exceed a
defined threshold and therefore warrant SOC investigation.

---

# 2. Data Sources

Primary telemetry:

`/var/log/auth.log`

Observed OpenSSH events include:

- Accepted password
- Failed password
- PAM authentication failure
- Pre-authentication connection close/reset
- Compressed repeated messages

Normalized detection dataset:

`02-Splunk-Labs/evidence/LAB-04/Test-D-Splunk-Telemetry.csv`

---

# 3. Lab Test Model

## Test A

Pre-attack baseline.

Expected result:

0 Lab 04 authentication failures.

## Test B

Single failed SSH authentication.

Expected result:

1 failed authentication.

Alert:

NO

## Test C

Controlled repeated failures below threshold.

Ground truth:

4 failed authentication attempts.

Alert:

NO

## Test D

Remote repeated authentication failures.

Source:

192.168.1.226

Destination:

192.168.1.149

Service:

SSH / TCP 22

Ground truth:

5 failed password authentication attempts.

Alert:

YES

---

# 4. Detection Threshold

Initial Lab 04 threshold:

- Same source IP
- Same destination
- SSH authentication
- Password failure
- 5 or more failed attempts
- Within 5 minutes

Detection result:

Possible SSH brute-force activity.

---

# 5. Telemetry Counting Consideration

Linux logging may compress repeated identical events.

Observed example:

`message repeated 2 times: [ Failed password ... ]`

Therefore:

Physical log record count may not equal actual authentication attempt count.

Test C demonstrated:

- Physical records containing `Failed password`: 3
- Actual failed password attempts represented: 4

Detection engineering must account for event compression when raw syslog data
is used directly.

The normalized Lab 04 CSV represents each authentication attempt as one event
for deterministic detection testing.

---

# 6. Normalized Fields

The Splunk-ready dataset uses:

- timestamp
- host
- src_ip
- dest_ip
- dest_port
- user
- action
- auth_method
- event_type

Example:

```text
src_ip=192.168.1.226
dest_ip=192.168.1.149
dest_port=22
user=analyst
action=failure
auth_method=password
event_type=ssh_authentication
```

---

# 7. Detection Logic

Conceptual logic:

IF

one source IP

generates

5 or more failed SSH password authentications

against

one destination

within

5 minutes

THEN

generate an SSH brute-force detection.

---

# 8. Splunk SPL

Conceptual SPL:

```spl
index=main sourcetype=lab04_ssh_bruteforce
action=failure dest_port=22
| bin _time span=5m
| stats count as failed_attempts
        values(user) as targeted_users
        values(dest_ip) as destinations
  by _time src_ip
| where failed_attempts >= 5
```

---

# 9. Expected Detection Result

Source:

192.168.1.226

Destination:

192.168.1.149

Target account:

analyst

Failed attempts:

5

Detection:

SSH BRUTE-FORCE THRESHOLD MET

Initial severity:

MEDIUM

---

# 10. Severity Model

## Informational

Normal successful SSH access.

## Low

One or two failed authentication attempts.

## Medium

Five or more failed SSH authentication attempts from one source within five
minutes.

## High

Repeated authentication failures combined with additional suspicious context,
such as:

- Multiple targeted accounts
- Multiple destination systems
- Successful authentication after repeated failures
- Privilege escalation
- Malware activity
- Reconnaissance immediately before authentication attacks
- Known malicious source intelligence

---

# 11. False-Positive Considerations

Legitimate causes may include:

- User mistyping a password
- Expired credentials
- Misconfigured automation
- Administrative troubleshooting
- Stored credentials that are no longer valid
- Security testing

Analysts should review source ownership, timing, targeted users, successful
logins, and follow-on activity before escalation.

---

# 12. MITRE ATT&CK Mapping

**T1110 — Brute Force**

The observed behavior represents repeated password authentication failures.

ATT&CK mapping identifies the behavior pattern.

It does not independently establish malicious intent.

---

# 13. Investigation Questions

1. What source IP generated the failures?
2. Which destination system was targeted?
3. Which account or accounts were targeted?
4. How many authentication attempts occurred?
5. Over what time window?
6. Did a successful login follow the failures?
7. Did the source perform reconnaissance beforehand?
8. Did the source target additional systems?
9. Was the activity authorized?
10. Did privilege escalation or persistence follow?
11. Is escalation required?

---

# 14. Lab 04 Detection Result

Test B:

1 failure

Result:

NO ALERT

Test C:

4 failures

Result:

BELOW THRESHOLD

Test D:

5 failures

Result:

ALERT CONDITION MET

Source:

192.168.1.226

Destination:

192.168.1.149

Final lab disposition:

BENIGN / AUTHORIZED TRAINING ACTIVITY

---

# 15. Detection Improvement Opportunities

Future versions may incorporate:

- Raw syslog repeat-message expansion
- Multiple usernames
- Distributed brute force
- Password spraying
- Successful login after failures
- GeoIP or reputation enrichment
- Asset criticality
- Risk-based alerting
- Correlation with network reconnaissance
- Correlation with privilege escalation

---

# 16. Detection Maturity

Level 1 — Fixed failure threshold

Level 2 — Time-window correlation

Level 3 — User and destination context

Level 4 — Reconnaissance correlation

Level 5 — Risk-based authentication analytics

---

# 17. Key Detection Principle

Authentication failure count is meaningful only when combined with:

**source + destination + user + time window + context**

---

**SOC Analyst Starter Kit v1**

**Detection Engineering — Lab 04**
