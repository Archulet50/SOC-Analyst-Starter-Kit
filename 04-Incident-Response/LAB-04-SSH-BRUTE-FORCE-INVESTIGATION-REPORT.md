# SOC Investigation Report — Lab 04

## SSH Brute-Force Investigation

**SOC Analyst Starter Kit v1**
**Classification:** Training Exercise
**Platform:** Linux / OpenSSH
**Primary Telemetry:** `/var/log/auth.log`
**MITRE ATT&CK:** T1110 — Brute Force
**Initial Severity:** Medium
**Final Status:** Closed — Authorized Lab Activity

---

# 1. Executive Summary

A series of failed SSH password authentication attempts was generated against
a Linux system as part of an authorized security lab.

The investigation was designed to distinguish normal authentication failures
from repeated behavior consistent with an SSH brute-force detection condition.

Testing progressed through multiple stages:

- Pre-attack baseline validation
- Single failed SSH authentication
- Repeated authentication failures below the alert threshold
- Remote repeated authentication failures reaching the detection threshold

The final remote test generated five failed SSH password authentication
attempts from source IP `192.168.1.226` against destination IP
`192.168.1.149`.

The activity satisfied the Lab 04 detection threshold of five failed SSH
authentication attempts from the same source within five minutes.

No evidence reviewed during the exercise established unauthorized access,
account compromise, privilege escalation, persistence, or malicious
follow-on activity.

The activity was confirmed as authorized lab testing.

Final disposition:

**BENIGN / AUTHORIZED TRAINING ACTIVITY**

---

# 2. Investigation Scope

The investigation focused on SSH authentication activity associated with the
Lab 04 testing period.

Primary questions:

1. Did repeated failed SSH authentications occur?
2. What system generated the activity?
3. What system received the activity?
4. Which account was targeted?
5. How many failed attempts occurred?
6. Was the alert threshold reached?
7. Did authentication eventually succeed?
8. Was there evidence of compromise or follow-on malicious activity?
9. Was the activity authorized?

---

# 3. Environment

## Target System

Role:

Linux SSH server / monitored endpoint

Sanitized hostname:

`SENTINEL`

Observed destination:

`192.168.1.149`

Service:

OpenSSH

Destination port:

`22/TCP`

SSH service state during validation:

Active and listening on IPv4 and IPv6.

Observed listeners included:

```text
0.0.0.0:22
[::]:22
```

## Remote Source System

Observed source:

`192.168.1.226`

Role:

Authorized remote lab system

Purpose:

Generate controlled SSH authentication failures against the monitored system.

## Target Account

Sanitized username:

`analyst`

Authentication method:

Password

---

# 4. Investigation Trigger

The Lab 04 detection threshold was defined as:

- Same source IP
- Same destination
- SSH password authentication
- Five or more failed authentication attempts
- Within five minutes

The remote test reached this threshold.

Observed detection condition:

```text
src_ip=192.168.1.226
dest_ip=192.168.1.149
dest_port=22
user=analyst
action=failure
failed_attempts=5
```

Initial classification:

**Possible SSH brute-force activity**

Initial severity:

**MEDIUM**

---

# 5. Evidence Reviewed

The investigation used the following Lab 04 artifacts:

```text
02-Splunk-Labs/evidence/LAB-04/
```

Evidence included:

- `Test-A-PreAttack-Baseline.txt`
- `Test-B-Single-Failed-Login.txt`
- `Test-C-Repeated-Failed-Logins.txt`
- `Test-D-Remote-Brute-Force.txt`
- `Test-D-Splunk-Telemetry.csv`

Supporting telemetry originated from:

```text
/var/log/auth.log
```

Relevant OpenSSH event types included:

- `Accepted password`
- `authentication failure`
- `Failed password`
- `Connection closed`
- `Connection reset`
- PAM authentication failure summaries

---

# 6. Test A — Pre-Attack Baseline

The first phase established the condition of the monitored SSH service before
controlled attack simulation.

The SSH service was confirmed operational.

The target system was listening on TCP port 22.

The baseline established that the monitored host was capable of receiving SSH
authentication attempts before subsequent testing began.

Purpose:

Establish known-good service state before generating authentication failures.

Analyst assessment:

**BASELINE ESTABLISHED**

---

# 7. Test B — Single Failed Authentication

A controlled SSH login attempt generated a single failed password
authentication.

Sanitized evidence included:

```text
SENTINEL sshd[221617]: pam_unix(sshd:auth): authentication failure
SENTINEL sshd[221617]: Failed password for analyst from 192.168.1.149 port 43392 ssh2
SENTINEL sshd[221617]: Connection closed by authenticating user analyst 192.168.1.149 port 43392 [preauth]
```

One failed password attempt alone did not meet the Lab 04 brute-force
threshold.

Detection result:

**NO ALERT**

Analyst assessment:

A single failed password may result from ordinary user error and is
insufficient by itself to establish brute-force behavior.

---

# 8. Test C — Repeated Failures Below Threshold

Additional controlled authentication failures were generated.

The raw log contained a compressed syslog event:

```text
message repeated 2 times: [ Failed password for analyst ... ]
```

This demonstrated an important telemetry issue.

A simple count of physical lines containing `Failed password` does not
necessarily equal the actual number of failed authentication attempts.

Observed physical records containing `Failed password`:

```text
3
```

One record represented two repeated occurrences.

Ground-truth failed password attempts represented by the evidence:

```text
4
```

Lab threshold:

```text
5 failures within 5 minutes
```

Detection result:

**BELOW THRESHOLD**

Analyst assessment:

Repeated authentication failures were present, but the defined Lab 04
threshold had not yet been reached.

---

# 9. Test D — Remote Threshold-Crossing Activity

The final test generated SSH authentication failures from a separate lab
system.

Source:

```text
192.168.1.226
```

Destination:

```text
192.168.1.149
```

Target account:

```text
analyst
```

Service:

```text
SSH / TCP 22
```

Relevant sanitized evidence included:

```text
SENTINEL sshd[225844]: pam_unix(sshd:auth): authentication failure
SENTINEL sshd[225844]: Failed password for analyst from 192.168.1.226 port 32172 ssh2
SENTINEL sshd[225844]: message repeated 2 times: [ Failed password for analyst from 192.168.1.226 port 32172 ssh2]
SENTINEL sshd[225844]: Connection reset by authenticating user analyst 192.168.1.226 port 32172 [preauth]
SENTINEL sshd[225844]: PAM 2 more authentication failures
SENTINEL sshd[225961]: pam_unix(sshd:auth): authentication failure
SENTINEL sshd[225961]: Failed password for analyst from 192.168.1.226 port 32190 ssh2
SENTINEL sshd[225961]: Failed password for analyst from 192.168.1.226 port 32190 ssh2
```

The normalized Splunk telemetry represented five failed password
authentication attempts.

Detection result:

**ALERT CONDITION MET**

---

# 10. Timeline

The remote threshold-crossing activity occurred during the following period:

```text
2026-08-12 09:03–09:04 MDT
```

Observed sequence:

```text
09:03:25  Authentication failure recorded
09:03:26  Failed password recorded
09:03:37  Repeated failed-password events summarized
09:03:38  Connection reset during pre-authentication
09:03:38  PAM additional authentication failures recorded
09:04:09  New authentication failure recorded
09:04:10  Failed password recorded
09:04:16  Additional failed password recorded
```

The activity occurred within the configured five-minute detection window.

---

# 11. Detection Assessment

The activity satisfied the Lab 04 detection criteria.

Required condition:

```text
same source
+
same destination
+
SSH password failures
+
count >= 5
+
within 5 minutes
```

Observed condition:

```text
source:       192.168.1.226
destination:  192.168.1.149
port:         22
account:      analyst
failures:     5
time window:  < 5 minutes
```

Detection assessment:

**TRUE POSITIVE FOR THE DEFINED BEHAVIOR**

This classification means the detection correctly identified the behavior it
was designed to detect.

It does not mean the underlying activity was malicious.

---

# 12. Behavioral Analysis

The observed behavior was consistent with repeated password authentication
attempts against an SSH service.

From a SOC perspective, the pattern warranted investigation because repeated
authentication failures may indicate:

- Brute-force password guessing
- Credential attacks
- Unauthorized access attempts
- Misconfigured automation
- Expired credentials
- User password errors
- Authorized penetration testing
- Security lab activity

The event pattern alone was therefore insufficient to determine intent.

Context was required.

---

# 13. Source Analysis

Source IP:

```text
192.168.1.226
```

The source system was part of the authorized lab environment.

The source was intentionally used to generate authentication failures against
the monitored Linux system.

Source disposition:

**KNOWN / AUTHORIZED LAB SYSTEM**

No evidence reviewed during this exercise established an unknown external
source.

---

# 14. Destination Analysis

Destination IP:

```text
192.168.1.149
```

Destination service:

```text
SSH / TCP 22
```

The SSH service was confirmed active during Lab 04 validation.

The system produced the expected OpenSSH authentication telemetry.

Destination disposition:

**AUTHORIZED LAB TARGET**

---

# 15. Account Analysis

Target account:

```text
analyst
```

The username was sanitized for repository evidence.

The activity consisted of controlled failed password authentication attempts.

No successful authentication associated with the Test D brute-force sequence
was established by the evidence used for the detection.

No account compromise was established.

Account disposition:

**NO COMPROMISE IDENTIFIED**

---

# 16. Success-After-Failure Analysis

A particularly important SOC correlation is:

```text
multiple failures
        ↓
successful authentication
        ↓
possible credential compromise
```

Lab 04 evidence demonstrated failed authentication behavior.

The evidence reviewed for the threshold-crossing Test D sequence did not
establish a successful login following those failures.

Therefore:

**NO SUCCESS-AFTER-FAILURE CONDITION ESTABLISHED**

This distinction reduced the severity of the final assessment.

---

# 17. Scope Analysis

The investigation evaluated whether the activity extended beyond repeated SSH
authentication failures.

No evidence reviewed during the Lab 04 exercise established:

- Successful unauthorized authentication
- Additional compromised accounts
- Privilege escalation
- Persistence
- Malware execution
- Data exfiltration
- Lateral movement
- Command execution after authentication

The observed scope remained limited to the controlled SSH authentication
exercise.

---

# 18. MITRE ATT&CK Mapping

Observed behavior maps to:

**T1110 — Brute Force**

The technique mapping is based on repeated password authentication attempts.

ATT&CK mapping describes observed behavior.

It does not establish attacker intent by itself.

Analyst conclusion:

**Behavior matches T1110 characteristics, but context confirms authorized
training activity.**

---

# 19. False-Positive Analysis

Potential benign explanations for repeated SSH authentication failures
include:

- Mistyped passwords
- Expired credentials
- Cached or stale credentials
- Misconfigured scripts
- Administrative testing
- Automated service failures
- Penetration testing
- Security training exercises

In this investigation, the source and activity were known.

The failures were intentionally generated as part of Lab 04.

Therefore the alert represents:

**A true detection of benign authorized activity**

This differs from a false positive.

The detection correctly identified the defined authentication pattern; the
analyst investigation determined that the activity was non-malicious.

---

# 20. Severity Assessment

Initial severity:

**MEDIUM**

Reason:

The defined threshold for repeated SSH authentication failures was reached.

Potential severity would increase if additional evidence showed:

- Successful login following failures
- Multiple targeted accounts
- Multiple destination systems
- Known malicious source intelligence
- Privilege escalation
- Persistence
- Malware execution
- Lateral movement

None of those conditions were established by the Lab 04 evidence reviewed.

Final operational severity:

**INFORMATIONAL / CLOSED**

---

# 21. Analyst Assessment

The detection functioned as intended.

Five failed SSH password authentication attempts from the same source against
the same destination occurred within the configured detection window.

The pattern met the behavioral threshold for possible SSH brute-force
activity.

Investigation determined that:

- The source system was authorized
- The destination system was an authorized lab target
- The target account was part of the exercise
- The authentication failures were intentionally generated
- No successful compromise was established
- No malicious follow-on activity was established

The alert therefore required no escalation.

---

# 22. Disposition

Detection:

**TRUE POSITIVE — BEHAVIOR DETECTED**

Security disposition:

**BENIGN / AUTHORIZED ACTIVITY**

Escalation:

**NOT REQUIRED**

Containment:

**NOT REQUIRED**

Account reset:

**NOT REQUIRED**

Host isolation:

**NOT REQUIRED**

Case status:

**CLOSED**

---

# 23. Analyst Lessons

## Lesson 1 — One Failure Is Not Brute Force

A single failed authentication is common and should not automatically generate
a high-confidence brute-force alert.

## Lesson 2 — Thresholds Require Context

Five failures may justify investigation, but the count alone does not
determine malicious intent.

## Lesson 3 — Raw Log Lines Can Mislead

Syslog may compress repeated messages.

Detection engineers must understand whether they are counting physical log
records or actual authentication attempts.

## Lesson 4 — Success After Failure Matters

A successful authentication immediately following repeated failures can
significantly increase investigative priority.

## Lesson 5 — Detection and Disposition Are Different

A detection may be technically correct while the underlying activity is
benign.

## Lesson 6 — Evidence Should Drive the Case

The analyst should distinguish:

```text
What happened?
```

from:

```text
Why did it happen?
```

Telemetry establishes behavior.

Investigation establishes context.

---

# 24. SOC Workflow Demonstrated

Lab 04 demonstrated the following workflow:

```text
Establish Baseline
        ↓
Generate Single Failure
        ↓
Validate Authentication Telemetry
        ↓
Generate Repeated Failures
        ↓
Evaluate Detection Threshold
        ↓
Generate Remote Activity
        ↓
Normalize Events
        ↓
Apply Detection Logic
        ↓
Investigate Source / Destination / Account
        ↓
Evaluate Scope
        ↓
Map MITRE ATT&CK
        ↓
Determine Severity
        ↓
Assign Disposition
        ↓
Close Case
```

---

# 25. Final Case Status

**Case:** Lab 04 — SSH Brute-Force Investigation

**Detection:** Repeated Failed SSH Authentication

**Source:** `192.168.1.226`

**Destination:** `192.168.1.149`

**Service:** SSH / TCP 22

**Target Account:** `analyst`

**Observed Failures:** 5

**Detection Threshold:** Met

**MITRE ATT&CK:** T1110 — Brute Force

**Initial Severity:** Medium

**Compromise Established:** No

**Escalation Required:** No

**Final Disposition:** Benign / Authorized Training Activity

**Case Status:** Closed

---

**SOC Analyst Starter Kit v1**

**Incident Response — Lab 04**
