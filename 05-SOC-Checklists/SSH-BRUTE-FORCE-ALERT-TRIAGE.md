# SSH Brute-Force Alert Triage Checklist

## SOC Analyst Starter Kit v1

Use this checklist when investigating repeated failed SSH authentication
activity or a suspected brute-force alert.

---

# 1. Alert Validation

- [ ] Confirm alert timestamp
- [ ] Confirm source IP
- [ ] Confirm destination IP
- [ ] Confirm destination port
- [ ] Confirm affected account
- [ ] Confirm authentication method
- [ ] Review assigned severity
- [ ] Identify the detection rule and threshold
- [ ] Confirm the alert time window

---

# 2. Authentication Failure Review

Review OpenSSH authentication telemetry for:

- [ ] `Failed password`
- [ ] `authentication failure`
- [ ] PAM failure summaries
- [ ] `Connection closed`
- [ ] `Connection reset`
- [ ] `[preauth]` activity

Primary Linux source:

```text
/var/log/auth.log
```

Additional source:

```text
journalctl -u ssh
```

---

# 3. Failure Count Validation

Determine the actual number of failed authentication attempts.

Do not assume:

```text
one physical log line = one authentication attempt
```

Check for compressed messages such as:

```text
message repeated 2 times: [ Failed password ... ]
```

Record:

- [ ] Physical failed-password log records
- [ ] Repeated-message multiplier
- [ ] Actual failed authentication attempts
- [ ] Number of SSH sessions involved

---

# 4. Threshold Assessment

Compare observed activity with the configured detection threshold.

Lab 04 reference threshold:

```text
5 or more failed SSH password authentications
from the same source
against the same destination
within 5 minutes
```

Determine:

- [ ] Threshold met
- [ ] Threshold not met
- [ ] Activity exceeded threshold significantly

---

# 5. Source Analysis

Record:

- [ ] Source IP
- [ ] Source hostname if known
- [ ] Internal or external source
- [ ] Asset owner
- [ ] Expected system role
- [ ] Authorized administrative system
- [ ] Authorized scanner or security-testing system
- [ ] Previous authentication activity
- [ ] Previous reconnaissance activity

Key question:

Is this source expected to initiate SSH connections to the target?

---

# 6. Destination Analysis

Record:

- [ ] Destination IP
- [ ] Destination hostname
- [ ] Destination asset role
- [ ] SSH service state
- [ ] Destination port
- [ ] Asset criticality
- [ ] Whether SSH exposure is expected

Confirm:

```text
TCP/22
```

is an authorized listening service.

---

# 7. Account Analysis

Determine:

- [ ] Targeted username
- [ ] Account validity
- [ ] Account privilege level
- [ ] Administrative access
- [ ] Service account vs. human user
- [ ] Whether multiple usernames were targeted
- [ ] Whether the account was disabled or locked
- [ ] Whether the password was recently changed

---

# 8. Success-After-Failure Correlation

Search for successful SSH authentication after the failed attempts.

Key event:

```text
Accepted password
```

Determine:

- [ ] No successful authentication followed
- [ ] Successful authentication followed
- [ ] Successful authentication came from same source
- [ ] Successful authentication targeted same account
- [ ] Success occurred shortly after failures

A successful login following repeated failures can significantly increase
investigation priority.

---

# 9. Reconnaissance Correlation

Review network telemetry occurring before the authentication failures.

Check for:

- [ ] Port scanning
- [ ] TCP/22 discovery
- [ ] Network service discovery
- [ ] Multiple destination ports
- [ ] Multiple target systems
- [ ] Repeated connection attempts

MITRE ATT&CK correlation may include:

```text
T1046 — Network Service Discovery
```

followed by:

```text
T1110 — Brute Force
```

---

# 10. Follow-On Activity

Review telemetry after the authentication attempt window.

Check for:

- [ ] Successful SSH session
- [ ] Command execution
- [ ] sudo activity
- [ ] Privilege escalation
- [ ] New processes
- [ ] Persistence
- [ ] New users or groups
- [ ] File modification
- [ ] Network connections
- [ ] Lateral movement
- [ ] Data transfer
- [ ] Malware alerts

---

# 11. MITRE ATT&CK Mapping

Primary technique:

**T1110 — Brute Force**

Use this mapping when repeated password authentication attempts are observed.

Potential related technique:

**T1046 — Network Service Discovery**

if reconnaissance occurred before the authentication activity.

Remember:

MITRE ATT&CK identifies behavior.

It does not determine malicious intent or final disposition.

---

# 12. False-Positive Review

Consider legitimate explanations:

- [ ] User mistyped password
- [ ] Expired credentials
- [ ] Cached credentials
- [ ] Misconfigured automation
- [ ] Administrative troubleshooting
- [ ] Security testing
- [ ] Penetration testing
- [ ] Training exercise
- [ ] Service account credential failure

Document the evidence supporting the final explanation.

---

# 13. Severity Assessment

## Informational / Low

Consider when:

- One or two failures occur
- Source is expected
- No suspicious follow-on activity exists

## Medium

Consider when:

- Failure threshold is reached
- Same source repeatedly targets SSH
- No confirmed compromise exists

## High

Consider when failures are combined with:

- Successful authentication afterward
- Multiple targeted accounts
- Multiple target hosts
- Known malicious source
- Reconnaissance immediately beforehand
- Privilege escalation
- Malware activity
- Lateral movement
- Persistence

---

# 14. Escalation Criteria

Escalate when:

- Source is unknown or unauthorized
- Failure volume is significant
- Multiple accounts are targeted
- Sensitive systems are targeted
- Successful login follows repeated failures
- Activity continues after blocking attempts
- Privilege escalation follows authentication
- Additional malicious behavior is correlated
- Analyst cannot explain the source or activity

---

# 15. Containment Considerations

If malicious activity is confirmed, consider:

- Blocking source IP
- Disabling affected account
- Resetting credentials
- Restricting SSH exposure
- Reviewing authorized_keys
- Reviewing active sessions
- Isolating affected systems
- Escalating to incident response

Containment actions should match organizational policy and incident severity.

---

# 16. Disposition

Select the most appropriate outcome:

- [ ] True Positive — Malicious
- [ ] True Positive — Authorized Security Activity
- [ ] Benign / Authorized Activity
- [ ] False Positive
- [ ] Requires Additional Investigation

---

# 17. Documentation Requirements

Record:

- Source IP
- Destination IP
- Destination port
- Targeted user
- Failure count
- Number of sessions
- Time window
- Detection threshold
- Successful login correlation
- Reconnaissance correlation
- Follow-on activity
- MITRE ATT&CK mapping
- Analyst assessment
- Severity
- Final disposition
- Escalation decision
- Containment actions if required

---

# Analyst Principle

A brute-force alert should answer more than:

```text
How many failures occurred?
```

The analyst should determine:

```text
Who generated them?
What system was targeted?
Which account was targeted?
Over what time?
Did authentication succeed?
What happened before and after?
Was the activity authorized?
```

Detection identifies the behavior.

Investigation determines the meaning.

---

**SOC Analyst Starter Kit v1**

**SSH Brute-Force Alert Triage Checklist**
