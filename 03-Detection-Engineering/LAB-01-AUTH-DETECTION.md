# Detection Engineering — Lab 01

## Multiple Linux Authentication Failures

**SOC Analyst Starter Kit v1**  
**Platform:** Ubuntu Linux  
**Detection Type:** Authentication  
**Severity:** HIGH  
**MITRE ATT&CK:** T1110 — Brute Force

---

# 1. Detection Objective

Identify repeated Linux authentication failures that may indicate:

- Brute-force activity
- Password guessing
- Credential misuse
- Misconfigured credentials
- Administrative troubleshooting
- Normal user authentication mistakes

The detection identifies suspicious authentication behavior.

It does not determine malicious intent.

---

# 2. Data Sources

Primary authentication telemetry:

```text
/var/log/auth.log

```

Derived detection telemetry:

```text
detected_threats.log
```

The authentication log provides the underlying Linux PAM events.

The Python SOC analyzer processes authentication telemetry and generates
derived detection output for Splunk monitoring and analyst investigation.

---

# 3. Detection Pipeline

```text
Linux Authentication Activity
            |
            v
    /var/log/auth.log
            |
            v
   Python SOC Analyzer
   soc_log_analyzer.py
            |
            v
 detected_threats.log
            |
            v
      Splunk Monitor
            |
            v
        index=main
            |
            v
     SPL Investigation
            |
            v
    Analyst Disposition
```

The pipeline separates raw telemetry, detection logic, SIEM visibility, and
analyst disposition.

---

# 4. Detection Hypothesis

Multiple authentication failures in the monitored event set may represent
suspicious authentication behavior and should be reviewed by an analyst.

A HIGH-severity result indicates that the configured detection threshold was
satisfied.

Severity alone does not establish malicious intent.

---

# 5. Observed Detection Result

The validated Lab 01 evidence recorded:

| Field | Observed Value |
|---|---|
| Detection | Authentication Failures |
| Severity | HIGH |
| Failure Count | 5 |
| Affected User | Local user |
| GDM Authentication Failures | 4 |
| sudo Authentication Failures | 1 |
| Remote Source | None identified |

Four observed events originated from the graphical login authentication
process (`gdm-password`).

One observed event originated from `sudo` authentication.

No remote host was identified in the reviewed event set.

---

# 6. Detection Assessment

The detection correctly identified multiple authentication failures and
reached the configured HIGH-severity threshold.

The observed behavior warranted investigation because repeated authentication
failures can be associated with password guessing or brute-force activity.

Investigation of the available telemetry associated the events with legitimate
local authentication and administrative troubleshooting activity.

No evidence of remote authentication attempts was identified in the reviewed
events.

---

# 7. False-Positive and Benign Considerations

Repeated authentication failures are not inherently malicious.

Potential legitimate explanations include:

- Mistyped credentials
- Graphical login authentication problems
- Administrative troubleshooting
- Failed `sudo` authentication
- Misconfigured credentials

Analysts should evaluate authentication source, account context, event count,
remote-source information, surrounding activity, and known administrative
actions before escalating.

---

# 8. MITRE ATT&CK Mapping

**T1110 — Brute Force**

The detection monitors authentication-failure behavior that can be associated
with brute-force activity.

ATT&CK mapping describes the behavior monitored by the detection. It does not
establish that the observed event set was malicious.

For this validated exercise, investigation determined that the observed
activity was benign and authorized.

---

# 9. Analyst Disposition

**Detection Result:** TRUE POSITIVE

**Detection Severity:** HIGH

**Activity Classification:** BENIGN / AUTHORIZED ACTIVITY

**Remote Authentication:** NONE IDENTIFIED

**Escalation:** NOT REQUIRED

The detection is considered a true positive because the authentication
failures targeted by the analytic actually occurred.

The final disposition reflects the context of those events rather than
changing whether the detection itself fired correctly.

---

# 10. Detection Engineering Lessons

This lab demonstrates several foundational detection-engineering principles:

- Detection severity is not equivalent to malicious intent.
- Authentication failures require contextual investigation.
- Local authentication activity can satisfy a brute-force-oriented threshold.
- Analysts should distinguish detection fidelity from incident classification.
- Available evidence should define the scope of the conclusion.
- Absence of an identified remote source in the reviewed evidence should not
  be generalized beyond the investigated event set.

---

# 11. SOC Workflow

```text
Telemetry
   |
   v
Detection
   |
   v
Triage
   |
   v
Investigation
   |
   v
Context
   |
   v
Disposition
```

The objective is not simply to generate a high-severity alert.

The objective is to identify relevant behavior, investigate the supporting
telemetry, establish context, and reach an evidence-based analyst disposition.

---

# 12. Lab 01 Detection Status

Linux Authentication Telemetry: VALIDATED

Authentication Failure Detection: VALIDATED

Five-Event Detection Result: VALIDATED

HIGH-Severity Threshold: VALIDATED

GDM Authentication Context: VALIDATED

sudo Authentication Context: VALIDATED

Remote Source in Reviewed Events: NONE IDENTIFIED

Final Disposition: BENIGN / AUTHORIZED ACTIVITY

Escalation: NOT REQUIRED

---

**SOC Analyst Starter Kit v1**

**Detection Engineering — Lab 01**
