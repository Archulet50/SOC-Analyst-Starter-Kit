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

The detection identifies suspicious behavior.

It does not determine malicious intent.

---

# 2. Data Source

Primary telemetry:

```text
/var/log/auth.log
