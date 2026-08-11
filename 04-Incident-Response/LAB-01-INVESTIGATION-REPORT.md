# SOC Investigation Report — Lab 01

## Linux Authentication Failure Investigation

**SOC Analyst Starter Kit v1**  
**Classification:** Training Exercise  
**Severity:** High  
**Status:** Closed  
**Disposition:** Benign / Authorized Activity

---

## 1. Executive Summary

Multiple authentication failures were detected on a monitored Ubuntu endpoint.

The detection identified five failed authentication events and assigned a HIGH
severity based on the configured detection threshold.

Analysis of the underlying telemetry identified four authentication failures
associated with the local graphical login process and one failure associated
with sudo authentication.

No remote source was identified in the reviewed events.

Based on the available evidence and known administrative activity, the events
were determined to represent legitimate local authentication troubleshooting
rather than malicious access.

**Final Disposition: Benign / Authorized Activity**

---

## 2. Detection Details

| Field | Value |
|---|---|
| Detection | Multiple Authentication Failures |
| Severity | HIGH |
| Failure Count | 5 |
| Authentication Mechanism | PAM |
| Local Login Source | GDM |
| Administrative Source | sudo |
| Remote Source | None identified |
| MITRE ATT&CK | T1110 — Brute Force |
| Escalation | Not Required |
| Status | Closed |

---

## 3. Detection Logic

The SOC analyzer processes Linux authentication telemetry and identifies
multiple authentication failures.

The detection workflow is:

```text
Linux Authentication
        ↓
/var/log/auth.log
        ↓
Python Detection Logic
        ↓
detected_threats.log
        ↓
Splunk
        ↓
SOC Investigation
