# Lab 01 — Linux Authentication Telemetry & Splunk Investigation

## SOC Analyst Starter Kit v1

**Difficulty:** Beginner  
**Platform:** Ubuntu Linux  
**SIEM:** Splunk  
**Log Source:** Linux Authentication Logs  
**Detection Focus:** Authentication Failures  
**MITRE ATT&CK:** T1110 — Brute Force

---

# 1. Lab Objective

In this lab, you will build and validate a basic Security Operations Center
telemetry pipeline using Linux authentication events, Python-based detection
logic, and Splunk.

You will learn how to:

- Identify Linux authentication telemetry
- Examine authentication failures
- Process security logs with a detection script
- Generate derived detection telemetry
- Configure Splunk to monitor SOC log output
- Validate that telemetry reaches the Splunk indexer
- Search authentication detections using SPL
- Distinguish a detection from a confirmed security incident
- Document evidence for a cybersecurity portfolio

---

# 2. Scenario

You are a Tier 1 SOC Analyst responsible for monitoring a Linux endpoint.

The system has recorded multiple authentication failures for a local user.
Your job is to determine whether the activity represents:

- Normal user behavior
- Administrative troubleshooting
- A misconfiguration
- Suspicious authentication activity
- A possible brute-force attempt

The goal is not simply to generate an alert.

The goal is to investigate the alert and determine its context.

---

# 3. Lab Architecture

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
