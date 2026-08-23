# Lab 02 — Suspicious PowerShell Investigation

## SOC Analyst Starter Kit v1

**Difficulty:** Beginner / Intermediate  
**Platform:** Windows  
**Detection Focus:** PowerShell Activity  
**Primary Telemetry:** Windows Event Logging  
**SIEM:** Splunk  
**MITRE ATT&CK:** T1059.001 — PowerShell

---

# 1. Lab Objective

In this lab, the analyst will generate controlled PowerShell activity on a
Windows endpoint, collect the resulting security telemetry, develop detection
logic, investigate the activity, and document the final disposition.

The student will learn how to:

- Identify PowerShell activity on Windows
- Enable useful PowerShell logging
- Generate controlled test activity
- Examine Windows Event Logs
- Identify suspicious command-line patterns
- Develop PowerShell detection logic
- Ingest Windows telemetry into Splunk
- Search events using SPL
- Map behavior to MITRE ATT&CK
- Document an investigation
- Distinguish suspicious behavior from malicious intent

---

# 2. Scenario

You are a Tier 1 SOC Analyst monitoring a Windows endpoint.

Security telemetry indicates that PowerShell commands were executed.

PowerShell is a legitimate administrative tool but is also frequently used
during malicious activity.

Your responsibility is to determine:

- What PowerShell command executed?
- Which user executed it?
- Which host generated the event?
- What was the command attempting to accomplish?
- Was the activity expected?
- Does the activity require escalation?

---

# 3. Detection Concept

The goal is not to detect every PowerShell execution as malicious.

Instead, analysts identify PowerShell activity that may deserve additional
investigation.

Examples may include:

- Encoded commands
- Download activity
- Hidden execution
- Suspicious child processes
- Execution policy bypass
- Obfuscated commands
- Unusual network activity
- Commands inconsistent with normal user behavior

---

# 4. Lab Architecture

```text
Windows Endpoint
       |
       v
PowerShell Activity
       |
       v
Windows Event Logging
       |
       v
PowerShell Operational Log
       |
       v
Telemetry Collection
       |
       v
Splunk
       |
       v
SPL Detection
       |
       v
SOC Investigation
       |
       v
Analyst Disposition

```
