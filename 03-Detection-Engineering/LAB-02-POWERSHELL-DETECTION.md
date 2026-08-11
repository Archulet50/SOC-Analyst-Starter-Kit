# Detection Engineering — Lab 02

## Suspicious PowerShell Activity

**SOC Analyst Starter Kit v1**  
**Platform:** Windows 11  
**Telemetry:** PowerShell Script Block Logging  
**Primary Event ID:** 4104  
**Correlated Event ID:** 4688  
**MITRE ATT&CK:** T1059.001 — PowerShell

---

# 1. Detection Objective

Identify PowerShell activity containing characteristics that may warrant
additional SOC investigation.

PowerShell is a legitimate administrative and automation tool. The objective
is therefore not to alert on every PowerShell execution.

The detection should identify behaviors or combinations of indicators that
increase investigative value.

---

# 2. Data Sources

Primary PowerShell telemetry:

```text
Microsoft-Windows-PowerShell/Operational
Event ID 4104
Process creation telemetry:

Windows Security Log
Event ID 4688

Event ID 4104 provides visibility into PowerShell script-block content.

Event ID 4688 provides process creation context including process name,
creator process, account context, elevation information, and — when enabled —
the process command line.

---

# 3. Detection Pipeline

Windows Endpoint
       |
       v
PowerShell Execution
       |
       +----------------------+
       |                      |
       v                      v
Event ID 4104            Event ID 4688
Script Content           Process Creation
       |                      |
       +----------+-----------+
                  |
                  v
            Correlation
                  |
                  v
          Detection Logic
                  |
                  v
           SOC Investigation
                  |
                  v
             Disposition

---

# 4. Lab Validation Tests

## Test A — Baseline PowerShell

Marker:

ACL-LAB02-BASELINE

Purpose:

Establish normal PowerShell telemetry.

Observed result:

- Event ID 4104 generated
- Script contents captured
- No suspicious behavior identified

Expected severity:

INFORMATIONAL

---

## Test B — Suspicious Indicators

Marker:

ACL-LAB02-SUSPICIOUS

Controlled indicators:

- Bypass
- Hidden
- DownloadString

The indicators were stored as harmless strings.

The test did not:

- Bypass execution policy
- Launch a hidden process
- Download content
- Execute downloaded content

Purpose:

Demonstrate how keyword detection can identify suspicious-looking activity
without proving malicious behavior.

Expected severity:

MEDIUM — INVESTIGATION REQUIRED

Expected disposition after investigation:

BENIGN / AUTHORIZED TRAINING ACTIVITY

---

## Test C — Encoded PowerShell

Marker:

ACL-LAB02-ENCODED

A harmless PowerShell command was encoded and executed using:

powershell.exe -NoProfile -EncodedCommand <Base64>

Decoded payload:

Write-Output "ACL-LAB02-ENCODED"

Event ID 4104 successfully exposed the processed script content.

Purpose:

Demonstrate that encoded execution is an investigative signal while the
decoded content determines what PowerShell actually executed.

Expected severity:

MEDIUM — INVESTIGATION REQUIRED

Expected disposition:

BENIGN / AUTHORIZED TRAINING ACTIVITY

---

## Test D — Process Creation Correlation

Marker:

ACL-LAB02-4688

Observed:

Event ID: 4688
Process: powershell.exe
Parent: powershell.exe
Command line captured: Yes

Purpose:

Correlate PowerShell script telemetry with process creation telemetry.

---# 5. Detection Indicators

Initial indicators include:

| Indicator | Investigative Value |
|---|---|
| EncodedCommand | Encoded PowerShell execution |
| -enc | Possible abbreviated encoded execution |
| Bypass | Possible execution-policy bypass |
| Hidden | Possible attempt to reduce user visibility |
| DownloadString | Possible network retrieval behavior |
| Invoke-WebRequest | Possible network retrieval |
| Invoke-Expression | Dynamic command execution |
| IEX | Alias associated with Invoke-Expression |

Indicator presence alone does not establish malicious intent.

---

# 6. Severity Model

## Informational

Normal PowerShell activity with no suspicious indicators.

Examples:

- Get-Date
- Get-Process
- Write-Output

## Low

A weak indicator requiring additional context.

## Medium

One strong indicator or multiple suspicious indicators.

Examples:

EncodedCommand

or:

Bypass + Hidden

## High

Multiple high-risk behaviors supported by corroborating telemetry.

Conceptual example:

Encoded execution
       +
Network retrieval
       +
Dynamic execution
       +
Suspicious process lineage

A HIGH detection still requires analyst validation.

---

# 7. Conceptual Detection Logic

IF EventID = 4104:
    Inspect script content.

IF no suspicious indicators:
    Severity = INFORMATIONAL.

IF one weak indicator:
    Severity = LOW.

IF one strong indicator OR multiple suspicious indicators:
    Severity = MEDIUM.

IF multiple high-risk behaviors AND corroborating telemetry exists:
    Severity = HIGH.

CORRELATE Event ID 4104 with Event ID 4688:

- Review process name
- Review command line
- Review parent process
- Review user context
- Review token elevation
- Review surrounding endpoint activity

---

# 8. Example Splunk Searches

Basic PowerShell search:

    index=main EventCode=4104

Search for selected indicators:

    index=main EventCode=4104
    (
        "EncodedCommand"
        OR "DownloadString"
        OR "Invoke-WebRequest"
        OR "Invoke-Expression"
        OR "Bypass"
        OR "Hidden"
    )

Example indicator-scoring concept:

    index=main EventCode=4104
    | eval encoded=if(match(_raw,"(?i)EncodedCommand"),1,0)
    | eval download=if(match(_raw,"(?i)DownloadString|Invoke-WebRequest"),1,0)
    | eval execution=if(match(_raw,"(?i)Invoke-Expression|\bIEX\b"),1,0)
    | eval bypass=if(match(_raw,"(?i)Bypass"),1,0)
    | eval hidden=if(match(_raw,"(?i)Hidden"),1,0)
    | eval indicator_score=encoded+download+execution+bypass+hidden
    | where indicator_score > 0
    | sort - indicator_score

This is starting detection logic and requires tuning against the environment.

---

# 9. Correlation Strategy

The preferred investigative model combines:

Event ID 4104
    Script Content
         +
Event ID 4688
    Process Creation
         +
    Command Line
         +
    Parent Process
         +
    User Context
         |
         v
Higher-Confidence Investigation

A single indicator can create an alert.

Correlated evidence provides context that helps the analyst determine what
actually occurred.

---

# 10. False-Positive Considerations

Legitimate PowerShell activity may include:

- System administration
- IT support
- Software deployment
- Security tooling
- Configuration management
- Automation
- Troubleshooting
- Scheduled tasks
- Log collection
- Endpoint management

Keyword presence alone should not determine final disposition.

---# 11. Analyst Triage Questions

When the detection fires, determine:

1. Which endpoint generated the activity?
2. Which account executed PowerShell?
3. What script block executed?
4. Which indicators triggered the detection?
5. Was the activity encoded or obfuscated?
6. Was network retrieval performed?
7. Was another command dynamically executed?
8. What process launched PowerShell?
9. What child processes were created?
10. Was the process elevated?
11. Is the behavior expected for this user and endpoint?
12. Does supporting telemetry indicate malicious behavior?

---

# 12. Lab Results

## Test A — Baseline

Marker:

ACL-LAB02-BASELINE

Telemetry:

- Event ID 4104 captured
- Script-block contents visible
- No suspicious behavior identified

Disposition:

BENIGN / BASELINE ACTIVITY

---

## Test B — Suspicious Indicators

Marker:

ACL-LAB02-SUSPICIOUS

Indicators:

- Bypass
- Hidden
- DownloadString

Telemetry:

- Event ID 4104 captured
- Complete test script block visible

Investigation determined that the indicators were harmless string values.

No execution-policy bypass occurred.

No hidden process was launched.

No remote content was downloaded.

Disposition:

BENIGN / AUTHORIZED TRAINING ACTIVITY

---

## Test C — Encoded PowerShell

Marker:

ACL-LAB02-ENCODED

Execution method:

powershell.exe -NoProfile -EncodedCommand <Base64>

Decoded script observed in Event ID 4104:

Write-Output "ACL-LAB02-ENCODED"

Investigation demonstrated that Script Block Logging provided visibility into
the script content processed by PowerShell.

Disposition:

BENIGN / AUTHORIZED TRAINING ACTIVITY

---

## Test D — Process Creation

Marker:

ACL-LAB02-4688

Telemetry:

- Security Event ID 4688 captured
- New process identified as powershell.exe
- Creator process identified as powershell.exe
- Command line captured
- Account context captured
- Token elevation information captured

Observed process relationship:

Parent PowerShell
       |
       v
Child PowerShell
       |
       v
Event ID 4688

Disposition:

BENIGN / AUTHORIZED TRAINING ACTIVITY

---

# 13. Detection vs. Investigation

Test B demonstrates a limitation of simple keyword detection.

The script contained:

- Bypass
- Hidden
- DownloadString

However, those strings did not perform the behaviors their names suggested.

Therefore:

Indicator Match
      !=
Behavior Confirmed
      !=
Malicious Intent

Detection identifies activity worth examining.

Investigation determines what actually happened.

---

# 14. Encoded Execution Lesson

Test C demonstrates another important distinction:

Encoded Execution
      !=
Malicious Payload

Encoding may increase investigative priority because it can obscure command
content.

The analyst should determine what the decoded command actually performs.

In this lab, the decoded payload performed only a harmless Write-Output
operation.

---

# 15. Process Correlation Lesson

Event ID 4688 adds context that Event ID 4104 alone does not provide.

Useful process-creation fields include:

- New Process Name
- Creator Process Name
- Process Command Line
- New Process ID
- Creator Process ID
- Account Name
- Logon ID
- Token Elevation Type

This allows the analyst to move from:

PowerShell content observed

to:

Who launched it?
What launched it?
How was it launched?
Was it elevated?
What command line was used?

---

# 16. Legitimate PowerShell Process Context

During testing, additional process telemetry showed legitimate Splunk-related
PowerShell activity.

Observed lineage:

splunkd.exe
     |
     v
splunk-powershell.exe

This reinforces another detection-engineering principle:

Process Name
     !=
Malicious Process

Parent process, application context, user context, command line, and
surrounding telemetry should be considered before assigning disposition.

---

# 17. Detection Improvement Opportunities

Future versions can incorporate:

- Sysmon process telemetry
- Network telemetry
- DNS telemetry
- File creation events
- Registry activity
- Parent/child process relationships
- User baselines
- Host roles
- Frequency analysis
- Threat-intelligence enrichment
- Allowlisting
- Risk-based scoring

---

# 18. Detection Maturity

Current progression:

Level 1 — Script Block Indicator Detection
                |
                v
Level 2 — Indicator Scoring
                |
                v
Level 3 — Process Correlation
                |
                v
Level 4 — Network and Endpoint Correlation
                |
                v
Level 5 — Behavioral / Risk-Based Detection

Lab 02 demonstrates the foundation for Levels 1 through 3 through controlled
endpoint testing.

---

# 19. Evidence

Lab evidence generated during testing:

- Test-A-Baseline.txt
- Test-B-Suspicious.txt
- Test-C-Encoded.txt
- Test-D-ProcessCreation.txt

Evidence must be sanitized before inclusion in a public portfolio or
commercial training product.

Potentially identifying information should be removed when unnecessary,
including:

- Personal usernames
- Hostnames
- Security identifiers
- Internal environment information
- Credentials
- Tokens
- Sensitive network information

---

# 20. Detection Engineering Principle

Detection engineering is not:

Suspicious Word
       |
       v
Attack

A stronger model is:

Telemetry
    |
    v
Indicator
    |
    v
Detection
    |
    v
Correlation
    |
    v
Context
    |
    v
Analyst Judgment
    |
    v
Disposition

The objective is not simply to identify suspicious-looking commands.

The objective is to determine what occurred, establish context, evaluate
risk, and support an evidence-based analyst decision.

---

# 21. Lab 02 Detection Status

PowerShell 5.1: VALIDATED

Script Block Logging: VALIDATED

Event ID 4104: VALIDATED

Baseline PowerShell Telemetry: VALIDATED

Suspicious Indicator Telemetry: VALIDATED

Encoded PowerShell Telemetry: VALIDATED

Process Creation Auditing: VALIDATED

Event ID 4688: VALIDATED

Command-Line Capture: VALIDATED

Parent/Child Process Visibility: VALIDATED

4104 + 4688 Correlation Model: VALIDATED

---

**SOC Analyst Starter Kit v1**

**Detection Engineering — Lab 02**
