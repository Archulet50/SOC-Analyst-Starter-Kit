# SOC Investigation Report — Lab 02

## Suspicious PowerShell Activity Investigation

**SOC Analyst Starter Kit v1**  
**Classification:** Training Exercise  
**Platform:** Windows 11  
**Primary Telemetry:** PowerShell Script Block Logging  
**Primary Event ID:** 4104  
**Correlated Event ID:** 4688  
**MITRE ATT&CK:** T1059.001 — PowerShell  
**Status:** Closed  
**Disposition:** Benign / Authorized Training Activity

---

# 1. Executive Summary

Controlled PowerShell activity was generated on a Windows endpoint to evaluate
PowerShell telemetry, detection logic, process correlation, and analyst
investigation workflow.

Four controlled tests were performed:

1. Baseline PowerShell activity
2. Suspicious-looking PowerShell indicators
3. Encoded PowerShell execution
4. PowerShell process creation and command-line capture

PowerShell Script Block Logging successfully recorded the test activity using
Event ID 4104.

Windows Process Creation auditing successfully recorded process activity using
Security Event ID 4688.

The investigation demonstrated that suspicious keywords, encoded execution,
and PowerShell process creation provide useful investigative signals, but none
independently establishes malicious intent.

All reviewed activity was intentionally generated for authorized
cybersecurity training.

Final disposition:

BENIGN / AUTHORIZED TRAINING ACTIVITY

---

# 2. Environment

Platform:

Windows 11

PowerShell:

Windows PowerShell 5.1

Primary PowerShell log:

Microsoft-Windows-PowerShell/Operational

Primary PowerShell telemetry:

Event ID 4104 — Script Block Logging

Process telemetry:

Security Event ID 4688 — Process Creation

Command-line process auditing:

Enabled and validated

---

# 3. Investigation Workflow

PowerShell Activity
       |
       v
Event ID 4104
Script Content
       |
       +----------------------+
       |                      |
       v                      v
Indicator Review        Event ID 4688
                       Process Creation
                              |
                              v
                         Command Line
                              |
                              v
                         Parent Process
       |                      |
       +----------+-----------+
                  |
                  v
              Context
                  |
                  v
          Analyst Assessment
                  |
                  v
             Disposition

---

# 4. Test A — Baseline PowerShell

Marker:

ACL-LAB02-BASELINE

Observed telemetry:

Event ID 4104

Observed script activity included:

$LabMessage = "ACL-LAB02-BASELINE"
Get-Date
$LabMessage

## Assessment

The activity represented ordinary PowerShell execution.

Script Block Logging successfully captured the activity.

No suspicious behavior was identified.

## Disposition

BENIGN / BASELINE ACTIVITY

---

# 5. Test B — Suspicious Indicators

Marker:

ACL-LAB02-SUSPICIOUS

Indicators observed:

- Bypass
- Hidden
- DownloadString

The controlled script assigned these indicators as harmless string values.

## Initial Assessment

A keyword-based detection could reasonably flag these terms because they may
appear in suspicious or malicious PowerShell activity.

The alert therefore warrants investigation.

## Investigation Findings

Review of the complete Event ID 4104 script block showed that the terms were
stored as variable values.

The script did not:

- Bypass execution policy
- Launch a hidden PowerShell process
- Download remote content
- Execute downloaded content
- Invoke an additional payload

## Analyst Assessment

The indicators were genuinely present in the telemetry.

The behaviors suggested by those words did not actually occur.

## Disposition

BENIGN / AUTHORIZED TRAINING ACTIVITY

---

# 6. Test C — Encoded PowerShell

Marker:

ACL-LAB02-ENCODED

Execution method:

powershell.exe -NoProfile -EncodedCommand <Base64>

Decoded command:

Write-Output "ACL-LAB02-ENCODED"

Event ID 4104 captured the decoded script content processed by PowerShell.

## Analyst Assessment

Encoded execution can warrant additional investigation because encoding may
be used to obscure command content.

However:

Encoded Execution
       !=
Malicious Payload

The decoded payload in this test performed only a harmless Write-Output
operation.

## Disposition

BENIGN / AUTHORIZED TRAINING ACTIVITY

---
# 7. Test D — Process Creation Correlation

Marker:

ACL-LAB02-4688

Windows Process Creation auditing generated:

Security Event ID 4688

Observed new process:

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Observed creator process:

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Observed command line:

powershell.exe -NoProfile -Command "Write-Output 'ACL-LAB02-4688'"

Token elevation:

TokenElevationTypeFull

## Process Relationship

Parent PowerShell
       |
       v
Child PowerShell
       |
       v
Event ID 4688
       |
       v
Command Line Captured

## Investigation Findings

Event ID 4688 provided additional context not available from script-block
content alone.

The event identified:

- New process name
- Creator process name
- Process command line
- New process ID
- Creator process ID
- Account context
- Logon context
- Token elevation information

The observed PowerShell child process matched the controlled Lab 02 activity.

## Analyst Assessment

The process relationship and command line were consistent with the authorized
test.

No unexpected process lineage was identified for the test marker.

## Disposition

BENIGN / AUTHORIZED TRAINING ACTIVITY

---

# 8. Additional Process Context

During review of Event ID 4688 telemetry, additional PowerShell-related
process activity was observed.

The process relationship included:

splunkd.exe
     |
     v
splunk-powershell.exe

This activity was separate from the controlled ACL-LAB02-4688 test.

## Analyst Lesson

A PowerShell-related executable name does not automatically indicate malicious
activity.

For example:

Process Name
     !=
Malicious Activity

Analysts should examine:

- Parent process
- Child process
- User or service account
- Command line
- Application context
- Elevation
- Timing
- Surrounding telemetry

The Splunk-related process lineage provides a useful example of legitimate
software generating PowerShell-related process activity.

---

# 9. Telemetry Correlation

The investigation demonstrated the value of combining multiple Windows
telemetry sources.

Event ID 4104 provides:

- PowerShell script-block content
- Decoded script visibility
- PowerShell command context

Event ID 4688 provides:

- Process creation
- Parent process
- Child process
- Command line
- User context
- Process identifiers
- Elevation information

Combined investigative model:

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

A single event may identify something worth investigating.

Correlated telemetry helps explain what actually occurred.

---

# 10. MITRE ATT&CK Mapping

Technique:

T1059.001 — PowerShell

PowerShell can be used by adversaries to execute commands and scripts.

The ATT&CK mapping identifies the behavior being monitored.

It does not mean every PowerShell event represents adversary activity.

The analyst must determine whether the observed behavior is expected,
suspicious, or malicious.

---

# 11. Indicators Reviewed

The investigation considered:

- PowerShell execution
- Event ID 4104
- Event ID 4688
- EncodedCommand
- Bypass
- Hidden
- DownloadString
- Script-block contents
- Parent process
- Child process
- Command-line arguments
- User context
- Process elevation

---

# 12. False-Positive Considerations

Legitimate PowerShell activity may result from:

- System administration
- IT support
- Security tooling
- Software deployment
- Automation
- Configuration management
- Scheduled tasks
- Troubleshooting
- Endpoint management
- Log collection
- Authorized security testing

Detection logic must therefore consider operational context.

---

# 13. Analyst Assessment

The telemetry pipeline successfully captured PowerShell activity through
multiple Windows logging mechanisms.

Test B demonstrated:

Suspicious Indicator
        !=
Malicious Behavior

Test C demonstrated:

Encoded Execution
        !=
Malicious Payload

Test D demonstrated:

Process Creation
        +
Command Line
        +
Parent Process
        =
Additional Investigative Context

The analyst should inspect the actual script content, process lineage, command
line, user context, and surrounding telemetry before assigning final
disposition.

---

# 14. Final Disposition

Final classification:

BENIGN / AUTHORIZED TRAINING ACTIVITY

Rationale:

- Test activity was intentionally generated.
- Script contents were known and controlled.
- Baseline activity was benign.
- Suspicious keywords were stored only as harmless strings.
- No execution-policy bypass occurred during the suspicious-indicator test.
- No hidden PowerShell process was launched during that test.
- No remote content was downloaded.
- The encoded payload contained only a benign training marker.
- Process creation matched the expected test behavior.
- No unauthorized activity was identified.

Escalation:

NOT REQUIRED

Case status:

CLOSED

---

# 15. Evidence

Associated Lab 02 evidence:

- Test-A-Baseline.txt
- Test-B-Suspicious.txt
- Test-C-Encoded.txt
- Test-D-ProcessCreation.txt

Evidence should be preserved for lab validation.

Before evidence is included in a public portfolio or commercial product,
machine-specific information should be reviewed and sanitized where
appropriate.

Examples include:

- Personal usernames
- Hostnames
- Security identifiers
- Internal environment information
- Credentials
- Authentication tokens
- Sensitive network information

---

# 16. Lessons Learned

Lab 02 demonstrates the progression from telemetry collection to correlated
SOC investigation.

Telemetry
    |
    v
Detection
    |
    v
Triage
    |
    v
Correlation
    |
    v
Context
    |
    v
Analyst Assessment
    |
    v
Disposition

The analyst's job is not simply to identify suspicious-looking strings.

The analyst must determine:

- What executed?
- What did it actually do?
- Who executed it?
- What launched it?
- Was it elevated?
- What happened around it?
- Is the activity expected?
- What evidence supports the conclusion?

---

# 17. Final Case Status

Detection: VALID

PowerShell Telemetry: VALIDATED

Event ID 4104: VALIDATED

Encoded PowerShell Visibility: VALIDATED

Process Creation Auditing: VALIDATED

Event ID 4688: VALIDATED

Command-Line Capture: VALIDATED

Parent/Child Process Visibility: VALIDATED

Malicious Activity: NOT IDENTIFIED

Escalation: NOT REQUIRED

Disposition: BENIGN / AUTHORIZED TRAINING ACTIVITY

Case Status: CLOSED

---

**SOC Analyst Starter Kit v1**

**Lab 02 — Suspicious PowerShell Investigation Report**
