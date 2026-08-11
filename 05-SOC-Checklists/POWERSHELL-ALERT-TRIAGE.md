# PowerShell Alert Triage Checklist

## SOC Analyst Starter Kit v1

Use this checklist when investigating suspicious PowerShell activity.

Primary telemetry:

- Event ID 4104 — PowerShell Script Block Logging
- Event ID 4688 — Windows Process Creation

MITRE ATT&CK:

T1059.001 — PowerShell

---

# 1. Alert Validation

- [ ] Confirm detection timestamp
- [ ] Confirm affected endpoint
- [ ] Identify affected user or service account
- [ ] Confirm PowerShell activity occurred
- [ ] Review assigned alert severity
- [ ] Identify the rule or indicator that triggered
- [ ] Determine whether the activity is still occurring
- [ ] Preserve relevant evidence

---

# 2. Script Block Review

Review:

Event ID 4104

Determine:

- [ ] What script block executed?
- [ ] Is the complete script visible?
- [ ] What commands were actually executed?
- [ ] Is the script encoded or obfuscated?
- [ ] Are suspicious keywords present?
- [ ] Do those keywords represent actual behavior?
- [ ] Is Invoke-Expression or IEX present?
- [ ] Is network retrieval present?
- [ ] Is execution-policy bypass present?
- [ ] Is hidden execution present?
- [ ] Does the script create or modify files?
- [ ] Does the script launch another process?

Key question:

Do not ask only:

Does this LOOK suspicious?

Also determine:

What did the script ACTUALLY DO?

---

# 3. Process Creation Review

Review:

Event ID 4688

Determine:

- [ ] What process was created?
- [ ] What process created it?
- [ ] What command line was used?
- [ ] Which account launched the process?
- [ ] Was the process elevated?
- [ ] What was the new process ID?
- [ ] What was the creator process ID?
- [ ] Was PowerShell launched by another PowerShell process?
- [ ] Was PowerShell launched by an unusual parent?
- [ ] Is the parent/child relationship expected?
- [ ] Were additional child processes created?

Review the process chain:

Parent Process
      |
      v
PowerShell
      |
      v
Child Process
      |
      v
Follow-On Activity

---

# 4. Encoded PowerShell Review

If encoded execution is identified:

- [ ] Identify EncodedCommand or -enc usage
- [ ] Preserve the encoded command when appropriate
- [ ] Determine whether decoded content is available
- [ ] Review Event ID 4104 for processed script content
- [ ] Identify the actual decoded behavior
- [ ] Determine whether the script accesses the network
- [ ] Determine whether additional payloads execute
- [ ] Identify follow-on processes
- [ ] Determine whether encoding has a legitimate explanation

Remember:

Encoded Execution
       !=
Malicious Payload

Encoding increases investigative interest.

Decoded behavior determines what actually executed.

---

# 5. Indicator Review

Check for indicators such as:

- [ ] EncodedCommand
- [ ] -enc
- [ ] Bypass
- [ ] Hidden
- [ ] DownloadString
- [ ] Invoke-WebRequest
- [ ] Invoke-Expression
- [ ] IEX
- [ ] Base64 content
- [ ] Obfuscated strings
- [ ] Suspicious URLs or domains
- [ ] Unexpected file paths

Important:

Indicator Present
       !=
Behavior Confirmed
       !=
Malicious Intent

---

# 6. User and Host Context

Determine:

- [ ] Which user executed PowerShell?
- [ ] Is PowerShell normal for this user?
- [ ] Does the user perform administrative work?
- [ ] Was the activity expected?
- [ ] Was the session interactive?
- [ ] Was the process elevated?
- [ ] Is the account privileged?
- [ ] Is the endpoint an administrative workstation?
- [ ] Is the endpoint a server or user workstation?
- [ ] Does the activity match the normal role of the host?

---
# 7. Network Activity Review

Determine whether PowerShell:

- [ ] Contacted an external host
- [ ] Contacted an unusual internal host
- [ ] Downloaded content
- [ ] Uploaded content
- [ ] Resolved suspicious domains
- [ ] Opened unexpected network connections
- [ ] Connected to an address not normally associated with the endpoint

If network telemetry is unavailable:

- [ ] Document the visibility limitation
- [ ] Do not assume absence of network activity

---

# 8. File and Registry Activity

Determine whether PowerShell:

- [ ] Created a file
- [ ] Modified a file
- [ ] Deleted a file
- [ ] Wrote to a temporary directory
- [ ] Wrote to a startup location
- [ ] Modified registry values
- [ ] Changed persistence-related registry locations
- [ ] Created or modified scheduled tasks
- [ ] Dropped executable or script content

If this telemetry is unavailable:

- [ ] Document the visibility limitation

---

# 9. Telemetry Correlation

Where available, correlate:

- [ ] Event ID 4104
- [ ] Event ID 4688
- [ ] Sysmon process telemetry
- [ ] Network telemetry
- [ ] DNS telemetry
- [ ] Authentication activity
- [ ] File events
- [ ] Registry activity
- [ ] Endpoint alerts
- [ ] Threat-intelligence findings

Preferred correlation model:

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
      +
Additional Endpoint Telemetry
      |
      v
Higher-Confidence Investigation

---

# 10. Severity Assessment

## Informational

Examples:

- Normal PowerShell activity
- Expected administrative commands
- No suspicious indicators
- No unusual process lineage

## Low

Examples:

- Weak indicator
- Expected user context
- No corroborating suspicious telemetry

## Medium

Examples:

- Encoded PowerShell
- Multiple suspicious indicators
- Unusual parent process
- Unexpected elevation
- Activity requiring analyst review

## High

Examples:

- Multiple high-risk behaviors
- Network retrieval plus execution
- Suspicious child processes
- Credential-access indicators
- Persistence behavior
- Strong corroborating telemetry

Important:

Severity prioritizes investigation.

Severity does not establish malicious intent.

---

# 11. Analyst Disposition

Choose one:

- [ ] Benign / Authorized Activity
- [ ] Expected Administrative Activity
- [ ] False Positive
- [ ] Suspicious — Continue Investigation
- [ ] True Positive — Security Incident
- [ ] Escalate to Tier 2
- [ ] Escalate to Incident Response

---

# 12. Escalation Considerations

Consider escalation when:

- [ ] Malicious behavior is confirmed
- [ ] Suspicious network activity is present
- [ ] Unauthorized execution is identified
- [ ] Credential access is suspected
- [ ] Persistence behavior is identified
- [ ] Multiple systems appear affected
- [ ] A privileged account is involved
- [ ] The analyst lacks sufficient visibility to safely close the case
- [ ] Organizational policy requires escalation

---

# 13. Documentation Requirements

Record:

- [ ] Detection timestamp
- [ ] Affected endpoint
- [ ] Affected user or service account
- [ ] Event ID 4104 evidence
- [ ] Event ID 4688 evidence
- [ ] Relevant script block
- [ ] Relevant command line
- [ ] Parent process
- [ ] Child process
- [ ] Elevation information
- [ ] Decoded script contents when available
- [ ] Network findings
- [ ] File or registry findings
- [ ] Investigation steps
- [ ] Final disposition
- [ ] Disposition rationale
- [ ] Escalation decision
- [ ] Visibility limitations

---

# 14. Evidence Handling

Preserve relevant evidence before modifying or closing the case.

For training and portfolio use:

- [ ] Sanitize usernames when unnecessary
- [ ] Sanitize hostnames when unnecessary
- [ ] Remove security identifiers when unnecessary
- [ ] Remove credentials
- [ ] Remove authentication tokens
- [ ] Remove sensitive network information
- [ ] Remove customer or organizational data
- [ ] Confirm screenshots contain no secrets

---

# 15. Lab 02 Validation Checklist

- [x] Windows PowerShell 5.1 verified
- [x] PowerShell Operational log verified
- [x] Script Block Logging enabled
- [x] Event ID 4104 validated
- [x] Baseline PowerShell event generated
- [x] Suspicious-indicator event generated
- [x] Encoded PowerShell event generated
- [x] Decoded script content observed
- [x] Process Creation auditing enabled
- [x] Event ID 4688 validated
- [x] Command-line capture validated
- [x] Parent/child process visibility validated
- [x] PowerShell process correlation demonstrated

---

# 16. Analyst Workflow

PowerShell Alert
       |
       v
Validate Event
       |
       v
Review Script Block
       |
       v
Review Process Creation
       |
       v
Review Command Line
       |
       v
Review Parent Process
       |
       v
Add User and Host Context
       |
       v
Correlate Additional Telemetry
       |
       v
Determine Actual Behavior
       |
       v
Assess Risk
       |
       v
Assign Disposition
       |
       v
Document Findings

---

# 17. Key Analyst Questions

Ask:

What actually executed?

What did it do?

Who executed it?

What launched it?

Was it elevated?

Did it contact the network?

Did it create files or processes?

What happened afterward?

Is the activity expected?

What evidence supports the conclusion?

---

# 18. Key Principle

Do not conclude:

Suspicious PowerShell
       =
Attack

Instead:

PowerShell Activity
       |
       v
Telemetry
       |
       v
Detection
       |
       v
Investigation
       |
       v
Correlation
       |
       v
Context
       |
       v
Evidence-Based Disposition

---

**SOC Analyst Starter Kit v1**

**PowerShell Alert Triage Checklist**
