# Lab 04 — SSH Brute-Force Detection

## SOC Analyst Starter Kit v1

**Difficulty:** Beginner / Intermediate
**Platform:** Linux / SSH
**Primary Telemetry:** Linux Authentication Logs
**SIEM:** Splunk
**Detection Focus:** Repeated SSH Authentication Failures
**MITRE ATT&CK:** T1110 — Brute Force

---

# 1. Lab Objective

The objective of this lab is to detect and investigate repeated SSH authentication failures against a Linux system.

The lab demonstrates a complete SOC workflow:

1. Establish a normal SSH baseline.
2. Generate a single failed authentication attempt.
3. Generate repeated failed authentication attempts.
4. Generate remote threshold-crossing authentication activity.
5. Review Linux authentication telemetry.
6. Normalize authentication events for Splunk analysis.
7. Develop detection logic.
8. Evaluate detection thresholds.
9. Investigate the activity from a SOC analyst perspective.
10. Map the behavior to MITRE ATT&CK.
11. Determine severity and disposition.
12. Preserve sanitized evidence for portfolio review.

The lab emphasizes an important detection-engineering principle:

> Individual authentication failures are common. Repeated failures become meaningful when evaluated by source, destination, account, frequency, and time window.

---

# 2. Scenario

A Linux system exposes SSH on TCP port 22.

Authentication failures begin appearing in the system authentication log.

A single failure may represent:

- a mistyped password,
- an expired credential,
- an administrator error,
- a legitimate user mistake,
- or malicious activity.

Repeated authentication failures from the same source against the same destination require additional investigation.

The SOC analyst must determine whether the activity represents:

- benign user error,
- administrative testing,
- password guessing,
- scripted authentication attempts,
- or a brute-force attack.

---

# 3. Lab Architecture

The lab uses two systems on the same controlled network.

```text
+-------------------------+
| Remote Test System      |
| 192.168.1.226           |
|                         |
| SSH authentication      |
| attempts                |
+------------+------------+
             |
             | TCP/22
             |
             v
+-------------------------+
| SENTINEL                |
| 192.168.1.149           |
|                         |
| OpenSSH Server          |
| Linux auth.log          |
| Splunk telemetry        |
+------------+------------+
             |
             v
+-------------------------+
| SOC Analysis            |
|                         |
| Authentication review   |
| SPL detection logic     |
| Threshold analysis      |
| Investigation           |
| Disposition             |
+-------------------------+
```

All testing was performed in an authorized home-lab environment.

---

# 4. Lab Environment

## Target System

```text
Hostname: SENTINEL
Operating System: Linux
Service: OpenSSH
Destination Port: TCP/22
Destination IP: 192.168.1.149
```

## Remote Test Source

```text
Source IP: 192.168.1.226
Protocol: SSH
Destination: 192.168.1.149
Destination Port: 22
```

## Authentication Account

The original local account name was sanitized for repository publication.

```text
Normalized username: analyst
```

## Primary Log Source

```text
/var/log/auth.log
```

---

# 5. SSH Service Validation

Before generating authentication activity, the SSH service was validated.

The OpenSSH server was confirmed to be:

```text
Active: active (running)
```

The service was listening on TCP port 22.

Example listener state:

```text
0.0.0.0:22
[::]:22
```

This established that the target system was capable of receiving SSH authentication attempts.

---

# 6. Test Model

Lab 04 uses four progressively stronger test conditions.

| Test | Activity | Purpose |
|---|---|---|
| Test A | Pre-attack baseline | Establish normal system state |
| Test B | Single failed login | Observe isolated authentication failure |
| Test C | Repeated failed logins | Observe repeated failures and log behavior |
| Test D | Remote repeated failures | Generate threshold-relevant remote activity |

This progression demonstrates why SOC detections should distinguish isolated failures from repeated authentication behavior.

---

# 7. Test A — Pre-Attack Baseline

Before generating failed authentication activity, the target system state was recorded.

Evidence:

```text
02-Splunk-Labs/evidence/LAB-04/Test-A-PreAttack-Baseline.txt
```

The baseline provides context for later analysis and demonstrates that evidence collection began before the primary test activity.

Baseline collection is important because an analyst should understand the environment before interpreting an alert.

---

# 8. Test B — Single Failed Authentication

A controlled SSH authentication attempt was performed.

One incorrect password was entered.

The authentication log recorded activity including:

```text
pam_unix(sshd:auth): authentication failure
```

and:

```text
Failed password for analyst
```

The connection subsequently closed during pre-authentication.

Evidence:

```text
02-Splunk-Labs/evidence/LAB-04/Test-B-Single-Failed-Login.txt
```

The evidence also contains a successful authentication event captured earlier for comparison.

---

# 9. Test B Analysis

A single failed password should not automatically generate a high-severity brute-force alert.

Users mistype passwords.

Administrators may attempt an outdated credential.

Automated systems may temporarily use stale credentials.

Therefore, the analyst must evaluate authentication failures in context.

Useful dimensions include:

```text
source IP
destination IP
destination port
username
failure count
time window
successful authentication correlation
```

The Test B activity establishes the low-volume comparison case for the later tests.

---

# 10. Test C — Repeated Failed Authentication

Repeated SSH authentication failures were then generated.

Evidence:

```text
02-Splunk-Labs/evidence/LAB-04/Test-C-Repeated-Failed-Logins.txt
```

The evidence contains multiple failure indicators including:

```text
authentication failure
Failed password
message repeated
PAM 2 more authentication failures
```

The activity originated from:

```text
192.168.1.149
```

This test demonstrated repeated authentication behavior and also exposed an important Linux logging consideration.

---

# 11. Syslog Message Compression

During Test C, the log contained:

```text
message repeated 2 times
```

This is significant.

A simple count of physical log lines containing:

```text
Failed password
```

does not necessarily equal the number of actual authentication failures.

For example:

```text
Failed password for analyst ...
message repeated 2 times: [ Failed password for analyst ... ]
```

represents more authentication activity than two ordinary log lines would suggest.

The log also contained:

```text
PAM 2 more authentication failures
```

This demonstrates that raw event counting can underrepresent the underlying activity.

---

# 12. Detection Engineering Lesson

Detection logic should not assume:

```text
one log line = one authentication attempt
```

Depending on the logging implementation, repeated events may be compressed or summarized.

A production-quality detection should account for:

- repeated-message summaries,
- PAM authentication summaries,
- individual failed-password events,
- event normalization,
- source grouping,
- account grouping,
- and time-window aggregation.

This distinction is important when designing reliable SIEM detections.

---

# 13. Test D — Remote Threshold-Crossing Activity

The final test generated repeated SSH authentication failures from a separate system.

Source:

```text
192.168.1.226
```

Destination:

```text
192.168.1.149
```

Destination service:

```text
SSH / TCP 22
```

The authentication logs recorded repeated failed password activity associated with the remote source.

Evidence:

```text
02-Splunk-Labs/evidence/LAB-04/Test-D-Remote-Brute-Force.txt
```

This represents the strongest brute-force-like condition in the lab.

---

# 14. Test D Evidence

Representative sanitized evidence includes:

```text
pam_unix(sshd:auth): authentication failure
Failed password for analyst from 192.168.1.226
message repeated 2 times
PAM 2 more authentication failures
```

The evidence demonstrates:

```text
remote source
+
same destination
+
same account
+
repeated authentication failures
+
short time interval
```

That combination provides significantly stronger detection context than an isolated authentication failure.

---

# 15. Splunk Telemetry Preparation

Normalized telemetry was created for Splunk analysis.

Evidence:

```text
02-Splunk-Labs/evidence/LAB-04/Test-D-Splunk-Telemetry.csv
```

The telemetry represents the authentication activity in a structured form suitable for SIEM analysis.

Useful normalized fields include:

```text
src_ip
dest_ip
dest_port
user
action
auth_method
event_type
```

Example logical event:

```text
src_ip=192.168.1.226
dest_ip=192.168.1.149
dest_port=22
user=analyst
action=failure
auth_method=password
event_type=ssh_authentication
```

---

# 16. Why Normalize the Data?

Raw Linux authentication logs are useful for investigation, but normalized fields make detection logic easier to build and maintain.

Instead of relying entirely on text such as:

```text
Failed password for analyst from 192.168.1.226
```

a normalized event can represent the same behavior as:

```text
src_ip=192.168.1.226
dest_ip=192.168.1.149
user=analyst
action=failure
```

This allows detection logic to focus on behavior rather than a specific raw-log format.

---

# 17. Detection Concept

The primary detection concept is:

> Identify multiple failed SSH authentication attempts from the same source against the same destination and account within a defined time window.

Conceptually:

```text
IF
    authentication protocol = SSH
AND
    action = failure
AND
    same source IP
AND
    same destination IP
AND
    same user
AND
    failure count >= threshold
WITHIN
    defined time window
THEN
    generate SSH brute-force alert
```

---

# 18. Detection Threshold

For the lab, the detection model uses repeated authentication failures within a short time window.

A practical starter threshold is:

```text
5 or more failed SSH authentications
from the same source
against the same destination/account
within 5 minutes
```

This is a training threshold rather than a universal production value.

Production thresholds should be tuned using:

- environment size,
- authentication volume,
- exposed services,
- administrative behavior,
- known scanners,
- service accounts,
- historical baselines,
- and false-positive rates.

---

# 19. Basic Splunk Search

A basic raw-log search can begin with:

```spl
"Failed password"
```

A more targeted search might include SSH context:

```spl
"sshd" "Failed password"
```

If structured fields are available:

```spl
event_type=ssh_authentication action=failure
```

These searches identify candidate authentication failures but do not yet implement behavioral detection.

---

# 20. Brute-Force Detection SPL

With normalized telemetry, a detection can aggregate failures by source, destination, and account.

Example:

```spl
event_type=ssh_authentication action=failure
| bin _time span=5m
| stats count AS failed_attempts
        earliest(_time) AS first_seen
        latest(_time) AS last_seen
        BY src_ip dest_ip user _time
| where failed_attempts >= 5
| convert ctime(first_seen) ctime(last_seen)
| sort - failed_attempts
```

This converts individual authentication failures into behavioral detection logic.

---

# 21. Detection Result Interpretation

A detection result should answer:

```text
Who generated the activity?
What system was targeted?
Which account was targeted?
How many failures occurred?
Over what period?
Was there a successful login afterward?
Did the source perform other suspicious activity?
```

A failure count by itself is not enough to determine malicious intent.

The alert begins the investigation.

---

# 22. Success-After-Failure Correlation

One of the most important investigation questions is:

> Did the source successfully authenticate after the failed attempts?

A pattern such as:

```text
multiple failures
        ↓
successful authentication
```

can significantly increase concern.

Possible explanations include:

- legitimate user eventually entered the correct password,
- administrator corrected a credential,
- password guessing succeeded,
- compromised credentials were discovered.

Context determines severity.

---

# 23. Source Analysis

The analyst should investigate the source IP.

Questions include:

```text
Is the source internal or external?
Is the source known?
Is it an administrator workstation?
Is it expected to use SSH?
Has it generated other authentication alerts?
Has it performed network reconnaissance?
Has it contacted other systems?
```

For Test D:

```text
Source IP: 192.168.1.226
```

The source was an authorized lab system.

---

# 24. Destination Analysis

The destination should also be investigated.

Questions include:

```text
Is SSH expected on the system?
Is TCP/22 intentionally exposed?
Is the system production-critical?
What accounts can authenticate?
Does the system permit password authentication?
Are there additional exposed services?
```

For this lab:

```text
Destination IP: 192.168.1.149
Service: SSH
Port: TCP/22
```

SSH was intentionally enabled for controlled testing.

---

# 25. Account Analysis

The targeted account should be evaluated.

Questions include:

```text
Is the account valid?
Is it privileged?
Is it a service account?
Is it frequently targeted?
Was it successfully accessed?
Was the password changed?
Was the account locked?
```

The repository uses the sanitized username:

```text
analyst
```

to avoid publishing the original local username.

---

# 26. Reconnaissance Correlation

Authentication activity should not always be investigated in isolation.

Earlier reconnaissance followed by authentication failures can indicate an attack progression such as:

```text
Network Service Discovery
        ↓
SSH service identified
        ↓
Authentication attempts
        ↓
Potential brute force
        ↓
Potential unauthorized access
```

This makes correlation between different detection categories valuable.

Lab 03 demonstrated network reconnaissance behavior.

Lab 04 extends the workflow into authentication-focused detection.

---

# 27. MITRE ATT&CK Mapping

The primary MITRE ATT&CK technique for this lab is:

```text
T1110 — Brute Force
```

The observed behavior consists of repeated authentication attempts against an account.

Depending on the exact behavior and tooling observed in a production environment, analysts may further evaluate applicable T1110 sub-techniques.

The lab intentionally avoids claiming a more specific sub-technique without evidence supporting that classification.

---

# 28. False-Positive Considerations

Repeated SSH authentication failures are suspicious but not automatically malicious.

Possible benign explanations include:

- mistyped passwords,
- expired credentials,
- administrator testing,
- automated jobs using stale credentials,
- configuration errors,
- monitoring systems,
- vulnerability scanners,
- orchestration tools,
- scripts,
- credential rotation failures.

Detection engineering must balance sensitivity against operational noise.

---

# 29. Severity Model

A practical severity model can consider failure volume and surrounding context.

## Informational

```text
isolated failure
known user
expected source
no suspicious correlation
```

## Low

```text
small number of failures
short duration
known source
no successful compromise
```

## Medium

```text
repeated failures
same source
same destination/account
threshold reached
no confirmed compromise
```

## High

```text
large failure volume
multiple targeted accounts
multiple destinations
success after repeated failures
reconnaissance correlation
unknown or external source
```

Severity should reflect both the authentication behavior and the investigation context.

---

# 30. Analyst Investigation

For Test D, the analyst reviewed:

```text
source IP
destination IP
destination port
targeted account
authentication failure count
time window
raw authentication evidence
normalized telemetry
success-after-failure context
related reconnaissance activity
```

The activity was confirmed to originate from an authorized lab source.

No unauthorized compromise occurred.

---

# 31. Investigation Disposition

The observed behavior matched the characteristics of repeated SSH password guessing.

However, the activity was intentionally generated as part of an authorized security lab.

Therefore:

```text
Classification:
True Positive — Authorized Security Testing
```

This distinction is important.

A detection can correctly identify malicious-like behavior even when the underlying activity is authorized.

---

# 32. Evidence Inventory

The final Lab 04 evidence set contains five artifacts.

```text
02-Splunk-Labs/evidence/LAB-04/
├── Test-A-PreAttack-Baseline.txt
├── Test-B-Single-Failed-Login.txt
├── Test-C-Repeated-Failed-Logins.txt
├── Test-D-Remote-Brute-Force.txt
└── Test-D-Splunk-Telemetry.csv
```

These artifacts document the progression from baseline through remote threshold-relevant authentication activity.

---

# 33. Evidence Sanitization

Repository evidence was sanitized before publication.

Sanitization included replacing the original workstation hostname with:

```text
SENTINEL
```

and replacing the original local username with:

```text
analyst
```

The purpose is to preserve technically meaningful telemetry while reducing unnecessary publication of local system identifiers.

Private credentials are never included in the repository.

---

# 34. Evidence Integrity

Evidence integrity should be preserved using cryptographic hashes.

SHA-256 hashes allow later verification that published evidence has not changed.

The intended workflow is:

```bash
sha256sum <evidence-files> > SHA256SUMS.txt
```

and verification with:

```bash
sha256sum -c SHA256SUMS.txt
```

The integrity manifest should be generated only after the final sanitization and QA pass.

---

# 35. Detection Engineering Artifact

The detailed detection-engineering documentation for this lab is located at:

```text
03-Detection-Engineering/LAB-04-SSH-BRUTE-FORCE-DETECTION.md
```

It documents:

- detection objective,
- data sources,
- test model,
- threshold strategy,
- telemetry counting considerations,
- normalized fields,
- detection logic,
- SPL,
- severity,
- false positives,
- MITRE mapping,
- investigation questions,
- detection result,
- improvement opportunities,
- and detection maturity.

---

# 36. Incident Response Artifact

The full SOC investigation report is located at:

```text
04-Incident-Response/LAB-04-SSH-BRUTE-FORCE-INVESTIGATION-REPORT.md
```

The report documents the investigation from alert trigger through final case disposition.

It demonstrates how a SOC analyst converts technical evidence into a defensible investigation narrative.

---

# 37. SOC Triage Checklist

The operational alert checklist is located at:

```text
05-SOC-Checklists/SSH-BRUTE-FORCE-ALERT-TRIAGE.md
```

The checklist provides a repeatable workflow for:

- validating the alert,
- counting failures,
- evaluating thresholds,
- analyzing source and destination,
- analyzing accounts,
- checking success-after-failure,
- correlating reconnaissance,
- reviewing follow-on activity,
- assigning severity,
- escalating,
- considering containment,
- documenting,
- and closing the case.

---

# 38. Complete SOC Workflow

Lab 04 demonstrates the following workflow:

```text
Baseline
   ↓
Authentication Activity
   ↓
Linux Authentication Logs
   ↓
Evidence Collection
   ↓
Telemetry Normalization
   ↓
Splunk Search
   ↓
Behavioral Aggregation
   ↓
Threshold Detection
   ↓
Alert Validation
   ↓
Source Analysis
   ↓
Destination Analysis
   ↓
Account Analysis
   ↓
Success Correlation
   ↓
MITRE ATT&CK Mapping
   ↓
Severity Assessment
   ↓
Investigation
   ↓
Disposition
   ↓
Evidence Preservation
```

---

# 39. Detection Improvement Opportunities

A production implementation could improve this detection by adding:

- dynamic baselines,
- account criticality,
- asset criticality,
- privileged-account weighting,
- external/internal source classification,
- GeoIP enrichment,
- threat-intelligence enrichment,
- allowlists,
- known administrative source lists,
- success-after-failure correlation,
- multiple-account detection,
- distributed-source detection,
- lockout correlation,
- network reconnaissance correlation,
- and automated incident enrichment.

These improvements move the detection from simple counting toward contextual behavioral analytics.

---

# 40. Skills Demonstrated

Lab 04 demonstrates practical experience with:

```text
Linux authentication logs
OpenSSH
SSH troubleshooting
SOC alert triage
Authentication analysis
Log interpretation
Telemetry normalization
Splunk SPL
Threshold detection
Detection engineering
False-positive analysis
MITRE ATT&CK
Incident investigation
Evidence collection
Evidence sanitization
Evidence integrity
Git-based documentation
```

---

# 41. Analyst Lessons

## Lesson 1

One failed authentication is an event.

Repeated failures are behavior.

## Lesson 2

Raw log-line counts may not equal actual authentication attempts.

## Lesson 3

Source, destination, account, and time provide essential context.

## Lesson 4

Success after repeated failures can materially change severity.

## Lesson 5

Detection and investigation are separate processes.

A detection identifies suspicious behavior.

An investigation determines what that behavior means.

## Lesson 6

A true-positive detection does not necessarily mean unauthorized compromise.

Authorized testing can intentionally generate behavior that correctly triggers security logic.

---

# 42. Final Lab Result

Lab 04 successfully demonstrated:

```text
SSH service validation
+
controlled failed authentication
+
repeated authentication failures
+
remote authentication activity
+
Linux log collection
+
telemetry normalization
+
Splunk detection logic
+
threshold analysis
+
SOC investigation
+
MITRE ATT&CK mapping
+
documented disposition
```

The final activity was classified as:

```text
True Positive — Authorized Security Testing
```

No unauthorized compromise occurred.

---

# 43. Key Detection Principle

The central lesson from Lab 04 is:

> Authentication detections become useful when events are converted into behavior.

The strongest analytical model is not simply:

```text
Failed password
```

It is:

```text
source
+
destination
+
account
+
failure frequency
+
time window
+
authentication outcome
+
surrounding context
```

That is the difference between searching logs and performing SOC analysis.

---

# 44. Lab Completion Checklist

- [x] SSH service validated
- [x] TCP/22 listener validated
- [x] Authentication log source identified
- [x] Pre-attack baseline captured
- [x] Single failed login generated
- [x] Repeated failed logins generated
- [x] Remote authentication failures generated
- [x] Raw evidence collected
- [x] Evidence sanitized
- [x] Syslog compression behavior analyzed
- [x] Splunk telemetry prepared
- [x] Detection threshold defined
- [x] SPL detection logic documented
- [x] MITRE ATT&CK mapped
- [x] False positives evaluated
- [x] Investigation completed
- [x] Severity assessed
- [x] Final disposition documented
- [x] Detection engineering document completed
- [x] Incident investigation report completed
- [x] SOC triage checklist completed
- [ ] Final evidence integrity manifest generated
- [ ] Repository QA completed
- [ ] Git commit completed
- [ ] GitHub push completed

---

# 45. Final Status

```text
Lab: LAB-04
Title: SSH Brute-Force Detection
Status: Technical testing complete
Detection: Validated
Investigation: Complete
Disposition: True Positive — Authorized Security Testing
MITRE ATT&CK: T1110 — Brute Force
Repository publication: Pending final QA
```

---

**SOC Analyst Starter Kit v1**

**Splunk Labs — Lab 04**
