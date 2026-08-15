# Lab 07 — PowerShell Behavioral Detection

> Detection engineering with Windows Event ID 4688, PowerShell Event ID 4104, behavioral scoring, and controlled validation.

## Overview

This lab develops and validates a behavioral analytic for PowerShell execution on a Windows endpoint.

Rather than treating every instance of `powershell.exe` as malicious, the analytic assigns weighted scores to selected execution characteristics and classifies activity as:

- **BASELINE**
- **REVIEW**
- **INVESTIGATE**

The lab uses controlled benign and security-relevant PowerShell executions to validate the detection logic against real Windows telemetry.

## MITRE ATT&CK

**Technique:** T1059.001 — PowerShell  
**Category:** Command and Scripting Interpreter

## Telemetry

Two Windows telemetry sources are correlated:

| Event ID | Source | Purpose |
|---|---|---|
| 4688 | Windows Security | Process creation and command-line context |
| 4104 | PowerShell Operational | PowerShell script-block content |

Together they answer two different investigative questions:

```text
Event 4688 → How was PowerShell launched?
Event 4104 → What did PowerShell execute?
```

## Lab Architecture

```text
Windows 11 Endpoint — MATTS-VAIO
        |
        | PowerShell execution
        v
+-----------------------------+
| Windows Security Logging    |
| Event ID 4688               |
+-----------------------------+
        |
        +--------------------+
                             |
                             v
                    Behavioral Detector
                             |
                             v
                 BASELINE / REVIEW /
                     INVESTIGATE
                             ^
                             |
        +--------------------+
        |
+-----------------------------+
| PowerShell Operational Log  |
| Event ID 4104               |
+-----------------------------+
        |
        v
Script-content investigation
```

## Detection Logic

The validated analytic uses three PowerShell execution characteristics:

| Signal | Weight |
|---|---:|
| `EncodedCommand` | +3 |
| `NonInteractive` | +1 |
| `NoProfile` | +1 |

### Disposition Thresholds

| Score | Disposition |
|---:|---|
| 0–1 | BASELINE |
| 2–3 | REVIEW |
| 4+ | INVESTIGATE |

These scores are lab validation thresholds and are not intended to represent universal production risk scores.

## Test Workflow

### Test A — Logging Baseline

Validated:

- Windows Security Event ID 4688
- PowerShell Operational Event ID 4104
- Process command-line auditing

**Result: PASS**

### Test B — Benign Control

A known-good PowerShell child process was executed with:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'LAB07-BENIGN-PROCESS-001'; Get-Date"
```

Detection result:

```text
Score:       1
Signals:     NoProfile
Disposition: BASELINE
```

**Result: PASS**

### Test C — Security-Relevant Control

A safe, read-only test used:

```text
-NoProfile
-NonInteractive
-EncodedCommand
```

The encoded script performed identity and local Administrator-group discovery.

Event ID 4688 exposed the execution characteristics and encoded command line.

Event ID 4104 exposed the decoded script content.

Detection result:

```text
Score:       5
Signals:     EncodedCommand, NonInteractive, NoProfile
Disposition: INVESTIGATE
```

**Result: PASS**

### Test D — Behavioral Detection

The scoring analytic was applied to observed PowerShell Event ID 4688 telemetry.

The benign control remained **BASELINE**, while the controlled security-relevant execution was classified **INVESTIGATE**.

**Result: PASS**

### Test E — Controlled Validation

Three executions were generated to test each classification level.

| Test | Score | Signals | Expected | Result |
|---|---:|---|---|---|
| E1 | 1 | NoProfile | BASELINE | BASELINE |
| E2 | 2 | NonInteractive, NoProfile | REVIEW | REVIEW |
| E3 | 5 | EncodedCommand, NonInteractive, NoProfile | INVESTIGATE | INVESTIGATE |

```text
E1 → Score 1 → BASELINE
E2 → Score 2 → REVIEW
E3 → Score 5 → INVESTIGATE
```

**Result: PASS**

## Detection Validation Finding

Validation identified a blind spot in the original investigation query.

The initial query searched Event ID 4688 for plaintext validation markers. This successfully identified E1 and E2 but missed E3.

Why?

E3 used `EncodedCommand`, meaning its marker was contained inside Base64-encoded command-line content and was not visible as plaintext in Event ID 4688.

The query was corrected to identify the encoded execution using its behavioral characteristics and controlled test window.

The corrected query successfully classified E3 as:

```text
Score:       5
Disposition: INVESTIGATE
```

This demonstrates an important detection-engineering principle:

> Validation should challenge the assumptions made by an analytic, not simply confirm an expected result.

## 4688 + 4104 Correlation

The lab demonstrated the complementary value of process and script-block telemetry.

```text
             PowerShell Activity
                     |
          +----------+----------+
          |                     |
          v                     v
     Event ID 4688         Event ID 4104
     Process View          Script View
          |                     |
     Process name          Commands
     Parent process        Script content
     Command line          Script Block ID
     Elevation
          |                     |
          +----------+----------+
                     |
                     v
              Analyst Context
```

A process event can reveal suspicious execution characteristics without immediately revealing the underlying encoded behavior.

Script Block Logging can provide the additional content required for investigation.

## Repository Structure

```text
Lab-07-PowerShell-Behavioral-Detection/
├── README.md
├── detection/
│   └── powershell-behavioral-detection.ps1
├── docs/
│   └── analyst-findings.md
├── evidence/
│   ├── Test-D-Detection-Results.csv
│   └── Test-E-Validation-Results.csv
└── queries/
    ├── event-4104.ps1
    └── event-4688.ps1
```

## Detection Script

The reusable analytic is located at:

```text
detection/powershell-behavioral-detection.ps1
```

Example:

```powershell
.\powershell-behavioral-detection.ps1 -Minutes 30
```

The script evaluates recent PowerShell process-creation telemetry and returns:

- Timestamp
- Event ID
- Behavioral score
- Triggered signals
- Analyst disposition

## Investigation Queries

### Event ID 4688

```text
queries/event-4688.ps1
```

Retrieves PowerShell process-creation telemetry from the Windows Security log.

### Event ID 4104

```text
queries/event-4104.ps1
```

Retrieves PowerShell Script Block Logging telemetry and supports an optional search term for focused investigation.

## Evidence

Raw validation evidence is preserved in:

```text
evidence/Test-D-Detection-Results.csv
evidence/Test-E-Validation-Results.csv
```

The Test E evidence contains the final controlled validation:

```text
E1  Score 1  BASELINE
E2  Score 2  REVIEW
E3  Score 5  INVESTIGATE
```

SHA-256 hashing was used during the evidence-transfer workflow to verify artifact integrity.

## False Positive Considerations

PowerShell execution characteristics are not inherently malicious.

Legitimate sources may include:

- Administrative scripts
- Endpoint-management systems
- Software deployment
- Scheduled automation
- Configuration-management tooling
- Security products

Production detection should incorporate additional context such as:

- Parent process
- User or service account
- Host role
- Script signer
- Script path
- Network activity
- Historical baseline
- Known automation

**Security-relevant does not automatically mean malicious.**

## Limitations

This analytic intentionally evaluates only the three execution characteristics directly tested in the lab.

It does not currently score:

- Network activity
- Download behavior
- Parent-process reputation
- Execution-policy bypass
- Hidden-window execution
- Additional obfuscation
- Script signing
- File reputation
- Threat intelligence
- User or host baselines

Additional signals should be individually tested and validated before being incorporated into the scoring model.

## Skills Demonstrated

- Windows Security Event analysis
- PowerShell Script Block Logging
- Event ID 4688 investigation
- Event ID 4104 investigation
- Behavioral detection engineering
- Detection scoring
- Telemetry correlation
- Controlled positive and negative testing
- False-positive analysis
- Detection validation
- Query troubleshooting
- Evidence preservation
- SHA-256 integrity verification
- MITRE ATT&CK mapping

## Key Takeaways

1. PowerShell execution alone is not sufficient evidence of malicious activity.
2. Event ID 4688 provides valuable process and command-line context.
3. Event ID 4104 can expose PowerShell behavior hidden behind encoded execution.
4. Multiple behavioral signals provide stronger investigative context than a single indicator.
5. Controlled baseline and positive tests improve confidence in an analytic.
6. Validation can expose weaknesses in both detection logic and investigative queries.
7. Detection thresholds require environment-specific tuning before production use.

## Result

**LAB 07 — PASS**

The final analytic successfully distinguished controlled PowerShell execution across three behavioral classifications:

```text
BASELINE → REVIEW → INVESTIGATE
```

while preserving the distinction between security-relevant behavior and confirmed malicious activity.