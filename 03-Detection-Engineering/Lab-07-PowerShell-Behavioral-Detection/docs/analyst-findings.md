# Lab 07 — Analyst Findings

## PowerShell Behavioral Detection

### MITRE ATT&CK

- **Technique:** T1059.001 — PowerShell
- **Primary Telemetry:** Windows Security Event ID 4688 and PowerShell Operational Event ID 4104

---

## Executive Summary

Lab 07 evaluated whether Windows process-creation and PowerShell script-block telemetry could distinguish routine PowerShell execution from activity warranting additional analyst review.

A weighted behavioral analytic was developed using three validated PowerShell execution characteristics:

| Signal | Score |
|---|---:|
| `EncodedCommand` | +3 |
| `NonInteractive` | +1 |
| `NoProfile` | +1 |

The resulting disposition model was:

| Score | Disposition |
|---:|---|
| 0–1 | BASELINE |
| 2–3 | REVIEW |
| 4+ | INVESTIGATE |

Controlled validation produced:

- E1: Score 1 — BASELINE
- E2: Score 2 — REVIEW
- E3: Score 5 — INVESTIGATE

The lab demonstrates that PowerShell execution should be evaluated using behavioral context rather than treating the presence of `powershell.exe` alone as malicious.

**Security-relevant activity is not synonymous with malicious activity.**

---

## Test A — Logging Baseline

Before generating detection telemetry, the Windows host was validated for the logging sources required by the lab.

Confirmed telemetry included:

- PowerShell Operational Event ID 4104
- Windows Security Event ID 4688
- Process command-line auditing

This established visibility into both process creation and PowerShell script content.

**Result: PASS**

---

## Test B — Benign PowerShell Control

A known benign PowerShell child process was generated:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'LAB07-BENIGN-PROCESS-001'; Get-Date"
```

Windows Security Event ID 4688 recorded the new PowerShell process.

Observed characteristics included:

- Process: `powershell.exe`
- Parent process: `powershell.exe`
- `NoProfile`
- Elevated token
- Visible command line

The behavioral detector assigned:

```text
Score:       1
Signals:     NoProfile
Disposition: BASELINE
```

PowerShell Event ID 4104 recorded the corresponding script block:

```powershell
Write-Output 'LAB07-BENIGN-PROCESS-001'
Get-Date
```

The 4688 and 4104 events occurred at the same time and contained the same unique marker, establishing a known-good correlation baseline.

**Result: PASS**

---

## Test C — Security-Relevant PowerShell Control

A safe, read-only security-relevant PowerShell execution was generated using:

- `NoProfile`
- `NonInteractive`
- `EncodedCommand`

The encoded script performed identity and privileged-group discovery:

```powershell
Write-Output 'LAB07-SECURITY-RELEVANT-001'
whoami
Get-LocalGroupMember -Group 'Administrators' |
    Select-Object Name,ObjectClass,PrincipalSource
```

No accounts, groups, files, security controls, or persistence mechanisms were modified.

### Event ID 4688 Findings

Windows Security Event ID 4688 showed:

- New process: `powershell.exe`
- Parent process: `powershell.exe`
- Elevated token
- `-NoProfile`
- `-NonInteractive`
- `-EncodedCommand`
- Base64-encoded command-line content

The process event exposed the execution characteristics, but the underlying commands were not immediately readable from the encoded command line.

### Event ID 4104 Findings

PowerShell Script Block Logging exposed the decoded script contents:

```powershell
Write-Output 'LAB07-SECURITY-RELEVANT-001'
whoami
Get-LocalGroupMember -Group 'Administrators' |
    Select-Object Name,ObjectClass,PrincipalSource
```

This demonstrated the complementary value of the two telemetry sources:

- **4688:** How PowerShell was launched
- **4104:** What PowerShell executed

**Result: PASS**

---

## Test D — Behavioral Detection

A weighted scoring analytic was applied to recent Event ID 4688 PowerShell process-creation telemetry.

### Scoring Logic

```text
EncodedCommand = +3
NonInteractive = +1
NoProfile      = +1
```

### Disposition Logic

```text
0–1 = BASELINE
2–3 = REVIEW
4+  = INVESTIGATE
```

The benign Test B process scored:

```text
Score:       1
Signals:     NoProfile
Disposition: BASELINE
```

The security-relevant Test C process scored:

```text
Score:       5
Signals:     EncodedCommand, NonInteractive, NoProfile
Disposition: INVESTIGATE
```

The analytic distinguished the controlled security-relevant execution from the known benign control without treating all PowerShell execution as suspicious.

**Result: PASS**

---

## Test E — Detection Validation

Three controlled PowerShell executions were generated to validate the classification thresholds.

### E1 — Baseline

Execution characteristic:

```text
NoProfile
```

Result:

```text
Score:       1
Disposition: BASELINE
```

### E2 — Review

Execution characteristics:

```text
NoProfile
NonInteractive
```

Result:

```text
Score:       2
Disposition: REVIEW
```

### E3 — Investigate

Execution characteristics:

```text
NoProfile
NonInteractive
EncodedCommand
```

Result:

```text
Score:       5
Disposition: INVESTIGATE
```

### Final Validation Results

| Test | Score | Signals | Disposition |
|---|---:|---|---|
| E1 | 1 | NoProfile | BASELINE |
| E2 | 2 | NonInteractive, NoProfile | REVIEW |
| E3 | 5 | EncodedCommand, NonInteractive, NoProfile | INVESTIGATE |

**Result: PASS**

---

## Validation Blind Spot Identified

The initial Test E validation query attempted to identify all three validation events by searching Event ID 4688 for their plaintext markers.

This successfully identified E1 and E2 but failed to return E3.

The reason was significant: E3 used `EncodedCommand`, so its marker existed inside the Base64-encoded argument and was not present as plaintext in the Event ID 4688 command line.

The validation query was corrected to identify the encoded execution using its PowerShell execution characteristics and the controlled test time window.

After correction, the analytic returned:

```text
E1 → Score 1 → BASELINE
E2 → Score 2 → REVIEW
E3 → Score 5 → INVESTIGATE
```

This exposed an assumption in the original validation query and demonstrated an important detection-engineering principle:

> Validation should test the assumptions made by the analytic itself, not merely confirm an expected result.

**Result: Query blind spot identified, corrected, and successfully retested.**

---

## 4688 + 4104 Correlation

The lab demonstrated why these telemetry sources are stronger when used together.

```text
                 PowerShell Activity
                         |
             +-----------+-----------+
             |                       |
             v                       v
        Event ID 4688           Event ID 4104
        Process Context         Script Content
             |                       |
      Process name              Commands executed
      Parent process            Decoded content
      Command line              Script Block ID
      Token elevation
             |                       |
             +-----------+-----------+
                         |
                         v
                  Analyst Context
```

Event ID 4688 provides execution context.

Event ID 4104 provides visibility into the PowerShell script content.

Together they provide substantially greater investigative context than either source alone.

---

## Analyst Assessment

The presence of PowerShell alone is insufficient evidence of malicious activity.

Likewise, individual execution characteristics such as `NoProfile`, `NonInteractive`, or `EncodedCommand` should not automatically be treated as proof of compromise.

These characteristics may legitimately appear during:

- System administration
- Software deployment
- Automation
- Configuration management
- Security operations
- Maintenance scripts

However, combinations of these signals can increase investigative priority.

The stronger analytic approach is therefore to combine execution characteristics with process context, script content, host context, user context, and other available telemetry.

---

## False Positive Considerations

Potential legitimate sources of higher behavioral scores include:

- Enterprise administration scripts
- Endpoint-management systems
- Software installers
- Scheduled automation
- Security products
- Deployment frameworks

A production implementation should consider additional context such as:

- Parent process
- User or service account
- Host role
- Script signer
- Script path
- Known automation accounts
- Command content
- Network activity
- Frequency
- Historical baseline

The scores used in this lab are validation thresholds, not universal indicators of maliciousness.

---

## Limitations

The Lab 07 analytic is intentionally limited to the three PowerShell characteristics that were directly tested and validated.

It does not currently evaluate:

- Parent-process reputation
- Network connections
- Download behavior
- Execution-policy bypass
- Hidden-window execution
- Additional obfuscation patterns
- Script signing
- File reputation
- Threat intelligence
- User baselines
- Host baselines

The scoring thresholds should not be treated as production risk scores without broader testing and environment-specific tuning.

---

## Evidence

The following evidence artifacts were preserved from the lab:

```text
evidence/
├── Test-D-Detection-Results.csv
└── Test-E-Validation-Results.csv
```

The Test D evidence contains the behavioral scoring results across the observed PowerShell process-creation telemetry.

The Test E evidence contains the final three-case validation:

```text
E1  Score 1  BASELINE
E2  Score 2  REVIEW
E3  Score 5  INVESTIGATE
```

Evidence integrity was checked using SHA-256 during the VAIO-to-ASUS lab workflow.

---

## Key Takeaways

1. Event ID 4688 provides valuable PowerShell process and command-line context.

2. Event ID 4104 provides visibility into PowerShell script content and can reveal behavior hidden behind encoded command-line execution.

3. PowerShell should not be classified as malicious solely because it executed.

4. Multiple behavioral signals provide better investigative context than a single indicator.

5. Detection validation can expose blind spots in the investigation query as well as the analytic.

6. Controlled positive and negative cases improve confidence in detection logic.

7. Security-relevant activity is not synonymous with malicious activity.

---

## Conclusion

Lab 07 demonstrated a complete detection-engineering workflow:

```text
Telemetry Validation
        |
        v
Known-Good Baseline
        |
        v
Security-Relevant Simulation
        |
        v
4688 + 4104 Correlation
        |
        v
Behavioral Scoring
        |
        v
Controlled Validation
        |
        v
Blind-Spot Identification
        |
        v
Query Correction
        |
        v
Validated Detection
```

The final analytic correctly classified the controlled validation cases as **BASELINE**, **REVIEW**, and **INVESTIGATE** while maintaining the important distinction between suspicious execution characteristics and confirmed malicious activity.