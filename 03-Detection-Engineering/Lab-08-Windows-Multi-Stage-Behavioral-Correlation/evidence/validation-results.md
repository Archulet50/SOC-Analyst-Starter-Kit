# Lab 08 Validation Results

## Windows Multi-Stage Behavioral Correlation

Lab 08 validates a behavioral detection model using Windows Security
Event ID 4688 and PowerShell Operational Event ID 4104.

The lab evaluates multiple discovery behaviors originating from a
common PowerShell parent process and assigns a weighted behavioral score.

---

## Telemetry Baseline

Observed during the 24-hour baseline:

| Event ID | Description | Events |
|---|---|---:|
| 4624 | Successful Logon | 150 |
| 4672 | Special Privileges Assigned to New Logon | 145 |
| 4688 | Process Creation | 4128 |
| 4104 | PowerShell Script Block Logging | 122 |

The high volume of Event ID 4688 demonstrated that timestamps alone
were insufficient for reliable correlation. Process relationships,
account context, and bounded time windows were required.

---

## Validation Model

| Score | Disposition |
|---:|---|
| 0-2 | BASELINE |
| 3-4 | REVIEW |
| 5+ | INVESTIGATE |

Three controlled tests were used to validate the model.

---

## Test A — Baseline

**Marker:** `LAB08-A-BASELINE`

PowerShell Script Block Logging successfully captured the controlled
marker in Event ID 4104.

No matching `whoami.exe`, `hostname.exe`, or `ipconfig.exe` process
creation events were identified during the Test A window.

**Result:**

- Score: 0
- Disposition: BASELINE
- Discovery behaviors: None

This test established the negative control and demonstrated that ordinary
PowerShell activity alone should not trigger an investigation.
---

## Test B — Partial Correlation

**Marker:** `LAB08-B-PARTIAL`

Controlled discovery activity:

- `whoami`
- `hostname`

Event ID 4104 captured the PowerShell activity.

Event ID 4688 independently confirmed creation of:

- `C:\Windows\System32\whoami.exe`
- `C:\Windows\System32\HOSTNAME.EXE`

Both child processes shared:

- Account: `Matt Archuleta`
- Creator: `powershell.exe`
- Creator PID: `0x46ec`

Observed process sequence:

```text
powershell.exe — PID 0x46ec
    ├── whoami.exe
    └── HOSTNAME.EXE

```

**Result:**

- Score: 3
- Disposition: REVIEW
- Events: 2
- Behaviors: Identity, Host

Test B demonstrated that multiple related discovery behaviors can warrant
analyst review without automatically reaching the investigation threshold.

---

## Test C — Full Behavioral Correlation

**Marker:** `LAB08-C-FULL-CORRELATION`

Controlled discovery activity:

- `whoami`
- `hostname`
- `whoami /groups`
- `ipconfig`

PowerShell Operational Event ID 4104 captured the controlled activity.

Windows Security Event ID 4688 independently confirmed four child
processes originating from the same PowerShell parent:

```text
powershell.exe — PID 0x46ec
    ├── whoami.exe
    ├── HOSTNAME.EXE
    ├── whoami.exe /groups
    └── ipconfig.exe
```All four process-creation events shared:

- Account: `Matt Archuleta`
- Creator: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Creator PID: `0x46ec`

Observed Event ID 4688 evidence:

| Process | Process ID | Creator PID |
|---|---|---|
| `whoami.exe` | `0x30d8` | `0x46ec` |
| `HOSTNAME.EXE` | `0x4b10` | `0x46ec` |
| `whoami.exe /groups` | `0x4f0c` | `0x46ec` |
| `ipconfig.exe` | `0x820` | `0x46ec` |

The controlled session also demonstrated membership in
`BUILTIN\Administrators` and a `High Mandatory Level` integrity context.

**Result:**

- Score: 8
- Disposition: INVESTIGATE
- Events: 4
- Behaviors: Identity, Groups, Host, Network

The result demonstrates that several individually common discovery
commands become more significant when correlated by common parent
process, account, behavioral diversity, and time window.

---

## Rejected Correlation — Events 4624 and 4672

During validation, Event ID 4672 was evaluated as a potential source
of privileged-session context for the Test C discovery sequence.

Two Event ID 4672 records were observed near the test window.

The events contained:

- Account Name: `SYSTEM`
- Account Domain: `NT AUTHORITY`
- Logon ID: `0x3E7`

These records did not identify the controlled user account.

A subsequent search for Event ID 4624 associated with the controlled
user during the privilege-validation window returned no matching event.

The 4624 and 4672 events were therefore not incorporated into the
Test C correlation.

### Analyst Finding

Temporal proximity alone does not establish event correlation.

Events should not be treated as belonging to the same activity unless
supporting attributes such as account identity, Logon ID, process
relationships, session context, or other corroborating evidence agree.

Rejecting an unsupported correlation prevents unrelated operating-system
activity from artificially increasing detection confidence.

---

## Final Validation Matrix

| Test | Behaviors | Score | Disposition |
|---|---|---:|---|
| A | None | 0 | BASELINE |
| B | Identity, Host | 3 | REVIEW |
| C | Identity, Groups, Host, Network | 8 | INVESTIGATE |

The three validation cases demonstrate that the analytic can distinguish
baseline PowerShell activity from partial discovery behavior and a
higher-confidence multi-stage discovery sequence.

---

## Final Analyst Disposition

**TRUE POSITIVE — AUTHORIZED CONTROLLED ACTIVITY**

The Test C detection correctly identified the behavior generated during
the controlled Lab 08 validation exercise.

The detection identifies activity requiring investigation; it does not
claim that the observed activity is malicious without additional analyst
context and evidence.
