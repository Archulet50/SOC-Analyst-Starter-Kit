# Lab 06 — Windows Privileged Administrative Discovery

## SOC Analyst Starter Kit v1

**Platform:** Windows / Windows Security Auditing
**SIEM:** Splunk
**Primary Telemetry:** Windows Security Event Log
**Detection Focus:** Identity, privilege, and process correlation
**MITRE ATT&CK:** T1087 — Account Discovery

---

## 1. Objective

The objective of Lab 06 is to detect and investigate security-relevant
administrative discovery performed within a privileged Windows logon context.

The lab evaluates whether process activity can be correlated with authentication
and privilege telemetry to distinguish routine elevated execution from
higher-value administrative discovery behavior.

The behavioral sequence evaluated is:

- successful interactive authentication;
- creation of a linked privileged logon context;
- assignment of special privileges;
- elevated process execution;
- administrative discovery activity; and
- correlation of identity, privilege, and process telemetry through Windows Logon IDs.

The lab includes a benign elevated-process control to demonstrate that process
elevation alone is insufficient to classify activity as suspicious.

---

## 2. Lab Environment

The controlled Lab 06 environment consisted of:

| Component | Role |
| --- | --- |
| WINDOWS-ENDPOINT | Windows telemetry source |
| Windows Security Log | Authentication, privilege, and process telemetry |
| Event ID 4624 | Successful authentication |
| Event ID 4672 | Special privileges assigned to a new logon |
| Event ID 4688 | Process creation |
| Splunk | SIEM ingestion and correlation platform |

Windows Process Creation auditing was enabled and Event ID 4688 telemetry
included process command-line information.

The activity was generated as authorized controlled lab activity.

No accounts, group memberships, permissions, services, registry keys, or
protected system files were modified as part of the administrative-discovery test.

---

## 3. Test Sequence

### Test A — Windows Audit Baseline

Test A established the Windows Security auditing configuration and confirmed
the availability of authentication, privilege, and process-creation telemetry.

Baseline event types included:

- Event ID 4624 — Successful Logon
- Event ID 4625 — Failed Logon
- Event ID 4672 — Special Privileges Assigned to New Logon
- Event ID 4688 — New Process Created

Observed event counts during the 24-hour baseline period were:

| Event ID | Count |
| --- | ---: |
| 4624 | 216 |
| 4625 | 0 |
| 4672 | 208 |
| 4688 | 12,919 |

Process Creation auditing was enabled.
Command-line telemetry was confirmed present in Event ID 4688.

**Test A Result: BASELINE ESTABLISHED**

### Test B — Benign Elevated Process

Test B established a negative-control case demonstrating that elevated process
execution alone is insufficient to classify activity as suspicious.

An authorized elevated instance of `notepad.exe` was launched from PowerShell.

Observed process context:

| Field | Value |
| --- | --- |
| Account | analyst |
| Process | notepad.exe |
| Parent Process | powershell.exe |
| Event ID | 4688 |
| Token Elevation | TokenElevationTypeFull (2) |
| Activity Classification | Authorized benign administrative activity |

The process executed with an elevated token; however, elevation alone does not
establish malicious or security-relevant behavior.

This negative control provides a comparison point for the administrative
discovery activity generated during Test C.

**Test B Result: BENIGN CONTROL OBSERVED**

### Test C — Administrative Discovery

Test C generated authorized security-relevant administrative discovery without
modifying accounts, groups, permissions, services, registry keys, or files.

Controlled command:

```text
net.exe localgroup Administrators
```

Windows Event ID 4688 recorded the following process chain:

```text
powershell.exe
    ->
net.exe
    ->
net1.exe
```

Observed process context:

| Field | Value |
| --- | --- |
| Account | analyst |
| Primary Process | net.exe |
| Child Process | net1.exe |
| Parent Process | powershell.exe |
| Event ID | 4688 |
| Command Context | localgroup Administrators |
| Token Elevation | TokenElevationTypeFull (2) |
| System Modification | None |

Unlike the benign elevated process in Test B, Test C contains administrative
discovery behavior relevant to security monitoring.

Process name, parent-process relationships, command-line content, account
identity, and privilege context provide a higher-value detection signal than
elevation alone.

**Test C Result: AUTHORIZED SECURITY-RELEVANT DISCOVERY OBSERVED**

### Test D — Identity and Privilege Correlation

Test D correlated Windows authentication and privilege telemetry with the
elevated process activity observed during Tests B and C.

Correlation identifiers:

| Event Context | Logon Identifier |
| --- | --- |
| 4624 New Logon ID | 0x1F23C58 |
| 4624 Linked Logon ID | 0x1F23B71 |
| 4672 Logon ID | 0x1F23B71 |
| 4688 Creator Logon ID | 0x1F23B71 |

Event ID 4624 recorded an interactive Logon Type 2 session for the tested
account `analyst`.

The 4624 event created New Logon ID `0x1F23C58` and identified linked privileged
Logon ID `0x1F23B71`.

Event ID 4672 assigned special privileges to Logon ID `0x1F23B71`, including
SeSecurityPrivilege, SeTakeOwnershipPrivilege, SeBackupPrivilege,
SeRestorePrivilege, SeDebugPrivilege, and SeImpersonatePrivilege.

The Event ID 4688 records generated during Tests B and C also identified
Creator Logon ID `0x1F23B71`.

This establishes an evidence-supported correlation path:

```text
4624 Interactive Authentication
        |
        v
4624 Linked Privileged Logon ID
        |
        v
4672 Special Privileges
        |
        v
4688 Elevated Process Activity
```

The shared Logon ID allows the analyst to associate privileged process execution
with the authenticated identity and its linked privileged security context.

**Test D Result: IDENTITY-PRIVILEGE-PROCESS CORRELATION CONFIRMED**

---

## 4. Correlation Analysis

Lab 06 demonstrates why individual Windows security events should be evaluated
as components of a behavioral sequence rather than as isolated indicators.

Test B and Test C both contain elevated Event ID 4688 process activity associated
with the same account and privileged logon context.

The distinguishing factor is process and command-line behavior.

Test B produced:

```text
powershell.exe -> notepad.exe
```

Test C produced:

```text
powershell.exe -> net.exe -> net1.exe
                    |
                    +-> localgroup Administrators
```

Both sequences occurred under Creator Logon ID `0x1F23B71`, which correlates
with the privileged logon identified by Event ID 4672 and the Linked Logon ID
recorded by Event ID 4624.

The resulting detection model therefore combines:

- authenticated identity;
- privileged logon context;
- process creation;
- parent-child process relationships;
- command-line content; and
- administrative discovery behavior.

This correlation reduces reliance on elevation as a standalone signal and allows
the detection to focus on behavior with greater investigative value.

The benign Test B process should not satisfy the administrative-discovery
detection condition.

The Test C `net.exe` and `net1.exe` activity should satisfy the detection
condition when correlated with the confirmed privileged logon context.

---

## 5. Detection Condition

The Lab 06 detection condition requires both privileged-logon correlation and
security-relevant administrative discovery behavior.

A candidate process event must satisfy the following conditions:

1. The event is Windows Event ID 4688.
2. The process Logon ID matches a Logon ID observed in Event ID 4672.
3. The same Logon ID is present as a Linked Logon ID in Event ID 4624.
4. The process is `net.exe` or `net1.exe`.
5. The command line contains `localgroup Administrators`.

Conceptually:

```text
4688 process creation
+
4672 privileged Logon ID match
+
4624 Linked Logon ID match
+
net.exe or net1.exe
+
localgroup Administrators
=
privileged administrative discovery candidate
```

The benign Test B `notepad.exe` event shares the privileged logon context but
does not contain the required discovery process or command-line behavior.

Test B therefore serves as the negative control for the detection condition.

The Test C `net.exe` and `net1.exe` events contain the required process and
command-line behavior and share the correlated privileged Logon ID.

Expected validation behavior:

| Test | Expected Result | Reason |
| --- | --- | --- |
| Test B — notepad.exe | NOT DETECTED | Elevated but no administrative discovery |
| Test C — net.exe | DETECTED | Privileged context plus administrative discovery |
| Test C — net1.exe | DETECTED | Privileged context plus administrative discovery |

These results remain expected outcomes until the correlation search is executed
successfully against the ingested Lab 06 dataset in Splunk.

---

## 6. Splunk Detection

The Lab 06 Splunk correlation search is preserved as:

`evidence/LAB-06/Lab-06-Identity-Privilege-Process-Correlation.spl`

The normalized five-event validation dataset is preserved as:

`evidence/LAB-06/Lab-06-Splunk-Telemetry.csv`

The SPL performs two primary correlation operations.

First, it identifies privileged Windows logon relationships:

- Event ID 4672 supplies privileged Logon IDs;
- Event ID 4624 supplies Linked Logon IDs; and
- Event ID 4688 supplies process Logon IDs.

The search uses `eventstats` to associate these identifiers by host and user.

An Event ID 4688 process is considered privilege-correlated when its Logon ID
is present in both the observed privileged Logon IDs and linked Logon IDs.

Second, the search evaluates administrative-discovery behavior.

A discovery candidate must:

- be an Event ID 4688 process;
- execute as `net.exe` or `net1.exe`; and
- contain `localgroup Administrators` in the command line.

The final search condition requires both:

```text
privilege_correlated = 1
AND
discovery_process = 1
```

The resulting fields include timestamp, host, user, Logon ID, process name,
parent process, command line, token elevation, event type, and test stage.

Static QA of the SPL confirmed the presence of the required 4624, 4672, and
4688 correlation logic, Logon ID matching, discovery-process matching, and
final filtering condition.

The SPL artifact is protected by the derived-artifact SHA-256 manifest.

Live execution against the ingested Lab 06 dataset remains pending because the
local Splunk Free instance is temporarily search-restricted by historical
license warnings associated with the expired download-trial stack.

The active Free stack has generated no new license warnings.

---

## 7. Evidence

Lab 06 preserves both primary Windows evidence and derived detection artifacts.

### Primary Windows Evidence

The following artifacts were captured from the Windows endpoint:

- `Test-A-Windows-Audit-Baseline.txt`
- `Test-B-Benign-Elevated-Process.txt`
- `Test-C-Administrative-Discovery.txt`
- `Test-D-Identity-Privilege-Correlation.txt`

These files preserve the audit configuration, benign control, administrative
discovery activity, and identity-to-privilege correlation used by the lab.

Their integrity is recorded in:

`evidence/LAB-06/SHA256SUMS.txt`

All four primary evidence files successfully passed SHA-256 verification after
transfer into the Lab 06 repository evidence directory.

### Derived Detection Artifacts

Two additional artifacts were produced from the preserved evidence:

- `Lab-06-Splunk-Telemetry.csv` — normalized five-event Splunk dataset
- `Lab-06-Identity-Privilege-Process-Correlation.spl` — correlation detection logic

Their integrity is recorded separately in:

`evidence/LAB-06/DERIVED-SHA256SUMS.txt`

Both derived artifacts successfully passed SHA-256 verification.

Separating the manifests preserves the distinction between evidence captured
from the Windows endpoint and artifacts subsequently created for normalization,
detection engineering, and SIEM analysis.

The normalized dataset contains five events across twelve fields representing:

- one Event ID 4624 interactive authentication event;
- one Event ID 4672 special-privilege event;
- one benign Event ID 4688 `notepad.exe` event;
- one Event ID 4688 `net.exe` administrative-discovery event; and
- one Event ID 4688 `net1.exe` administrative-discovery event.

The normalized CSV was successfully ingested into Splunk using sourcetype
`lab06:windows:normalized` and host `WINDOWS-ENDPOINT`.

---

## 8. Analyst Assessment

Lab 06 demonstrates that privileged execution should not be treated as a
standalone indicator of suspicious activity.

The benign Test B and administrative-discovery Test C activity both executed
within the same correlated privileged logon context.

The security-relevant distinction was established through behavioral context:

- process identity;
- parent-child process relationships;
- command-line content;
- authenticated account;
- privileged Logon ID correlation; and
- the administrative-discovery objective of the executed command.

Test B demonstrated that an elevated `notepad.exe` process can occur within the
privileged context without satisfying the administrative-discovery condition.

Test C demonstrated the contrasting behavior through execution of `net.exe` and
`net1.exe` with the `localgroup Administrators` command context.

Test D established the supporting identity and privilege relationship by
correlating Event IDs 4624, 4672, and 4688 through Logon ID `0x1F23B71`.

From a SOC perspective, the higher-value investigative signal is therefore not
simply that an elevated process executed. The signal is the combination of
privileged identity context and security-relevant discovery behavior.

### Current Disposition

**TRUE POSITIVE — AUTHORIZED CONTROLLED ACTIVITY**

The administrative-discovery behavior was intentionally generated as part of
Lab 06 and is confirmed by the preserved Windows evidence.

This disposition describes the underlying security-relevant behavior and its
authorization status. It does not imply that the Splunk correlation search has
already completed live validation.

### Validation Status

**EVIDENCE CORRELATION: CONFIRMED**

**SPL STATIC QA: PASSED**

**SPLUNK DATA INGESTION: COMPLETED**

**LIVE SPLUNK CORRELATION SEARCH: PENDING**

Live search validation will be completed when Splunk search capability becomes
available following expiration of the historical license-warning restriction.

---

## 9. SOC Takeaways

Lab 06 produced several practical detection-engineering and SOC-analysis lessons:

1. **Privilege alone is not a sufficient detection signal.**
   The benign Test B activity demonstrated that elevated execution can occur
   without security-relevant administrative discovery.

2. **Command-line context materially improves process detection.**
   The `localgroup Administrators` argument distinguished Test C from the benign
   elevated-process control.

3. **Parent-child process relationships add behavioral context.**
   The `powershell.exe -> net.exe -> net1.exe` sequence provides substantially
   more investigative context than an isolated Event ID 4688 record.

4. **Logon IDs provide a valuable Windows correlation key.**
   Event IDs 4624, 4672, and 4688 were associated through the privileged Logon ID
   `0x1F23B71`, connecting identity, privilege assignment, and process execution.

5. **Negative controls strengthen detection validation.**
   Test B provides a known benign elevated event against which the Test C
   administrative-discovery behavior can be compared.

6. **Evidence provenance matters.**
   Primary endpoint evidence and analyst-derived detection artifacts were
   preserved separately and protected with independent SHA-256 manifests.

7. **Validation status must be reported precisely.**
   Evidence correlation and static SPL QA are complete, while live execution of
   the Splunk correlation search remains pending because of the current search
   restriction.

Lab 06 therefore demonstrates an end-to-end SOC workflow spanning telemetry
collection, evidence preservation, normalization, behavioral comparison,
identity and privilege correlation, detection engineering, SIEM ingestion,
analyst assessment, and validation tracking.
