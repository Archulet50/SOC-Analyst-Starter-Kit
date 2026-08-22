# Lab 10 — Detection Alert

## Alert Summary

**Alert:** Multi-Stage Windows Discovery from PowerShell

**Severity:** Medium

**Host:** `MATTS-VAIO`

**Account:** `MATTS-VAIO\Matt Archuleta`

**Detection Window:** August 22, 2026 — 15:42:32 through 15:43:05

**Status:** Investigation Required

## Trigger

Multiple Windows discovery processes were observed from a common PowerShell parent within a short time window.

Observed behaviors:

- Identity discovery — `whoami.exe`
- Host discovery — `HOSTNAME.EXE`
- Group and privilege discovery — `whoami.exe /groups`
- Network configuration discovery — `ipconfig.exe`

## Detection Context

All four Event ID 4688 process-creation records identified Creator PID `0x2e94` and Logon ID `0x13b3e7cc`.

The alert identifies security-relevant discovery behavior. It does not establish malicious intent.

## Required Analyst Action

Validate the process relationships, correlate supporting telemetry, establish session context, determine scope, assess ATT&CK relevance, and assign a final disposition.
