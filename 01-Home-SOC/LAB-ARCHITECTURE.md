# Archuleta Cyber Labs
## SOC Analyst Starter Kit v1.0

# Reference SOC Lab Architecture

## Purpose

This document describes the reference Security Operations Center
(SOC) lab used to develop and validate the exercises included in
the SOC Analyst Starter Kit.

The reference environment is not a mandatory hardware configuration.
Students may reproduce the labs using physical systems, virtual
machines, or a combination of both.

---

## Reference SOC Workstation

### Hardware

System:
ASUS Zenbook 14 UM3406KA

Architecture:
x86-64

Memory:
30 GiB RAM

Storage:
Approximately 1 TB NVMe SSD

Swap:
8 GiB

---

## Operating System

Ubuntu 24.04.4 LTS

Linux Kernel:
7.0.0-28-generic

---

## Security Operations Software

### Splunk Enterprise

Installation path:

/opt/splunk

Status during validation:

splunkd running

Purpose:

- Security log ingestion
- Event searching
- Detection engineering
- Alert development
- Dashboard creation
- Security investigations

---

## Python

Python Version:

3.12.3

Purpose:

- Security automation
- Log analysis
- Detection scripting
- Event generation
- Supporting SOC utilities

---

## Network

Primary reference network:

192.168.1.0/24

Reference SOC workstation:

192.168.1.149

Connection:

Ethernet

NOTE:

IP addresses shown in training materials may use sanitized or
example addresses rather than production/home network addresses.

---

## SOC Workflow

Security telemetry
        |
        v
Log source / endpoint
        |
        v
Splunk Enterprise
        |
        v
SPL detection
        |
        v
Alert / suspicious event
        |
        v
SOC analyst investigation
        |
        v
Evidence collection
        |
        v
Incident documentation
        |
        v
MITRE ATT&CK mapping
        |
        v
Portfolio project

---

## Lab Objectives

The reference SOC environment will be used to demonstrate:

1. Security event generation
2. Log collection
3. SIEM ingestion
4. SPL searching
5. Detection engineering
6. Alert triage
7. Incident investigation
8. Evidence collection
9. Incident reporting
10. MITRE ATT&CK mapping
11. Security automation
12. Portfolio documentation

---

## Privacy and Security

Training screenshots and examples must not expose:

- Passwords
- API keys
- Authentication tokens
- Public IP addresses
- Personally identifiable information
- Machine IDs
- Boot IDs
- Private cryptographic keys
- Real customer or organizational data

Sensitive values should be sanitized before publication.

---

## Reference Architecture Status

Operating System: VERIFIED
Storage: VERIFIED
Memory: VERIFIED
Networking: VERIFIED
Splunk: VERIFIED RUNNING
Python: VERIFIED
