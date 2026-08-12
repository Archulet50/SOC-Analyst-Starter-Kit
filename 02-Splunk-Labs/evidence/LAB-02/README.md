# Lab 02 Evidence Package

## Suspicious PowerShell Investigation

This directory contains sanitized evidence generated during Lab 02 of the
SOC Analyst Starter Kit.

## Evidence Files

### Test A — Baseline

`Test-A-Baseline-SANITIZED.txt`

Demonstrates normal PowerShell activity captured through Event ID 4104.

Marker:

`ACL-LAB02-BASELINE`

---

### Test B — Suspicious Indicators

`Test-B-Suspicious-SANITIZED.txt`

Demonstrates PowerShell telemetry containing suspicious indicators such as:

- Bypass
- Hidden
- DownloadString

The indicators were intentionally generated as harmless training strings.

Marker:

`ACL-LAB02-SUSPICIOUS`

---

### Test C — Encoded PowerShell

`Test-C-Encoded-SANITIZED.txt`

Demonstrates harmless PowerShell execution using EncodedCommand and the
resulting decoded script visibility through Event ID 4104.

Marker:

`ACL-LAB02-ENCODED`

---

### Test D — Process Creation

`Test-D-ProcessCreation-SANITIZED.txt`

Demonstrates Security Event ID 4688 with:

- PowerShell process creation
- Parent process
- Command line
- Process correlation

Marker:

`ACL-LAB02-4688`

---

## Integrity Verification

`SHA256SUMS.txt` contains SHA-256 hashes for the repository evidence files.

Verify with:

    sha256sum -c SHA256SUMS.txt

All evidence should return:

    OK

---

## Evidence Handling

The original Windows evidence was preserved separately before text encoding
conversion.

Workflow:

    Windows Evidence
          |
          v
    Sanitized Copy
          |
          v
    SHA-256 Verification
          |
          v
    Secure Transfer
          |
          v
    SHA-256 Verification
          |
          v
    UTF-16LE to UTF-8 Conversion
          |
          v
    Privacy Review
          |
          v
    Repository Evidence Package

The repository contains UTF-8 copies intended for training and portfolio use.

Machine-specific identifiers and unnecessary personal information were removed
before publication.

---

## Training Purpose

This evidence is generated entirely from controlled, authorized lab activity.

It is intended to demonstrate:

- SOC evidence collection
- PowerShell telemetry analysis
- Detection engineering
- Event correlation
- Evidence sanitization
- File integrity verification
- Investigation documentation

---

**SOC Analyst Starter Kit v1**  
**Lab 02 — Evidence Package**
