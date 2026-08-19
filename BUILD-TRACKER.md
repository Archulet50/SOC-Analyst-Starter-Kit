# Archuleta Cyber Labs
## SOC Analyst Starter Kit v1.0 — Build Tracker

**Product:** Archuleta Cyber Labs — SOC Analyst Starter Kit  
**Version:** 1.0  
**Status:** IN DEVELOPMENT

# PHASE 1 — FOUNDATION

## Product Foundation

- [x] Create product directory structure
- [x] Create product manifest
- [x] Initialize Git repository
- [x] Create development roadmap
- [x] Document SOC architecture
- [x] Inventory primary SOC system
- [x] Verify Splunk environment
- [ ] Verify security log source
- [ ] Verify Splunk log ingestion
- [ ] Establish screenshot standards
- [ ] Create product documentation standards

### Reference SOC Environment

**Primary SOC Workstation**

- ASUS Zenbook 14 UM3406KA
- Ubuntu 24.04.4 LTS
- Linux 7.0.0-28-generic
- x86-64 architecture
- 30 GiB RAM
- Approximately 1 TB NVMe SSD
- 8 GiB swap
- Ethernet networking
- Splunk Enterprise
- Python 3.12.3
- Git

### Reference SOC Functions

The primary SOC workstation currently provides:

- SIEM services
- Security log ingestion
- SPL searching
- Detection engineering
- Security monitoring
- Python security Automation
- Git version control
- Lab development
- Technical documentation

# PHASE 2 — HANDS-ON LABS

**Status:** ACTIVE — 7 LABS COMPLETED

The hands-on lab program has expanded beyond the original three-lab
Version 1.0 concept. Labs are developed through controlled activity,
telemetry collection, detection development, investigation, evidence
preservation, MITRE ATT&CK mapping, and analyst documentation.
## Lab 01 — Linux Authentication Detection

**Status:** COMPLETE

### Focus

- Linux authentication telemetry
- PAM authentication failures
- Detection severity
- Analyst triage and investigation
- MITRE ATT&CK T1110 — Brute Force
- Benign versus security-relevant disposition

## Lab 02 — Suspicious PowerShell

**Status:** COMPLETE

### Focus

- Windows PowerShell 5.1
- PowerShell Script Block Logging
- Event ID 4104
- Process Creation Event ID 4688
- Encoded PowerShell
- Parent/child process analysis
- Evidence sanitization
- SHA-256 integrity verification
- MITRE ATT&CK T1059.001 — PowerShell

## Lab 03 — Network Reconnaissance Detection

**Status:** COMPLETE

### Focus

- Nmap
- tcpdump
- PCAP analysis
- TCP SYN interpretation
- Structured network telemetry
- Multi-port reconnaissance detection
- Splunk-ready CSV generation
- MITRE ATT&CK T1046 — Network Service Discovery

### Validation Note

PCAP evidence, structured telemetry, detection logic, and investigation
were independently validated.

Historical Splunk Free licensing restrictions affected final indexed-event
validation during the original lab.

## Lab 04 — SSH Brute-Force Detection

**Status:** COMPLETE

### Focus

- Repeated SSH authentication failures
- Source/destination/account correlation
- Time-window aggregation
- Threshold-based detection
- Success-after-failure analysis
- Syslog repeated-message handling
- MITRE ATT&CK T1110 — Brute Force
- Sanitized evidence and SHA-256 verification

**Final Disposition:** TRUE POSITIVE — AUTHORIZED SECURITY TESTING

## Lab 05 — SSH Success-After-Failure Correlation

**Status:** COMPLETE

### Focus

- Repeated failed SSH authentication
- Subsequent successful authentication
- Source/destination/account correlation
- Temporal correlation
- 5-, 15-, and 30-minute detection windows
- Fail2Ban defensive-control interaction
- Splunk-oriented detection logic
- Evidence integrity verification

### Validation Result

- 4 normalized authentication failures
- 1 subsequent successful authentication
- Same source, destination, and account
- Failure-to-success interval: 18 minutes 02 seconds
- 5-minute window: NOT DETECTED
- 15-minute window: NOT DETECTED
- 30-minute window: DETECTED

**Final Disposition:** TRUE POSITIVE — AUTHORIZED CONTROLLED ACTIVITY

## Lab 06 — Windows Privileged Administrative Discovery

**Status:** COMPLETE

### Focus

- Event ID 4624 — Successful authentication
- Event ID 4672 — Special privilege assignment
- Event ID 4688 — Process creation
- Windows Logon ID correlation
- Parent/child process relationships
- Command-line behavioral context
- Benign elevated-process comparison
- Privileged administrative discovery
- MITRE ATT&CK T1087 — Account Discovery
- SHA-256 evidence verification

### Validation Result

- Interactive authentication observed
- Privileged logon context confirmed
- Special privileges correlated through Logon ID
- Benign elevated-process control preserved
- Administrative discovery activity observed
- Process ancestry confirmed
- Normalized dataset ingested into Splunk

**Final Disposition:** TRUE POSITIVE — AUTHORIZED CONTROLLED ACTIVITY

## Lab 07 — PowerShell Behavioral Detection

**Status:** COMPLETE — PUBLISHED

### Focus

- Windows Security Event ID 4688
- PowerShell Operational Event ID 4104
- Process and script-block correlation
- Encoded PowerShell analysis
- Weighted behavioral scoring
- Controlled positive and negative validation
- Detection tuning
- Investigation-query troubleshooting
- MITRE ATT&CK T1059.001 — PowerShell

### Behavioral Scoring

| Signal | Score |
|---|---:|
| `EncodedCommand` | +3 |
| `NonInteractive` | +1 |
| `NoProfile` | +1 |

### Validation Result

| Test | Score | Disposition |
|---|---:|---|
| E1 | 1 | BASELINE |
| E2 | 2 | REVIEW |
| E3 | 5 | INVESTIGATE |

Validation identified a blind spot in the original Event ID 4688
investigation query because the E3 marker existed inside Base64-encoded
command-line content rather than as plaintext.

The investigation approach was corrected and successfully retested using
Event ID 4688 process context together with Event ID 4104 script-block
content.

**Final Disposition:** TRUE POSITIVE — AUTHORIZED CONTROLLED ACTIVITY

## Hands-On Lab Milestone

**7 hands-on SOC labs completed and documented.**

Current technical progression:

```text
Telemetry Collection
        ↓
Detection Development
        ↓
Behavioral Analysis
        ↓
Event Correlation
        ↓
Controlled Validation
        ↓
Investigation
        ↓
Evidence Preservation
        ↓
Analyst Disposition
```

# PHASE 3 — DETECTION ENGINEERING

**Status:** ACTIVE

## Detection Library

### Implemented Detection Capabilities

- [x] Linux authentication failure detection
- [x] Repeated authentication failure detection
- [x] Authentication threshold analysis
- [x] Success-after-failure correlation
- [x] Suspicious PowerShell analysis
- [x] Encoded PowerShell detection
- [x] Network reconnaissance detection
- [x] Multi-destination-port analysis
- [x] Windows privileged-context correlation
- [x] Suspicious process execution analysis
- [x] Parent/child process correlation
- [x] Behavioral scoring
- [x] Multi-event telemetry correlation
- [x] Controlled detection validation
- [x] Detection tuning and blind-spot identification

## Detection Documentation Standard

Production-quality detections should contain:

- [x] Detection name
- [x] Detection objective
- [x] Required data source
- [x] Detection/query logic
- [x] Detection logic explanation
- [x] MITRE ATT&CK mapping
- [x] Severity or behavioral score
- [x] Severity rationale
- [x] False-positive considerations
- [x] Investigation procedure
- [x] Validation procedure
- [x] Analyst disposition guidance

### Detection Engineering Milestone

Lab 07 established the first explicitly weighted behavioral analytic in
the Starter Kit and demonstrated controlled validation across three
expected dispositions:

```text
BASELINE → REVIEW → INVESTIGATE
```

The lab also demonstrated an important engineering principle:

**A detection is not complete merely because it fires. Its investigation
logic must also be tested against the telemetry representation actually
available to the analyst.**

# PHASE 4 — INCIDENT RESPONSE TOOLS

## Analyst Templates

- [ ] SOC daily checklist
- [ ] Alert triage checklist
- [ ] Investigation checklist
- [ ] Investigation worksheet
- [ ] Incident report template
- [ ] Evidence log
- [ ] Incident timeline
- [ ] Escalation worksheet
- [ ] Detection engineering template
- [ ] MITRE ATT&CK mapping worksheet

## Incident Workflow

Develop and document:

EVENT

↓

DETECTION

↓

TRIAGE

↓

INVESTIGATION

↓

EVIDENCE COLLECTION

↓

SEVERITY ASSESSMENT

↓

MITRE ATT&CK MAPPING

↓

RESPONSE / ESCALATION

↓

INCIDENT DOCUMENTATION

↓

LESSONS LEARNED

# PHASE 5 — SOC CHECKLISTS

Create concise operational references for:

- [ ] Beginning-of-shift SOC checklist
- [ ] Alert triage checklist
- [ ] Authentication investigation checklist
- [ ] Endpoint investigation checklist
- [ ] Network investigation checklist
- [ ] Evidence handling checklist
- [ ] Incident escalation checklist
- [ ] End-of-shift SOC checklist
- [ ] Analyst shift-handoff checklist

# PHASE 6 — PORTFOLIO BUILDER

## GitHub

- [ ] Create student GitHub project structure
- [ ] Create cybersecurity project README template
- [ ] Create lab documentation template
- [ ] Create detection documentation template
- [ ] Create incident investigation case-study template
- [ ] Create screenshot guidance
- [ ] Create repository sanitation checklist

## Resume

- [ ] Create technical-project resume guide
- [ ] Create SOC analyst resume bullets
- [ ] Create detection engineering resume bullets
- [ ] Create Splunk resume bullets
- [ ] Create incident response resume bullets
- [ ] Explain how to distinguish lab experience from employment

## LinkedIn

- [ ] Create project-post template
- [ ] Create lab-completion post template
- [ ] Create detection-engineering post template
- [ ] Create portfolio presentation guide

## Interview Preparation

- [ ] Create SOC lab interview talking points
- [ ] Create technical walkthrough framework
- [ ] Create STAR-story template
- [ ] Create detection explanation framework
- [ ] Create incident investigation explanation framework

# PHASE 7 — PRODUCT DOCUMENTATION

## Start Here

- [ ] Welcome document
- [ ] Product overview
- [ ] Learning roadmap
- [ ] Lab prerequisites
- [ ] Installation requirements
- [ ] Product directory guide
- [ ] How to use the labs
- [ ] Troubleshooting guidance

## Technical Documentation

- [x] Reference SOC architecture
- [x] Reference hardware inventory
- [x] Student lab prerequisites
- [ ] Network architecture
- [ ] Splunk architecture
- [ ] Data pipeline architecture
- [ ] Screenshot standards
- [ ] Privacy and sanitation standards

# PHASE 8 — QUALITY ASSURANCE

Every lab must be tested before release.

## Technical QA

- [ ] Commands tested
- [ ] SPL queries tested
- [ ] Expected output verified
- [ ] Screenshots verified
- [ ] MITRE ATT&CK mappings verified
- [ ] Links verified
- [ ] Instructions reproduced from clean starting point

## Security QA

Verify that published material contains no:

- [ ] Passwords
- [ ] API keys
- [ ] Authentication tokens
- [ ] Private keys
- [ ] Machine IDs
- [ ] Boot IDs
- [ ] Public IP addresses
- [ ] Personally identifiable information
- [ ] Sensitive home-network information
- [ ] Real customer data

## Editorial QA

- [ ] Grammar reviewed
- [ ] Terminology consistent
- [ ] Formatting consistent
- [ ] Commands clearly separated
- [ ] Beginner explanations included
- [ ] Expected results included
- [ ] Troubleshooting included

# PHASE 9 — FINAL PRODUCT

## Packaging

- [ ] Final START HERE guide
- [ ] Final product README
- [ ] Export documentation to PDF
- [ ] Package editable templates
- [ ] Package detection files
- [ ] Package SPL examples
- [ ] Organize screenshots
- [ ] Create final ZIP distribution
- [ ] Test ZIP extraction
- [ ] Test product on clean system
- [ ] Generate checksums
- [ ] Assign version number
- [ ] Create release notes

## Version 1.0

- [ ] Release candidate created
- [ ] Release candidate tested
- [ ] Final corrections completed
- [ ] Version 1.0 approved
- [ ] Version 1.0 packaged

# PHASE 10 — BUSINESS LAUNCH

## Product Positioning

- [ ] Finalize product name
- [ ] Finalize tagline
- [ ] Define target customer
- [ ] Define customer problem
- [ ] Define product promise
- [ ] Write product description
- [ ] Determine launch price
- [ ] Determine regular price

## Storefront

- [ ] Select storefront platform
- [ ] Create seller account
- [ ] Create product listing
- [ ] Upload product
- [ ] Configure payment processing
- [ ] Configure digital delivery
- [ ] Create refund/support policy
- [ ] Test purchase workflow

## Marketing Assets

- [ ] Product cover
- [ ] Product screenshots
- [ ] Product feature graphic
- [ ] LinkedIn launch announcement
- [ ] LinkedIn technical posts
- [ ] GitHub companion repository
- [ ] Free lead magnet
- [ ] Product call-to-action

## Launch

- [ ] Soft launch
- [ ] First visitor
- [ ] First lead
- [ ] First customer
- [ ] First $1 earned
- [ ] First 5 customers
- [ ] First customer feedback
- [ ] First product review
- [ ] Version 1.1 improvement list

# 30-DAY TARGET

The original 30-day build plan has progressed substantially beyond the
initial technical target. Seven hands-on SOC labs are now complete.

## Week 1 — BUILD

**Status:** COMPLETE

Goal:

Establish the SOC architecture and complete the technical foundation.

- [x] Product workspace created
- [x] Product manifest created
- [x] Git initialized
- [x] Reference SOC documented
- [x] Telemetry pipeline established
- [x] Initial hands-on lab completed

## Week 2 — PRODUCTIZE

**Status:** ACTIVE

Goal:

Convert working technical material into professional portfolio and
training assets.

- [x] Hands-on labs documented
- [x] Detection engineering documentation established
- [x] Incident-response documentation established
- [x] SOC checklist structure established
- [x] Evidence-handling workflow established
- [x] SHA-256 integrity workflow established
- [x] GitHub portfolio structure established
- [ ] Complete reusable template package
- [ ] Complete screenshot package
- [ ] Assemble Version 1.0 detection pack

## Week 3 — PACKAGE AND LAUNCH

**Status:** PENDING

Goal:

Create a polished Version 1.0 package that can be distributed and
presented professionally.

- [ ] Final product package
- [ ] Final documentation review
- [ ] Product graphics
- [ ] Product listing
- [ ] Free lead magnet
- [ ] Launch content
- [ ] Storefront

## Week 4 — SELL AND IMPROVE

**Status:** PENDING

Goal:

Validate the product with real users and use feedback to guide Version
1.1.

- [ ] Launch publicly
- [ ] Generate first sale
- [ ] Reach five customers
- [ ] Collect feedback
- [ ] Improve product
- [ ] Begin Version 1.1 backlog

# SUCCESS METRICS

## Product

Current technical milestone:

- [x] Seven hands-on SOC labs completed
- [x] Linux and Windows telemetry represented
- [x] Network telemetry represented
- [x] Detection engineering workflow demonstrated
- [x] Incident investigation workflow demonstrated
- [x] MITRE ATT&CK mapping demonstrated
- [x] Evidence integrity verification demonstrated
- [x] Behavioral detection scoring demonstrated
- [x] Multi-event correlation demonstrated
- [x] Git/GitHub publication workflow demonstrated
- [ ] Version 1.0 product package completed
- [ ] Reusable analyst template package completed
- [ ] Final detection pack assembled
- [ ] Portfolio packaging completed

## Learning

Demonstrated practical experience with:

- Linux
- Windows
- Splunk
- SPL
- SIEM operations
- Windows Security Event telemetry
- PowerShell Script Block Logging
- SSH authentication telemetry
- Network packet analysis
- PCAP analysis
- Detection engineering
- Behavioral scoring
- Event correlation
- Detection validation
- Detection tuning
- Incident response
- Analyst triage
- MITRE ATT&CK
- Evidence handling
- SHA-256 integrity verification
- Git
- GitHub
- Technical documentation

## Business

Initial milestones:

- [ ] Version 1.0 packaged
- [ ] First product published
- [ ] First lead generated
- [ ] First paying customer
- [ ] First five customers
- [ ] First customer review
- [ ] First $100 in product revenue

# PRODUCT BACKLOG

These ideas are intentionally NOT part of Version 1.0.

Do not interrupt Version 1.0 development to build them.

## Cybersecurity Products

- Advanced Splunk Detection Pack
- SOC Analyst Starter Kit Pro
- SOC Analyst video course
- Advanced Detection Engineering Lab
- Python for SOC Analysts
- Security Automation Toolkit
- Cybersecurity Command Center
- Small Business Cybersecurity Toolkit
- GRC Starter Toolkit
- AI-Assisted SOC Workflow

## Career Products

- Veteran-to-Cybersecurity Guide
- Cybersecurity Career Transition Toolkit
- SOC Interview Preparation Kit
- Cybersecurity Portfolio Builder
- Military Experience Translation Guide

## Aviation Products

- Aircraft Maintenance Leadership Toolkit
- Aircraft Maintenance KPI Dashboard
- Maintenance Shift Turnover Toolkit
- Maintenance Training Tracker
- Aircraft Maintenance Root Cause Analysis Toolkit
- Aviation Cybersecurity Course

## Future Business Opportunities

- Cybersecurity consulting
- Small-business security assessments
- Cybersecurity training
- Splunk consulting
- Security documentation services
- Automation consulting
- Rural small-business technology consulting
- Aviation cybersecurity consulting

# CURRENT BUILD POSITION

**Current Phase:** Phase 2 / Phase 3 — Hands-On Labs and Detection Engineering

**Technical Milestone:** Labs 01–07 completed and documented

**Latest Completed Lab:** Lab 07 — PowerShell Behavioral Detection

**Latest Published Milestone:** Lab 07 detection artifacts and root repository documentation

**Next Lab:** Lab 08 — Detection Engineering Expansion

**Productization Status:** ACTIVE

**Next Technical Objective:**

```text
Existing Detection Capability
        ↓
Select Lab 08 Detection Objective
        ↓
Define Required Telemetry
        ↓
Establish Baseline
        ↓
Generate Controlled Activity
        ↓
Develop Detection Logic
        ↓
Validate Positive and Negative Cases
        ↓
Investigate Alert Context
        ↓
Tune Detection
        ↓
Preserve Evidence
        ↓
Document Analyst Findings
        ↓
Publish
```
---

# PROJECT RULE

## BUILD → TEST → DOCUMENT → SANITIZE → PACKAGE → SELL

New ideas go into the Product Backlog.

**Version 1.0 ships before Version 2.0 begins.**
