# Archuleta Cyber Labs
## SOC Analyst Starter Kit v1.0 — Build Tracker

**Product:** Archuleta Cyber Labs — SOC Analyst Starter Kit  
**Version:** 1.0  
**Status:** IN DEVELOPMENT

---

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
- Python security automation
- Git version control
- Lab development
- Technical documentation

---

# PHASE 2 — HANDS-ON LABS

## Lab 01 — Linux Authentication Investigation

**Status:** NOT STARTED

### Objective

Generate Linux authentication activity, ingest the security
telemetry into Splunk, identify suspicious authentication behavior,
investigate the activity, document the evidence, and map relevant
behavior to MITRE ATT&CK.

### Build Tasks

- [ ] Define learning objectives
- [ ] Identify Linux authentication log source
- [ ] Verify log permissions
- [ ] Verify Splunk input
- [ ] Generate safe authentication test events
- [ ] Confirm events reach Splunk
- [ ] Develop baseline SPL search
- [ ] Develop detection SPL
- [ ] Identify suspicious authentication activity
- [ ] Perform analyst investigation
- [ ] Identify relevant fields
- [ ] Determine severity
- [ ] Identify possible false positives
- [ ] Map detection to MITRE ATT&CK
- [ ] Capture sanitized screenshots
- [ ] Complete investigation worksheet
- [ ] Complete incident report
- [ ] Write student instructions
- [ ] Write expected-results section
- [ ] Create troubleshooting section
- [ ] Validate lab from beginning to end

---

## Lab 02 — Suspicious PowerShell Investigation

**Status:** NOT STARTED

### Objective

Generate controlled PowerShell activity on a Windows endpoint,
collect the relevant telemetry, develop a Splunk detection, and
investigate the resulting security event.

### Build Tasks

- [ ] Define learning objectives
- [ ] Configure Windows telemetry source
- [ ] Determine required Windows logging
- [ ] Verify Splunk ingestion
- [ ] Generate safe PowerShell test activity
- [ ] Locate activity in Splunk
- [ ] Develop baseline SPL search
- [ ] Develop detection SPL
- [ ] Investigate suspicious activity
- [ ] Identify relevant fields
- [ ] Determine severity
- [ ] Identify possible false positives
- [ ] Map detection to MITRE ATT&CK
- [ ] Capture sanitized screenshots
- [ ] Complete investigation worksheet
- [ ] Complete incident report
- [ ] Write student instructions
- [ ] Write expected-results section
- [ ] Create troubleshooting section
- [ ] Validate lab from beginning to end

---

## Lab 03 — Network Reconnaissance Investigation

**Status:** NOT STARTED

### Objective

Generate controlled network reconnaissance activity, collect
network telemetry, develop a detection, investigate the source,
and document the analyst's findings.

### Build Tasks

- [ ] Define learning objectives
- [ ] Establish network telemetry source
- [ ] Verify telemetry ingestion
- [ ] Establish normal network baseline
- [ ] Generate controlled reconnaissance activity
- [ ] Locate activity in Splunk
- [ ] Develop baseline SPL search
- [ ] Develop detection SPL
- [ ] Investigate reconnaissance activity
- [ ] Identify source and destination systems
- [ ] Determine severity
- [ ] Identify possible false positives
- [ ] Map detection to MITRE ATT&CK
- [ ] Capture sanitized screenshots
- [ ] Complete investigation worksheet
- [ ] Complete incident report
- [ ] Write student instructions
- [ ] Write expected-results section
- [ ] Create troubleshooting section
- [ ] Validate lab from beginning to end

---

# PHASE 3 — DETECTION ENGINEERING

## Detection Library

### Initial Detection Pack

- [ ] Linux authentication failures
- [ ] Repeated authentication failures
- [ ] Authentication failure threshold detection
- [ ] Successful login following repeated failures
- [ ] Suspicious PowerShell execution
- [ ] Encoded PowerShell activity
- [ ] Network port scanning
- [ ] Multiple destination port activity
- [ ] Privilege escalation activity
- [ ] Suspicious process execution

### Detection Documentation

Each production detection should contain:

- [ ] Detection name
- [ ] Detection objective
- [ ] Data source
- [ ] SPL query
- [ ] Detection logic explanation
- [ ] MITRE ATT&CK mapping
- [ ] Severity
- [ ] Severity rationale
- [ ] False-positive considerations
- [ ] Investigation procedure
- [ ] Remediation recommendations
- [ ] Validation procedure

---

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

---

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

---

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

---

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

---

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

---

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

---

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

---

# 30-DAY TARGET

## Week 1 — BUILD

Goal:

Establish the SOC architecture and complete the technical foundation
for the first hands-on lab.

- [x] Product workspace created
- [x] Product manifest created
- [x] Git initialized
- [x] Reference SOC documented
- [ ] Telemetry pipeline validated
- [ ] Lab 01 completed

## Week 2 — PRODUCTIZE

Goal:

Convert working technical material into professional training assets.

- [ ] Labs documented
- [ ] Templates created
- [ ] Checklists created
- [ ] Screenshots captured
- [ ] Detection pack assembled

## Week 3 — PACKAGE AND LAUNCH

Goal:

Create a product that can actually be purchased and delivered.

- [ ] Final product package
- [ ] Storefront
- [ ] Product graphics
- [ ] Product listing
- [ ] Free lead magnet
- [ ] Launch content

## Week 4 — SELL AND IMPROVE

Goal:

Validate that customers will pay for the product.

- [ ] Launch publicly
- [ ] Generate first sale
- [ ] Reach five customers
- [ ] Collect feedback
- [ ] Improve product
- [ ] Begin Version 1.1 backlog

---

# SUCCESS METRICS

## Product

- Version 1.0 completed
- Three validated hands-on SOC labs
- Ten documented detections
- Professional analyst templates
- Portfolio-building resources

## Learning

Demonstrate practical experience with:

- Linux
- Splunk
- SPL
- SIEM operations
- Detection engineering
- Incident response
- MITRE ATT&CK
- Python
- Git
- Technical documentation

## Business

Initial milestones:

- First product published
- First lead generated
- First paying customer
- First five customers
- First customer review
- First $100 in product revenue

---

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

---

# CURRENT BUILD POSITION

**Current Phase:** Phase 1 — Foundation

**Current Milestone:** Validate SOC telemetry pipeline

**Next Lab:** Lab 01 — Linux Authentication Investigation

**Next Technical Objective:**

Linux Authentication Event

↓

Security Log

↓

Splunk Input

↓

Indexed Event

↓

SPL Search

↓

Detection

↓

Investigation

↓

Incident Documentation

---

# PROJECT RULE

## BUILD → TEST → DOCUMENT → SANITIZE → PACKAGE → SELL

New ideas go into the Product Backlog.

**Version 1.0 ships before Version 2.0 begins.**
