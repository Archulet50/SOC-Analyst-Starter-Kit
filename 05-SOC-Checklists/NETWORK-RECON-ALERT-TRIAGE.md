# Network Reconnaissance Alert Triage Checklist

## SOC Analyst Starter Kit v1

Use this checklist when investigating suspected network reconnaissance,
port scanning, or network service discovery activity.

---

# 1. Alert Validation

- [ ] Confirm detection timestamp
- [ ] Identify source IP
- [ ] Identify destination IP
- [ ] Identify detection rule
- [ ] Review assigned severity
- [ ] Confirm network telemetry is available
- [ ] Determine the detection time window

---

# 2. Traffic Analysis

- [ ] Count unique destination ports
- [ ] Count unique destination hosts
- [ ] Review TCP flags
- [ ] Identify repeated connection attempts
- [ ] Distinguish unique connections from retransmissions
- [ ] Determine whether ports were sequential or specifically targeted
- [ ] Determine whether connections succeeded

Key question:

Does the traffic represent isolated service access or a broader
reconnaissance pattern?

---

# 3. Source Analysis

- [ ] Identify source host
- [ ] Determine source ownership
- [ ] Determine whether source is internal or external
- [ ] Identify expected role of source system
- [ ] Check whether source is an authorized scanner
- [ ] Review previous activity from source
- [ ] Determine whether source contacted additional systems

---

# 4. Destination Analysis

- [ ] Identify target system
- [ ] Determine target role
- [ ] Identify exposed services
- [ ] Compare observed ports with expected services
- [ ] Determine asset sensitivity
- [ ] Check whether additional systems were targeted

---

# 5. Reconnaissance Assessment

Evaluate:

- Number of unique ports
- Number of destination systems
- Scan duration
- Connection frequency
- Source reputation
- Expected administrative activity
- Authorized scanning windows
- Follow-on behavior

Potential reconnaissance indicators:

- Many destination ports
- Sequential port access
- Rapid connection attempts
- Multiple destination hosts
- Repeated scanning
- Unexpected source host
- Unusual service discovery

---

# 6. Correlation

Check for activity occurring before or after the scan:

- [ ] Authentication failures
- [ ] Successful logons
- [ ] PowerShell activity
- [ ] Process creation
- [ ] Web requests
- [ ] Exploitation attempts
- [ ] Malware alerts
- [ ] Firewall events
- [ ] Additional reconnaissance
- [ ] Privilege escalation
- [ ] Persistence activity

---

# 7. MITRE ATT&CK

Primary mapping:

**T1046 — Network Service Discovery**

Remember:

ATT&CK mapping describes observed behavior.

It does not establish malicious intent.

---

# 8. False-Positive Review

Determine whether activity could originate from:

- [ ] Vulnerability scanner
- [ ] Monitoring system
- [ ] Asset discovery
- [ ] IT administration
- [ ] Troubleshooting
- [ ] Security assessment
- [ ] Authorized penetration test
- [ ] Configuration validation

---

# 9. Escalation Criteria

Consider escalation when:

- Source is unknown or unauthorized
- Numerous systems are targeted
- Reconnaissance is repeated
- Sensitive assets are targeted
- Exploitation follows reconnaissance
- Credential attacks follow reconnaissance
- Malware activity is correlated
- Activity violates established policy
- Source cannot be explained through authorized operations

---

# 10. Disposition

Select the most appropriate outcome:

- [ ] True Positive — Malicious
- [ ] True Positive — Authorized Security Activity
- [ ] Benign / Authorized Activity
- [ ] False Positive
- [ ] Requires Additional Investigation

---

# 11. Documentation

Record:

- Source IP
- Destination IP
- Unique destination ports
- Unique destination hosts
- Time window
- Packet or event counts
- Evidence reviewed
- Correlated activity
- Analyst assessment
- MITRE ATT&CK mapping
- Final disposition
- Escalation decision

---

# Analyst Principle

A large packet count does not necessarily mean a large scan.

Retransmissions can generate multiple packets for a single connection attempt.

Prioritize:

**unique source + unique destination + unique destination ports + time + context**

---

**SOC Analyst Starter Kit v1**

**Network Reconnaissance Alert Triage Checklist**
