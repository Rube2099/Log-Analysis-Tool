# SOC Monitoring & Incident Response Platform

A C++-based Security Operations Center (SOC) simulation platform that performs real-time log monitoring, threat detection, incident correlation, threat scoring, automated response, and case management.

## Overview

This project simulates the core workflow of a modern Security Operations Center (SOC).

The platform continuously monitors security logs, detects suspicious activities, correlates security events into incidents, prioritizes threats, generates response recommendations, and maintains incident cases for analysts.

---

## Features

### Real-Time Log Monitoring

* Continuous log processing
* Real-time event analysis

### Brute Force Detection

* Detects repeated failed login attempts
* Tracks attacker IP addresses

### Distributed Attack Detection

* Identifies coordinated attacks from multiple IPs
* Detects attack bursts within configurable time windows

### Behavioral Detection

* Detects abnormal activity patterns
* Generates behavior alerts and warnings

### Threat Intelligence

* Detects known malicious IP addresses
* Integrates threat intelligence feeds

### Threat Scoring Engine

* Dynamic risk scoring per attacker
* Severity classification:

  * LOW
  * MEDIUM
  * HIGH
  * CRITICAL

### MITRE ATT&CK Mapping

Maps detections to ATT&CK techniques:

| Detection          | Technique |
| ------------------ | --------- |
| Brute Force        | T1110     |
| Distributed Attack | T1498     |
| Known Malicious IP | T1583     |

### Incident Correlation Engine

* Correlates multiple security events
* Creates unified incidents

### IOC Database

* Stores Indicators of Compromise
* Maintains attacker intelligence

### Case Management

* Automatic case creation
* Dynamic severity updates
* Dynamic status updates

Case statuses:

* OPEN
* INVESTIGATING
* CONTAINED

### Priority Queue

* Sorts incidents by threat score
* Highlights highest-risk attackers

### Response Recommendation Engine

Generates analyst recommendations based on incident severity.

### Automated Response

For critical incidents:

* Block source IP
* Escalate incident
* Trigger containment actions

### Export Capabilities

* JSON incident export
* HTML dashboard generation

---

## Project Structure

```text
SOC-Platform/
│
├── Alert/
├── dashboard/
├── detectors/
├── ioc/
├── response/
├── case_management/
│
├── realtime_monitor.cpp
├── threat_score.cpp
├── threat_intelligence.cpp
├── mitre_mapping.cpp
│
└── incidents.json
```

## Sample Output

```text
===== INCIDENT REPORT =====

IP: 10.10.10.10

Severity: CRITICAL

Threat Score: 56

Reasons:
 - Known Malicious IP [T1583]

Recommended Actions:
 - Block source IP
 - Escalate to security team
```

---

## Dashboard

The platform generates an HTML dashboard showing:

* Threat scores
* Severity levels
* Incident summaries
* Color-coded alerts

---

## Technologies Used

* C++
* STL
* File Handling
* Data Structures
* Real-Time Processing
* Threat Intelligence Concepts
* MITRE ATT&CK Framework
* Incident Response Concepts
* SOC Operations Concepts

---

## Future Improvements

* Threat Hunting Analytics
* Email Alerting
* GeoIP Enrichment
* SIEM Integration
* REST API Support
* SOAR-style Playbooks

---

## Architecture Diagram
<img width="721" height="1311" alt="Untitled Diagram drawio (1)" src="https://github.com/user-attachments/assets/df23d852-e034-493b-a9f2-2e9d2c9acf56" />

## Screenshots

### Incident Report
<img width="601" height="712" alt="Screenshot (266)" src="https://github.com/user-attachments/assets/1d6ac521-e63b-4d63-8a6f-8659fb8846a1" />

### Case Management
<img width="272" height="814" alt="Screenshot (265)" src="https://github.com/user-attachments/assets/d941e233-6afc-4fe4-a63f-009de2cb79e4" />

### HTML Dashboard
<img width="484" height="512" alt="Screenshot (272)" src="https://github.com/user-attachments/assets/9b6de8aa-3f2a-4d1f-bc71-fd52daef3735" />




## Author

Basil Mohammed

Electrical Engineering (Electronics & Communications)

Interested in Cybersecurity, SOC Operations, Threat Detection, and Security Automation.
