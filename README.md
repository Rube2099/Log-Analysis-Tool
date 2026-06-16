# 🔐 SSH Log Analyzer & Brute Force Detector

A lightweight C++ security tool that analyzes SSH authentication logs to identify suspicious and malicious login attempts.
Originally designed for efficient brute-force detection, the project has now evolved into a mini SIEM-style monitoring system with advanced threat analysis.

---

✅ Core Features
SSH Log Parsing
Parses authentication logs (e.g., /var/log/auth.log) to extract IPs, timestamps, and login status.

Brute Force Detection
Identifies repeated failed login attempts from the same IP using a sliding window algorithm.

Top-K Attackers
Ranks suspicious IPs with a Min Heap approach.

Event Classification
Categorizes login activity into severity levels: LOW / MEDIUM / HIGH.

Behavioral Analysis Engine
Suspicion score tracking per IP

Dynamic risk levels (LOW → MEDIUM → HIGH)

Score decay based on inactivity

Threat Intelligence Integration
Detects blacklisted IPs

Enriches threat scores for known malicious sources

Threat Scoring System
Aggregates evidence from multiple detectors to generate overall threat levels:
LOW / MEDIUM / HIGH / CRITICAL

Distributed Attack Detection
Flags suspicious activity across multiple IPs within a time window.

Alert Management
Tracks alert statistics

Generates summaries

Reports top attackers

Threat Dashboard
Displays the most dangerous IPs and ranks threats by accumulated scores and severity.

---

## 📸 Sample Output

<img width="1680" height="990" alt="Screenshot (256)" src="https://github.com/user-attachments/assets/2f0670c9-6630-4697-b639-dda7142965a8" />

## Technologies Used

Language
C++

Key Data Structures
-unordered_map<string, vector<time_t>>
-deque
-priority_queue

---

## How to Run

1. Compile the program:

2. Run the program:


Make sure the log file (`sample.log`) is in the same directory.

---

## Example Use Case

This tool can help detect brute-force login attempts by analyzing authentication logs and identifying suspicious IP addresses with high numbers of failed login attempts.

---


## Future Improvements

-Real-time log monitoring

-Detect distributed attacks (multiple IPs)

-Visualization dashboard

---

## Author

Basil Mohammed
Electrical & Electronics Engineering Student | Cybersecurity Enthusiast


