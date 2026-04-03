# 🔐 SSH Log Analyzer & Brute Force Detector

A lightweight C++ tool that analyzes SSH authentication logs to identify suspicious and malicious login attempts.  
Its core feature includes efficient brute-force detection using a sliding window algorithm to flag repeated failed logins from the same IP

---

## Features

- **SSH Log Parsing**  
  Parses authentication logs (e.g., `/var/log/auth.log`) to extract key fields such as IP address, timestamp, and login status.
  
- **Brute Force Detection**  
  Detects brute-force attacks by identifying repeated failed login attempts from the same IP within a configurable time window using a sliding window algorithm.

- **Top-K Attackers Identification**  
  Ranks the most suspicious IP addresses based on failed attempts using a Min Heap approach.

- **Event Classification**  
  Classifies login activity into categories with severity levels (LOW / MEDIUM / HIGH).

- **Modular & Efficient Design**  
  Built with clean, modular C++ code using efficient data structures and algorithms.

---

## 📸 Sample Output

<img width="1151" height="743" alt="Output" src="https://github.com/user-attachments/assets/7afa2cf4-9db6-4a74-bf3f-ab4c164cc3a5" />


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


