# Log-Analysis-Tool
Built a C++ log analysis tool that parses authentication logs and detects potential brute-force login attempts.
# Log Analysis Tool

## Description
A C++ log analysis tool that parses authentication logs and detects potential brute-force login attempts.

The program scans log files, identifies failed login attempts, extracts attacker IP addresses, and ranks the most suspicious sources using an optimized Top-K detection approach.

---

## Features

- Parse authentication log files using C++ file streams
- Detect failed login attempts
- Extract attacker IP addresses
- Identify suspicious IPs based on attempt frequency
- Rank Top-K attackers using a Min-Heap (`priority_queue`)
- Efficient counting using `unordered_map`

---

## Technologies Used

- C++
- STL (unordered_map, vector, priority_queue)
- File handling
- Log parsing techniques

---

## How to Run

1. Compile the program:

2. Run the program:


Make sure the log file (`sample.log`) is in the same directory.

---

## Example Use Case

This tool can help detect brute-force login attempts by analyzing authentication logs and identifying suspicious IP addresses with high numbers of failed login attempts.

---
## Example Output

------> Analysis Log Report <------

IP : 192.168.1.10 ----> 2 Failed attempts
IP : 45.77.23.19 ----> 5 Failed attempts ⚠ Suspicious

---------> Top 3 suspicious IPs <---------

1. 45.77.23.19 ----> 5 attempts ⚠
2. 192.168.1.10 ----> 2 attempts
3. 172.16.0.8 ----> 1 attempts


## Future Improvements

- Add command-line arguments
- Export results to a report file
- Add time-based attack detection
- Real-time log monitoring

---

## Author

Basil Mohammed  
Electrical Engineering Student  
Interested in Cybersecurity and IoT Systems


