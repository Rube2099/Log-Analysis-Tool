#include <iostream>
#include <string>
#include <unordered_map>
#include <queue>
#include <algorithm>
#include <fstream>
#include <vector>
#include <sstream>

using namespace std;


/* ===== Function Prototypes ===== */
string extractIP(const string& line);
string extractTimeStamp(const string& line);
unordered_map<string, vector<string>> parseFailedAttempts(const string& filename);
vector<pair<string, int>> getTopK(
    const unordered_map<string, vector<string>>& failedAttempts,
    int top_k);
string classifyDanger(int attempt);
void printReport(
    const unordered_map<string, int>& failedAttempts,
    const vector<pair<string, int>>& topIPs,
    const vector<string>& distributedAttacks);

/*=== Extract time stamp */

string extractTimeStamp(const string& line) {

    stringstream ss(line);
    string month, day, time;

    if(!(ss >> month >> day >> time)) {
        return "";
    }

    return time;
}

/* ===== Parse Log File ===== */
unordered_map<string, vector<string>> parseFailedAttempts(const string& filename) {

    unordered_map<string, vector<string>> failedAttempts;
    ifstream file(filename);

    if (!file) {
        throw runtime_error("Error opening file!");
    }

    string line;
    while (getline(file, line)) {

        if (line.find("Failed password") != string::npos) {

            string ip = extractIP(line);
            string timestamp = extractTimeStamp(line);

            if (!ip.empty() && !timestamp.empty()) {
                failedAttempts[ip].push_back(timestamp);
            }
        }
    }

    file.close();
    return failedAttempts;
}

/* ===== Extract IP ===== */
string extractIP(const string& line) {

    size_t pos = line.find("from ");
    if (pos == string::npos)
        return "";

    size_t start = pos + 5;
    size_t end = line.find(" ", start);

    if (end == string::npos)
        end = line.length();

    return line.substr(start, end - start);
}

/* ===== Top K Suspicious IPs ===== */
vector<pair<string, int>> getTopK(
    const unordered_map<string, vector<string>>& failedAttempts,
    int top_k) {

    priority_queue<
        pair<int, string>,
        vector<pair<int, string>>,
        greater<pair<int, string>>
    > minHeap;

    for (const auto& entry : failedAttempts) {

        minHeap.push({ entry.second.size(), entry.first });

        if (minHeap.size() > top_k) {
            minHeap.pop();
        }
    }

    vector<pair<string, int>> topIPs;

    while (!minHeap.empty()) {
        topIPs.push_back({
            minHeap.top().second,
            minHeap.top().first
        });
        minHeap.pop();
    }

    reverse(topIPs.begin(), topIPs.end());
    return topIPs;
}

/* ===== Severity Classification ===== */
string classifyDanger(int attempt) {

    if (attempt >= 8)
        return "HIGH";

    if (attempt >= 4)
        return "MEDIUM";

    return "LOW";
}

/*===== Convert time to seconds*/
int convertTimeToSeconds(const string& time) {
    stringstream ss(time);

    int h, m, s;
    char c1, c2;

    if (!(ss >> h >> c1 >> m >> c2 >> s)) {
        return -1;
    }

    return (h * 3600) + (m * 60) + s;
}


/* ===== Detect Brute Force IPs ===== */
vector<string> detectBruteForce(
    const unordered_map<string, vector<string>>& failedAttempts,
    int threshold,
    int windowSeconds) {
    vector<string> result;
    for (const auto& entry : failedAttempts) {
        string ip = entry.first;
        const vector<string>& timestamps = entry.second;
        vector<int> times;
        // Convert timestamps to seconds
        for (const string& t : timestamps) {
            int sec = convertTimeToSeconds(t);
            if (sec != -1) {  // ignore invalid timestamps
                times.push_back(sec);
            }
        }
        if (times.empty()) continue;
        // Sort times to apply sliding window
        sort(times.begin(), times.end());
        int left = 0;
        for (size_t right = 0; right < times.size(); ++right) {
            // Shrink window if time difference exceeds windowSeconds
            while (times[right] - times[left] > windowSeconds) {
                ++left;
            }
            // Check if window contains enough attempts
            if (right - left + 1 >= threshold) {
                result.push_back(ip);
                break; // no need to check further windows for this IP
            }
        }
    }
    return result;
}

/* ===== Detect Distributed Attack =====*/

vector<string> detectDistributedAttack(
    const unordered_map<string, vector<string>>& failedAttempts,
    int attemptsThreshold,
    int ipThreshold,
    int windowSeconds
) {
    vector<string> result;
    vector<pair<int, string>> events;

    for(const auto& entry : failedAttempts) {
        string ip = entry.first;
        for(const string& t : entry.second) {
            int sec = convertTimeToSeconds(t);
            if(sec != -1) {
                events.push_back({sec, ip});
            }
        }
    }
    /*Sort events*/
    sort(events.begin(), events.end());
    /*Sliding window*/
    unordered_map<string, int> freq;
    int left = 0;

    for(size_t right = 0; right < events.size(); right++) {
        string ipRight = events[right].second;
        freq[ipRight]++;

        while (events[right].first - events[left].first > windowSeconds) {
            string ipLeft = events[left].second;
            freq[ipLeft]--;
            if(freq[ipLeft] == 0) {
                freq.erase(ipLeft);
            }
            left++;
        }
        int totalAttempts = right - left + 1;
        if (totalAttempts >= attemptsThreshold && freq.size() >= ipThreshold) {
            result.push_back(to_string(events[left].first) + "-" + to_string(events[right].first));
            break;
        }
    }

    return result;
}

/* ===== Print Report ===== */
void printReport(
    const unordered_map<string, vector<string>>& failedAttempts,
    const vector<pair<string, int>>& topIPs,
    const vector<string>& distributedAttacks) {

    cout << "\n====== SSH Log Analysis Report ======\n\n";

    for (const auto& entry : failedAttempts) {

        cout << "IP: " << entry.first
             << " | Attempts: " << entry.second.size()
             << " | Severity: "
             << classifyDanger(entry.second.size())
             << endl;
    }

    cout << "\n---- Top Suspicious IPs ----\n";

    for (size_t i = 0; i < topIPs.size(); i++) {

        cout << i + 1 << ". "
             << topIPs[i].first
             << " | Attempts: "
             << topIPs[i].second
             << " | Severity: "
             << classifyDanger(topIPs[i].second)
             << endl;
    }

    cout<<"\n ===== Distributed Attacks Detected =====\n";

    if (distributedAttacks.empty()) {
        cout<<"No distributed attacks detected.\n";
    } else {
        for(const string& attack : distributedAttacks) {
            string nice = attack;
            replace(nice.begin(), nice.end(), '-', ' ');
            cout<<"Attack window : From"<< nice <<" seconds"<<endl;
        }
    }

    cout << "\n======================================\n";
}

/* ===== Main ===== */
int main() {

    try {

        string filename = "sample.log";
        int top_k = 3;

        auto failedAttempts = parseFailedAttempts(filename);
        auto topIPs = getTopK(failedAttempts, top_k);
        auto distributedAttacks = detectDistributedAttack(failedAttempts, 10, 3, 30);
        printReport(failedAttempts, topIPs, distributedAttacks);

        vector<string> bruteForceIPs = detectBruteForce(failedAttempts, 5, 30);
        if (!bruteForceIPs.empty()) {
            cout << "\n===== Brute Force Attackers (>=5 attempts in 30 sec) =====\n";
            for (const string& ip : bruteForceIPs) {
                cout << ip << endl;
            }
            cout << "=============================================\n";
        } else {
            cout << "\n-----No brute force patterns detected.-----\n";
        }

    }
    catch (const exception& e) {

        cout << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}