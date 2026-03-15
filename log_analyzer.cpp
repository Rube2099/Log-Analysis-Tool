#include <iostream>
#include <string>
#include <unordered_map>
#include <queue>
#include <algorithm>
#include <fstream>
#include <vector>

using namespace std;

/* ===== Function Prototypes ===== */
string extractIP(const string& line);
unordered_map<string, int> parseFailedAttempts(const string& filename);
vector<pair<string, int>> getTopK(
    const unordered_map<string, int>& failedAttempts,
    int top_k);
string classifyDanger(int attempt);
void printReport(
    const unordered_map<string, int>& failedAttempts,
    const vector<pair<string, int>>& topIPs);

/* ===== Parse Log File ===== */
unordered_map<string, int> parseFailedAttempts(const string& filename) {

    unordered_map<string, int> failedAttempts;
    ifstream file(filename);

    if (!file) {
        throw runtime_error("Error opening file!");
    }

    string line;
    while (getline(file, line)) {

        if (line.find("Failed password") != string::npos) {

            string ip = extractIP(line);
            if (!ip.empty()) {
                failedAttempts[ip]++;
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
    const unordered_map<string, int>& failedAttempts,
    int top_k) {

    priority_queue<
        pair<int, string>,
        vector<pair<int, string>>,
        greater<pair<int, string>>
    > minHeap;

    for (const auto& entry : failedAttempts) {

        minHeap.push({ entry.second, entry.first });

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

/* ===== Print Report ===== */
void printReport(
    const unordered_map<string, int>& failedAttempts,
    const vector<pair<string, int>>& topIPs) {

    cout << "\n====== SSH Log Analysis Report ======\n\n";

    for (const auto& entry : failedAttempts) {

        cout << "IP: " << entry.first
             << " | Attempts: " << entry.second
             << " | Severity: "
             << classifyDanger(entry.second)
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

    cout << "\n======================================\n";
}

/* ===== Main ===== */
int main() {

    try {

        string filename = "sample.log";
        int top_k = 3;

        auto failedAttempts = parseFailedAttempts(filename);
        auto topIPs = getTopK(failedAttempts, top_k);

        printReport(failedAttempts, topIPs);

    }
    catch (const exception& e) {

        cout << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
