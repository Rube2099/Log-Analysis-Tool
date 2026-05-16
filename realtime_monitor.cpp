#include <iostream>
#include <fstream>
#include <unordered_map>
#include <queue>
#include <thread>
#include <chrono>
#include <string>

#include "log_utils.h"

using namespace std;

void logBruteForce(const string& ip, const string& time, int attempts);
void logDistributed(int currentTime, int total, int unique);


void updateDistributed(const string& ip, int currentTime);
unordered_map<string, queue<int>> ipQueues;
unordered_map<string, int> lastAlertTime;
unordered_map<string, int> suspicionScore;
unordered_map<string, int> lastSlowAlert;

queue<pair<int, string>> events;
unordered_map<string, int> freq;
int lastDistributedAlert = -1;


const int WINDOW = 30;
const int THRESHOLD = 5;
const int COOLDOWN = 60;
bool DEBUG_MODE = true;

void processLogLine(const string& line) {
    if(line.find("Failed password") == string::npos)
    return;

    string ip =extractIP(line);
    string time = extractTimeStamp(line);
    int currentTime = convertTimeToSeconds(time);

    if(ip.empty() || currentTime == -1)
    return;

    queue<int>& q = ipQueues[ip];
    suspicionScore[ip]++;
    if (suspicionScore[ip] >= 5) {

    if(!lastSlowAlert.count(ip) ||
       currentTime - lastSlowAlert[ip] > COOLDOWN) {

        cout << "{"
             << "\"type\":\"slow_attack\","
             << "\"ip\":\"" << ip << "\","
             << "\"score\":" << suspicionScore[ip]
             << "}" << endl;

        lastSlowAlert[ip] = currentTime;
    }
}
    q.push(currentTime);
/*----- Brute force -----*/
    while(!q.empty() && currentTime - q.front() > WINDOW) {
        q.pop();
    }

    if(q.size() >= THRESHOLD) {
        if(!lastAlertTime.count(ip) ||
            currentTime - lastAlertTime[ip] > COOLDOWN) {
                logBruteForce(ip, time, q.size());
                lastAlertTime[ip] = currentTime;
            }
    }
    updateDistributed(ip, currentTime);

}

/*----- Log Brute force -----*/

void logBruteForce(const string& ip, const string& time, int attempts) {
    cout << "{"
         << "\"type\":\"brute_force\","
         << "\"timestamp\":\"" << time << "\","
         << "\"ip\":\"" << ip << "\","
         << "\"attempts\":" << attempts
         << "}" << endl;
}


/*----- Logs Ditributed Atteck -----*/

void logDistributed(int currentTime, int total, int unique) {
    cout << "{"
         << "\"type\":\"distributed_attack\","
         << "\"timestamp\":" << currentTime << ","
         << "\"total_attempts\":" << total << ","
         << "\"unique_ips\":" << unique
         << "}" << endl;
}

/*----- Distributed Attack function -----*/

void updateDistributed(const string& ip, int currentTime) {


    events.push({currentTime, ip});
    freq[ip]++;

    while(!events.empty() && currentTime - events.front().first > WINDOW) {

        string oldIP = events.front().second;

        freq[oldIP]--;
        if (freq[oldIP] == 0) {
            freq.erase(oldIP);
        }
        events.pop();
    }

    int totalAttempts = events.size();
    int uniqueIPs = freq.size();

    if(totalAttempts >= THRESHOLD && uniqueIPs >= 3) {
        if(lastDistributedAlert == -1 || currentTime - lastDistributedAlert > COOLDOWN) {
            logDistributed(currentTime, totalAttempts, uniqueIPs);

            lastDistributedAlert = currentTime;
            lastDistributedAlert = currentTime;
        }
    }

}
/* ----- Monitoring logs -----*/

void monitorLog(const string& filename) {

    ifstream file(filename);

    if(!file) {
        throw runtime_error("Error opening file!");
    }

    file.seekg(0, ios::end);
    string line;

    while (true) {

        if (getline(file, line)) {
            processLogLine(line);
            if (DEBUG_MODE) {
                cout << "LINE: " << line << endl;
            }
        }
        else {
            if (file.eof()) {
                file.clear();
            }
            this_thread::sleep_for(chrono::milliseconds(200));
        }
    }

}


/*----- Main -----*/

int main() {
    monitorLog("sample.log");
    return 0;
}
