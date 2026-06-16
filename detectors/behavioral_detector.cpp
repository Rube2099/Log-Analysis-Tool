#include "behavioral_detector.h"
#include "../Alert/alerts.h"
#include <unordered_map>
#include "../threat_score.h"
#include <iostream>


using namespace std;

unordered_map<string, int> suspicionScore;
unordered_map<string, int> lastSeenTime;
unordered_map<string, int> lastSlowAlert;
unordered_map<string, string> lastRiskLevel;
unordered_map<string, int> attackerScores;

const int COOLDOWN = 60;
const bool DEBUG_MODE = true;
const int BEHAVIOR_THRESHOLD = 5;
const int MAX_SCORE = 10;

string getRiskLevel(int score);

void logBehaviorWarning(const string& ip, int score) {
    logAlert("behavior_warning", "MEDIUM",
             "{\"ip\":\"" + ip + "\",\"score\":" + to_string(score) + "}");
}

void logBehaviorAlert(const string& ip, int score) {
    logAlert("behavior_alert", "HIGH",
             "{\"ip\":\"" + ip + "\",\"score\":" + to_string(score) + "}");
}


//Update behaviour
void updateBehavioral(
    const string& ip,
    int currentTime)
{
    cout << "[ENTRY] "
         << ip
         << " current score="
         << suspicionScore[ip]
         << endl;

int idle = 0;
int decay = 0;

if (lastSeenTime.count(ip))
    {
        idle = currentTime - lastSeenTime[ip];

if (idle < 0)
{
    idle = 0;
}

decay = idle / 300;
        decay = idle / 300;

        suspicionScore[ip] =
            max(0,
                suspicionScore[ip]
                - min(decay, suspicionScore[ip]));
    }

    if (DEBUG_MODE) {
        cout << "[DEBUG] "
        << ip
        << " idle=" << idle
        << " decay=" << decay
        << " score=" << suspicionScore[ip]
        << endl;
    }


    suspicionScore[ip]++;
    addThreatScore(ip,1);
    if (suspicionScore[ip] > MAX_SCORE)
{
    suspicionScore[ip] = MAX_SCORE;
}

attackerScores[ip] = suspicionScore[ip];

cout << "[ATTACKER SCORE] "
     << ip
     << " -> "
     << attackerScores[ip]
     << endl;

cout << "[CAP CHECK] "
     << suspicionScore[ip]
     << endl;

string risk = getRiskLevel(suspicionScore[ip]);

if (!lastRiskLevel.count(ip))
{
    lastRiskLevel[ip] = "LOW";
}

string previousRisk = lastRiskLevel[ip];

if (previousRisk == "LOW" && risk == "MEDIUM") {
    logAlert("behavior_warning", "MEDIUM",
             "{\"ip\":\"" + ip + "\",\"score\":" + to_string(suspicionScore[ip]) + "}");
}

if (previousRisk == "MEDIUM" && risk == "HIGH") {
    logAlert("behavior_alert", "HIGH",
             "{\"ip\":\"" + ip + "\",\"score\":" + to_string(suspicionScore[ip]) + "}");
}


lastRiskLevel[ip] = risk;

if (DEBUG_MODE)
{
    cout << "[DEBUG] "
     << ip
     << " score=" << suspicionScore[ip]
     << " risk=" << risk
     << endl;
}
    lastSeenTime[ip] = currentTime;

}  

string getRiskLevel(int score)
{
    if (score >= 9)
        return "HIGH";

    if (score >= 5)
        return "MEDIUM";

    return "LOW";
}


