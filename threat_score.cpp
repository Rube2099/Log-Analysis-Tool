#include "threat_score.h"
#include <iostream>
#include <unordered_map>
#include <algorithm>
#include <vector>

using namespace std;

unordered_map<string,int> threatScores;

void addThreatScore(
    const string& ip,
    int points)
{
    threatScores[ip] += points;
}

int getThreatScore(
    const string& ip)
{
    return threatScores[ip];
}

string getThreatLevel(int score)
{
    if(score >= 15)
        return "CRITICAL";

    if(score >= 10)
        return "HIGH";

    if(score >= 5)
        return "MEDIUM";

    return "LOW";
}

void printThreatSummary()
{
    std::cout << "\n===== THREAT DASHBOARD =====\n";
    vector<pair<string,int>> sortedThreats;

    for(auto& threat : threatScores)
    {
    sortedThreats.push_back(threat);
    }

    sort(
    sortedThreats.begin(),
    sortedThreats.end(),
    [](const auto& a, const auto& b)
    {
        return a.second > b.second;
    }
    );

    int count = 0;
    for(auto& threat : sortedThreats)
    {
        if(count >= 10)
        break;
         // Print 
        cout
        << threat.first
        << " -> "
        << threat.second
        << " ("
        << getThreatLevel(threat.second)
        << ")"
        << endl;

         count++;
    }

    std::cout << "============================\n";
}