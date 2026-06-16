#include "alert_stats.h"
#include <iostream>
#include <unordered_map>
#include "../detectors/behavioral_detector.h"
#include "alert_manager.h"

using namespace std;

void recordAlert(const string& type)
{
    alertCounters[type]++;
}

void printAlertSummary()
{
    cout << endl;

    cout << "===== ALERT SUMMARY ====="
         << endl;

         
    cout << "Attackers tracked: "
     << attackerScores.size()
     << endl;

    for (auto& alert : alertCounters)
    {
        cout
            << alert.first
            << " : "
            << alert.second
            << endl;
    }

    cout << "\nTop Attackers:\n";

    for (auto& attacker : attackerScores)
    {
    if (attacker.second >= 5)
        {
        cout
            << attacker.first
            << " -> score "
            << attacker.second
            << endl;
        }
    }
    cout << "========================="
         << endl;
}