#include "alert_manager.h"
#include <unordered_map>
#include <iostream>
#include "../detectors/behavioral_detector.h"

using namespace std;

unordered_map<string, int> alertCounters;

void incrementAlert(const string& type)
{
    alertCounters[type]++;
}

