#include "alerts.h"
#include "alert_stats.h"
#include <fstream>
#include <iostream>
#include "alert_manager.h"

using namespace std;

ofstream alertFile(
    "alerts.jsonl",
    ios::app
);

void logAlert(
    const string& type,
    const string& severity,
    const string& details)
{
    alertFile.flush();
    incrementAlert(type);
    cout << "[ALERT FILE WRITE]" << endl;

    alertFile
        << "{"
        << "\"type\":\"" << type << "\","
        << "\"severity\":\"" << severity << "\","
        << "\"details\":" << details
        << "}"
        << endl;
}