#ifndef LOG_UTILS_H
#define LOG_UTILS_H

#include <string>

using namespace std;

string extractIP(const string& line);
string extractTimeStamp(const string& line);
int convertTimeToSeconds(const string& time);

#endif
