#include "log_utils.h"
#include <sstream>

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

/* ===== Extract Time ===== */
string extractTimeStamp(const string& line) {

    stringstream ss(line);
    string month, day, time;

    if (!(ss >> month >> day >> time)) {
        return "";
    }

    return time;
}

/* ===== Convert Time to Seconds ===== */
int convertTimeToSeconds(const string& time) {

    stringstream ss(time);

    int h, m, s;
    char c1, c2;

    if (!(ss >> h >> c1 >> m >> c2 >> s)) {
        return -1;
    }

    return (h * 3600) + (m * 60) + s;
}
