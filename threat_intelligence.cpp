#include "threat_intelligence.h"
#include <iostream>
#include <fstream>
#include <unordered_set>
#include <string>

using namespace std;

unordered_set<string> blacklist;

void loadBlacklist()
{
    ifstream file("blacklist.txt");

    string ip;

    while (getline(file, ip))
    {
        if (!ip.empty())
        {
            blacklist.insert(ip);
        }
    }
}

bool isBlacklisted(const string& ip)
{
    return blacklist.count(ip) > 0;
}