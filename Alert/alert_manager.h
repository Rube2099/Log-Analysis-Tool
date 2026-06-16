#pragma once

#include <unordered_map>
#include <string>

extern std::unordered_map<std::string,int> alertCounters;

void incrementAlert(const std::string& type);
void printAlertSummary();