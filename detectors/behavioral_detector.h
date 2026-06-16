#pragma once

#include <string>
#include <unordered_map>

extern std::unordered_map<std::string, int> attackerScores;

std::string getRiskLevel(int score);

void updateBehavioral(
    const std::string& ip,
    int currentTime
);