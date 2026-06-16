#pragma once

#include <string>

void addThreatScore(
    const std::string& ip,
    int points
);

int getThreatScore(
    const std::string& ip
);

std::string getThreatLevel(
    int score
);

void printThreatSummary();