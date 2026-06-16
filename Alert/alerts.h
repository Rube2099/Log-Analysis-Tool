#ifndef ALERTS_H
#define ALERTS_H

#include <string>

void logAlert(
    const std::string& type,
    const std::string& severity,
    const std::string& details
);

#endif