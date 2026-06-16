#include "behavioral_detector.h"
#include <iostream>

int main() {
    std::string ip = "127.0.0.1";

    // Force repeated behavior to escalate risk
    for (int t = 0; t < 15; t++) {
        updateBehavioral(ip, t * 100); // simulate time steps
    }

    std::cout << "Check alerts.jsonl for output" << std::endl;
    return 0;
}
