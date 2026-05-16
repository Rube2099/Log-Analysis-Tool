#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <vector>
#include <cstdlib>

using namespace std;

ofstream logFile("sample.log", ios::app);

int currentTime = 0;

/*---- Generate random IP ----*/

string randomIP() {
    return to_string(rand() % 256) + "." +
           to_string(rand() % 256) + "." +
           to_string(rand() % 256) + "." +
           to_string(rand() % 256);
}

/*---- Generate time ----*/

string formatTime(int seconds) {
    int h = seconds / 3600;
    int m = (seconds % 3600) / 60;
    int s = seconds % 60;

    char buffer[9];

    sprintf(buffer, "%02d:%02d:%02d", h, m, s);

    return string(buffer);
}

/*---- Writing logs ----*/

void writeLog(const string& ip, int currentTime) {
    logFile << "Jul 10 " << formatTime(currentTime)
            << " server sshd[123]: Failed password for root from "
            << ip << " port 22 ssh2"
            << endl;

            logFile.flush();
}

/*---- Brute force simulation ----*/

void simulateBruteForce() {
    string attackerIP = randomIP();

    for (int i = 0; i < 6; i++) { // > threshold
        writeLog(attackerIP, currentTime);
        currentTime += 3;
        this_thread::sleep_for(chrono::milliseconds(300));
    }
}

/*---- Simulate slow brute force ----*/

void simulatedSlowBruteforce() {
    string attackerIP = "192.168.1.250";

    for (int i = 0; i < 6; i++) {

        writeLog(attackerIP, currentTime);
        currentTime += 20;

        this_thread::sleep_for(chrono::milliseconds(300));
    }
}

/*---- Distributed Attack ----*/

void simulateDistributedAttack() {

    vector<string> ips;

    for (int i = 0; i < 4; i++) {
        ips.push_back(randomIP());
    }

    for (int i = 0; i < 6; i++) {

        for (const string& ip : ips) {
            writeLog(ip, currentTime);
            currentTime += 5;
        }

        this_thread::sleep_for(chrono::milliseconds(300));
    }
}

/*---- Main ----*/

int main() {

    srand(time(0));

    while (true) {

        int mode = rand() % 4;

        if (mode == 0) {
            // normal
            writeLog(randomIP(), currentTime);
            currentTime += 40;
        }
        else if (mode == 1) {
            simulateBruteForce();
        }else if (mode == 2) {
            simulatedSlowBruteforce();
        }
        else {
            simulateDistributedAttack();
        }

        this_thread::sleep_for(chrono::seconds(2));
    }

    return 0;
}
