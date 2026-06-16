#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <vector>
#include <cstdlib>

using namespace std;

ofstream logFile("sample.log");

int currentTime = 0;

/*---- Generate random IP ----*/

string randomIP() {
    return to_string(rand() % 256) + "." +
           to_string(rand() % 256) + "." +
           to_string(rand() % 256) + "." +
           to_string(rand() % 256);
}
/*---- Normal traffics ----*/

vector<string> normalIPs =
{
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "192.168.1.13"
};

string getNormalIP()
{
    return normalIPs[rand() % normalIPs.size()];
}

/*---- Generate time ----*/

string formatTime(int seconds)
{
    seconds %= 86400;

    int h = seconds / 3600;
    int m = (seconds % 3600) / 60;
    int s = seconds % 60;

    char buffer[9];

    sprintf(buffer,"%02d:%02d:%02d",h,m,s);

    return string(buffer);
}

/*---- Writing logs ----*/

void writeLog(const string& ip, int currentTime) {
    cout << "[GENERATOR] "
     << ip
     << " time="
     << currentTime
     << endl;
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
const string PERSISTENT_ATTACKER =
    "10.10.10.10";

void simulatedSlowBruteforce()
{
    for(int i = 0; i < 12; i++)
    {
        writeLog(PERSISTENT_ATTACKER, currentTime);
        currentTime += 1200;

        this_thread::sleep_for(
            chrono::milliseconds(300)
        );
    }
}

/*---- Test Decay ----*/

void testDecay()
{
    string ip = "100.100.100.100";

    writeLog(ip, currentTime);

    currentTime += 1200; // 20 دقيقة

    writeLog(ip, currentTime);
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
    testDecay();

    while (true) {

        int mode = rand() % 4;

        if (mode == 0) {
            // normal
            writeLog(getNormalIP(), currentTime);
            currentTime += rand() % 60 + 10; // 10–69 seconds
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
