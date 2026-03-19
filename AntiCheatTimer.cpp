#include "AntiCheatTimer.h"
#include "dllmain.h"
#include <iostream>
AntiCheatTimer::AntiCheatTimer() : active(false) {}
AntiCheatTimer::~AntiCheatTimer() {
    stop();
}
int AntiCheatTimer::getRandomMinutes() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(20, 30);
    return dis(gen);
}

void AntiCheatTimer::timerLoop() {
    while (active) {
        int minutes = getRandomMinutes();
        std::this_thread::sleep_for(std::chrono::minutes(minutes));
        if (active && callback) {
            callback(); 
        }
    }
}
void AntiCheatTimer::startSightTimer() {
    if (active) return;
    callback = [this]() {
        StartSightImgDetection("Image by time");
        };
    active = true;
    timerThread = std::thread(&AntiCheatTimer::timerLoop, this);
}
void AntiCheatTimer::start(const std::function<void()>& func) {
    if (active) return;

    callback = func;
    active = true;
    timerThread = std::thread(&AntiCheatTimer::timerLoop, this);
}

void AntiCheatTimer::stop() {
    active = false;
    if (timerThread.joinable()) {
        timerThread.join();
    }
}