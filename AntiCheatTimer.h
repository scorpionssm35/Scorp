#pragma once

#include <thread>
#include <chrono>
#include <random>
#include <atomic>
#include <functional>
#include <string>

class AntiCheatTimer {
private:
    std::atomic<bool> active{ false };
    std::thread timerThread;
    std::function<void()> callback;
    int getRandomMinutes();
    void timerLoop();

public:
    AntiCheatTimer();
    ~AntiCheatTimer();
    void startSightTimer();
    void start(const std::function<void()>& func);
    void stop();
    bool isRunning() const { return active; }
};