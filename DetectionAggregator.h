#pragma once
#define NOMINMAX 
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <vector>
#include <string>
#include <map>
#include <atomic>
#include <mutex>
#include <deque>
#include <algorithm> 
#include "KernelCheatDetector.h"
#include <chrono>

// =================== ПЕРЕМЕСТИТЬ СЮДА глобальные структуры ===================
struct DetectionRecord {
    uint64_t timestamp;
    KernelCheatDetector::CheatPattern pattern;
    DWORD pid;
    std::string processName;
    double confidence;
};

struct AggStats {
    int count;
    double maxConfidence;
    uint64_t firstTime;
    uint64_t lastTime;

    AggStats();
};

class SmartRateLimiter {
private:
    std::mutex m_mutex;
    std::map<std::string, uint64_t> m_lastLogTime;
    std::map<std::string, int> m_detectionCounter;

public:
    bool ShouldLog(const std::string& key, int cooldownMs = 60000);
    void ResetKey(const std::string& key);
};

struct AntiCheatConfig {
    int logCooldownNormal;
    int logCooldownCritical;
    int minDetectionsForLog;
    bool enableAggregation;
    bool logMissedDetections;

    AntiCheatConfig();
};

// =================== Класс DetectionAggregator ===================
class DetectionAggregator {
private:
    std::mutex m_mutex;
    std::deque<DetectionRecord> m_buffer; // Используем глобальный DetectionRecord
    static const size_t MAX_BUFFER_SIZE = 1000; // Исправлено: статическая константа

public:
    DetectionAggregator();
    void AddDetection(KernelCheatDetector::CheatPattern pattern, DWORD pid,
        const std::string& processName, double confidence);
    void ProcessAndLog(bool force = false);

private:
    std::string PatternToString(KernelCheatDetector::CheatPattern pattern);
};

// =================== Глобальные переменные ===================
extern SmartRateLimiter g_rateLimiter;
extern AntiCheatConfig g_config;
extern std::atomic<int> g_totalDetections;
extern std::atomic<int> g_loggedDetections;
extern DetectionAggregator g_detectionAggregator;
extern std::string Name_Game;
//extern KernelCheatDetector g_simpleDetector;
extern std::unique_ptr<KernelCheatDetector> g_simpleDetector;

// =================== Вспомогательные классы ===================
class ScopedTimer {
    std::chrono::high_resolution_clock::time_point m_start;
    std::string m_operation;
public:
    ScopedTimer(const std::string& op);
    ~ScopedTimer();
};

#define START_TIMING(op) auto start_##op = std::chrono::high_resolution_clock::now()
#define END_TIMING(op) \
    auto end_##op = std::chrono::high_resolution_clock::now(); \
    double duration_##op = std::chrono::duration<double, std::micro>(end_##op - start_##op).count(); \
    if (g_simpleDetector && g_simpleDetector->IsValid()) { \
        g_simpleDetector->RecordTiming(#op, duration_##op); \
    }