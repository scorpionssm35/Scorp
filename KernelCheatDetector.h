#pragma once

#include <Windows.h>
#include <vector>
#include <string>
#include <map>
#include <atomic>
#include <mutex>
#include <deque>
#include <algorithm>
#include <cmath>
extern std::string Name_GameEXE;
class KernelCheatDetector {
private:
    struct TimingRecord {
        uint64_t timestamp;
        double duration;
        std::string operation;
        DWORD processId;
    };

    struct OperationStats {
        std::deque<double> recentTimings;
        double mean = 0.0;
        double stddev = 0.0;
        double min = 0.0;
        double max = 0.0;
        uint64_t count = 0;
        uint64_t lastUpdateTime = 0;
    };

    std::mutex m_timingMutex;
    std::mutex m_statsMutex;
    std::deque<TimingRecord> m_recentTimings;
    std::map<std::string, OperationStats> m_operationStats;
    LARGE_INTEGER m_frequency;
    bool m_highResTimer;

    // Конфигурация
    std::string m_targetGameProcess;
    bool m_onlyMonitorGameProcess;

    const double SUSPICIOUS_DELAY_MIN = 100.0;
    const double SUSPICIOUS_DELAY_MAX = 5000.0;
    const double HUMAN_REACTION_MIN = 80000.0;
    const double FRAME_TIME_60FPS = 16666.67;
    const size_t MAX_RECORDS = 1000;
    const size_t STATS_WINDOW = 100;
    const double CORRELATION_THRESHOLD = 0.7;

    void UpdateStatistics(const std::string& operation, double duration);
    double CalculateStdDev(const std::deque<double>& values, double mean);
    double CalculateCorrelation(const std::deque<double>& x, const std::deque<double>& y);
    bool CheckPatternConsistency(const std::deque<double>& timings);
    bool CheckHumanReactionTime(double duration);

    // Вспомогательные функции
    std::string GetProcessNameById(DWORD pid);
    bool IsProcessExcluded(const std::string& processName);

public:
    void CleanupOldOperationStats(uint64_t currentTimeMs = 0);
    KernelCheatDetector(const std::string& targetGameProcess = Name_GameEXE, bool onlyMonitorGameProcess = true);
    ~KernelCheatDetector();

    bool IsValid() const { return m_highResTimer; }
    uint64_t GetCurrentTimeMicroseconds();

    // Основные функции
    void RecordTiming(const std::string& operation, double durationMicroseconds);
    void RecordFrameTiming(double frameTimeMicroseconds);

    // Проверка процесса
    bool IsTargetGameProcess(DWORD pid);
    bool IsTargetGameProcess(const std::string& processName);
    bool ShouldMonitorProcess(DWORD pid);

    // Детекция
    bool DetectESPCheat();
    bool DetectAimbotCheat();
    bool DetectTriggerbotCheat();
    bool DetectDMACheat();
    bool DetectKernelDriverCheat();
    bool DetectTimingCheat();
    bool DetectMemoryPatternCheat();
    void AnalyzeAdvancedPatterns();
    void ResetStatistics();

    // Настройки
    void SetTargetGameProcess(const std::string& processName);
    void SetOnlyMonitorGameProcess(bool enable);

    enum CheatPattern {
        PATTERN_NONE = 0,
        PATTERN_REGULAR_READ,
        PATTERN_READ_COMPUTE_WRITE,
        PATTERN_SUB_HUMAN,
        PATTERN_DMA_BURST,
        PATTERN_KERNEL_DELAY
    };

    CheatPattern AnalyzePatterns();
    CheatPattern AnalyzePatternsForProcess(DWORD pid); 
};