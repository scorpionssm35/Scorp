#include "DetectionAggregator.h"
#include <string>
#include <sstream>
#include "BehaviorDetector.h"        
#include "UltimateScreenshotCapturer.h"
#include "LogUtils.h"
#include "dllmain.h"
#include "GlobalDefines.h"
SmartRateLimiter g_rateLimiter;
AntiCheatConfig g_config;
std::atomic<int> g_totalDetections(0);
std::atomic<int> g_loggedDetections(0);
DetectionAggregator g_detectionAggregator; 
std::unique_ptr<KernelCheatDetector> g_simpleDetector;
AggStats::AggStats() : count(0), maxConfidence(0.0), firstTime(0), lastTime(0) {}
AntiCheatConfig::AntiCheatConfig() :
    logCooldownNormal(60000),
    logCooldownCritical(30000),
    minDetectionsForLog(3),
    enableAggregation(true),
    logMissedDetections(true) {
}
bool SmartRateLimiter::ShouldLog(const std::string& key, int cooldownMs) {
    uint64_t now = GetTickCount64();
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_lastLogTime.find(key);
    if (it != m_lastLogTime.end() && (now - it->second) < (uint64_t)cooldownMs) {
        m_detectionCounter[key]++; // считаем пропущенные детекции
        return false;
    }

    m_lastLogTime[key] = now;
    int missed = 0;
    auto itCounter = m_detectionCounter.find(key);
    if (itCounter != m_detectionCounter.end()) {
        missed = itCounter->second;
        m_detectionCounter[key] = 0;
    }

    if (missed > 0 && g_config.logMissedDetections) {
        Log("[VEH] Missed " + std::to_string(missed) + " detections for " + key);
    }
    return true;
}
void SmartRateLimiter::ResetKey(const std::string& key) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_lastLogTime.erase(key);
    m_detectionCounter.erase(key);
}
DetectionAggregator::DetectionAggregator() {
    // Конструктор теперь пустой, так как MAX_BUFFER_SIZE инициализирован в заголовке
}
void DetectionAggregator::AddDetection(KernelCheatDetector::CheatPattern pattern, DWORD pid, const std::string& processName, double confidence) {
    std::lock_guard<std::mutex> lock(m_mutex);

    DetectionRecord record; // Используется глобальный DetectionRecord
    record.timestamp = GetTickCount64();
    record.pattern = pattern;
    record.pid = pid;
    record.processName = processName;
    record.confidence = confidence;

    m_buffer.push_back(record);
    if (m_buffer.size() > MAX_BUFFER_SIZE) {
        m_buffer.pop_front();
    }

    g_totalDetections++;
}
struct AggregationKey {
    KernelCheatDetector::CheatPattern pattern;
    DWORD pid;

    bool operator<(const AggregationKey& other) const {
        if (pattern != other.pattern)
            return pattern < other.pattern;
        return pid < other.pid;
    }
};
void DetectionAggregator::ProcessAndLog(bool force) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_buffer.empty()) return;

    // Явно указываем глобальную область видимости для AggStats
    std::map<AggregationKey, ::AggStats> aggregated;

    // Агрегируем записи
    for (size_t i = 0; i < m_buffer.size(); ++i) {
        const DetectionRecord& record = m_buffer[i];
        AggregationKey key;
        key.pattern = record.pattern;
        key.pid = record.pid;

        // Используем глобальный ::AggStats
        ::AggStats& stats = aggregated[key];

        stats.count++;
        stats.maxConfidence = std::max(stats.maxConfidence, record.confidence);
        if (stats.firstTime == 0) stats.firstTime = record.timestamp;
        stats.lastTime = record.timestamp;
    }

    // Вектор для хранения ключей, которые были обработаны и записаны в лог
    std::vector<AggregationKey> processedKeys;

    // Обрабатываем агрегированные данные
    for (std::map<AggregationKey, ::AggStats>::const_iterator it = aggregated.begin();
        it != aggregated.end(); ++it) {
        const AggregationKey& key = it->first;
        const ::AggStats& stats = it->second;

        // Находим имя процесса для этого PID
        std::string processName;
        for (size_t i = 0; i < m_buffer.size(); ++i) {
            const DetectionRecord& record = m_buffer[i];
            if (record.pattern == key.pattern && record.pid == key.pid) {
                processName = record.processName;
                break;
            }
        }

        std::string patternStr = PatternToString(key.pattern);
        std::stringstream keyStream;
        keyStream << patternStr << "_" << key.pid;
        std::string keyStr = keyStream.str();

        if (force || stats.count >= (size_t)g_config.minDetectionsForLog) {
            int cooldown = (key.pattern == KernelCheatDetector::PATTERN_KERNEL_DELAY) ?
                g_config.logCooldownCritical : g_config.logCooldownNormal;

            if (g_rateLimiter.ShouldLog(keyStr, cooldown)) {
                std::stringstream logStream;
                logStream << "[VEH] Aggregated detection: Pattern=" << patternStr
                    << " PID=" << key.pid
                    << " Process=" << processName
                    << " Count=" << stats.count
                    << " MaxConfidence=" << stats.maxConfidence
                    << " Duration=" << (stats.lastTime - stats.firstTime) << "ms";

                Log(logStream.str());
                g_loggedDetections++;
                StartSightImgDetection(logStream.str());
                // Запоминаем этот ключ для последующего удаления
                processedKeys.push_back(key);
            }
        }
    }

    // Удаляем из буфера только те записи, которые были обработаны и записаны в лог
    if (!processedKeys.empty()) {
        auto it = m_buffer.begin();
        while (it != m_buffer.end()) {
            bool shouldRemove = false;

            // Проверяем, нужно ли удалять эту запись
            for (const auto& key : processedKeys) {
                if (it->pattern == key.pattern && it->pid == key.pid) {
                    shouldRemove = true;
                    break;
                }
            }

            if (shouldRemove) {
                it = m_buffer.erase(it);
            }
            else {
                ++it;
            }
        }
    }
}
std::string DetectionAggregator::PatternToString(KernelCheatDetector::CheatPattern pattern) {
    switch (pattern) {
    case KernelCheatDetector::PATTERN_NONE: return "NONE";
    case KernelCheatDetector::PATTERN_REGULAR_READ: return "REGULAR_READ";
    case KernelCheatDetector::PATTERN_READ_COMPUTE_WRITE: return "READ_COMPUTE_WRITE";
    case KernelCheatDetector::PATTERN_SUB_HUMAN: return "SUB_HUMAN";
    case KernelCheatDetector::PATTERN_DMA_BURST: return "DMA_BURST";
    case KernelCheatDetector::PATTERN_KERNEL_DELAY: return "KERNEL_DELAY";
    default: return "UNKNOWN";
    }
}
void DetectionAggregator::NotifyDangerousPlayer(uint64_t entityId)
{
    float currentScore = g_suspicionMetrics.espScore +
        g_suspicionMetrics.aimbotScore +
        g_suspicionMetrics.speedhackScore +
        g_suspicionMetrics.wallhackScore +
        g_suspicionMetrics.triggerbotScore +
        (g_suspicionMetrics.totalFlags * 5.0);
    PlayerRiskLevel level = (currentScore >= 70.0f) ? PlayerRiskLevel::High :
        (currentScore >= 40.0f) ? PlayerRiskLevel::Medium :
        PlayerRiskLevel::Low;

    if (level == PlayerRiskLevel::Low) return;

    std::string levelStr = (level == PlayerRiskLevel::High) ? "HIGH RISK" : "MEDIUM RISK";

   // LogFormat("[VEH] Entity %llu → %s (score: %.1f)", entityId, levelStr.c_str(), currentScore);

    if (level == PlayerRiskLevel::High)
    {
        LogFormat("[VEH] Entity %llu — Warning!", entityId);
        StartSightImgDetection(("[VEH] Entity " + std::to_string(entityId) + " — Warning!").c_str());
        BD_ResetSuspicionMetrics();    
    }
}
ScopedTimer::ScopedTimer(const std::string& op) : m_operation(op) {
    m_start = std::chrono::high_resolution_clock::now();
}
ScopedTimer::~ScopedTimer() {
    auto end = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::micro>(end - m_start).count();

    if (g_simpleDetector && g_simpleDetector->IsValid()) {
        g_simpleDetector->RecordTiming(m_operation, duration);
    }
}