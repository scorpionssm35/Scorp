#pragma once

#include <Windows.h>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>
#include <cstdint>

extern std::string Name_GameEXE;

class KernelCheatDetector {
public:
    // === Оригинальное перечисление (полная совместимость с dllmain.cpp) ===
    enum CheatPattern {
        PATTERN_NONE = 0,
        PATTERN_REGULAR_READ,
        PATTERN_READ_COMPUTE_WRITE,
        PATTERN_SUB_HUMAN,
        PATTERN_DMA_BURST,
        PATTERN_KERNEL_DELAY
    };

private:
    struct ModuleBaseline {
        std::string name;
        uintptr_t base;
        uintptr_t textStart;
        size_t    textSize;
        uint64_t  hash;
    };

    std::vector<ModuleBaseline> m_baselines;
    std::mutex                  m_scanMutex;
    std::atomic<uint64_t>       m_lastIntegrityCheck{ 0 };
    const uint64_t              INTEGRITY_INTERVAL_MS = 2000; // раз в 2 секунды — очень лояльно к CPU

    bool m_initialized = false;
    bool m_highResTimer = false;
    LARGE_INTEGER m_frequency{};

    // Вспомогательные
    uint64_t FNV1aHash(const void* data, size_t size);
    bool GetTextSection(HMODULE hMod, uintptr_t& start, size_t& size);
    void CreateBaselines();
    bool CheckCodeIntegrity();
    bool PerformHeuristicScan();

    bool PerformHeuristicScanUnsafe();
    bool CheckCodeIntegrityUnsafe();
    bool HashTextSectionUnsafe(uintptr_t addr, size_t size, uint64_t& outHash);

public:
    KernelCheatDetector(const std::string& targetGameProcess = Name_GameEXE, bool onlyMonitorGameProcess = true);
    ~KernelCheatDetector();

    bool IsValid() const { return m_highResTimer && m_initialized; }

    // === ОБЯЗАТЕЛЬНАЯ ФУНКЦИЯ СБРОСА КЕША ===
    void ResetCache();

    // === СТАРЫЕ МЕТОДЫ (полная совместимость с dllmain.cpp) ===
    void RecordTiming(const std::string& operation, double durationMicroseconds);
    void RecordFrameTiming(double frameTimeMicroseconds);
    bool ShouldMonitorProcess(DWORD pid);

    void CleanupOldOperationStats(uint64_t currentTimeMs = 0);
    void ResetStatistics();

    void AnalyzeAdvancedPatterns();
    CheatPattern AnalyzePatterns();
    CheatPattern AnalyzePatternsForProcess(DWORD pid);

    // Заглушки старых детектов
    bool DetectESPCheat() { return false; }
    bool DetectAimbotCheat() { return false; }
    bool DetectTriggerbotCheat() { return false; }
    bool DetectDMACheat() { return false; }
    bool DetectKernelDriverCheat() { return false; }
    bool DetectTimingCheat() { return false; }
    bool DetectMemoryPatternCheat() { return false; }
};