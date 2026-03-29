#pragma once

#include <Windows.h>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <setupapi.h>
#include <devguid.h>
#include <winternl.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "ntdll.lib")

extern std::string Name_Game;

// Недокументированные структуры
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    PVOID Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

#define SystemModuleInformation         ((SYSTEM_INFORMATION_CLASS)11)
#define STATUS_INFO_LENGTH_MISMATCH     ((NTSTATUS)0xC0000004L)
#define CODEINTEGRITY_OPTION_TESTSIGNING 0x00000002
#define SystemKernelDebuggerInformation ((SYSTEM_INFORMATION_CLASS)35)

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

class KernelCheatDetector {
public:
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

    std::atomic<uint64_t> m_lastIntegrityCheck{ 0 };
    std::atomic<uint64_t> m_lastHeuristicCheck{ 0 };
    std::atomic<uint64_t> m_lastKernelDriverCheck{ 0 };
    std::atomic<uint64_t> m_lastTestSigningCheck{ 0 };
    std::atomic<uint64_t> m_lastDMACheck{ 0 };
    bool m_dmaDetected = false;
    bool m_initialized = false;
    bool m_highResTimer = false;
    LARGE_INTEGER m_frequency{};

    // Вспомогательные
    uint64_t FNV1aHash(const void* data, size_t size);
    bool GetTextSection(HMODULE hMod, uintptr_t& start, size_t& size);
    bool HashTextSectionUnsafe(uintptr_t addr, size_t size, uint64_t& outHash);
    void CreateBaselines();                    // ← теперь private
    bool CheckCodeIntegrityUnsafe();
    bool PerformHeuristicScanUnsafe();
    bool PerformHeuristicScanImpl();
    // Новые детекты
    bool DetectLoadedKernelDrivers();
    bool IsTestSigningOrDebugEnabled();
    bool DetectDMADevices();

public:
    KernelCheatDetector(const std::string& targetGameProcess = Name_Game, bool onlyMonitorGameProcess = true);
    ~KernelCheatDetector();

    bool IsValid() const { return m_highResTimer && m_initialized; }

    void ResetCache();

    // Старые методы — теперь с реализацией (заглушки)
    void RecordTiming(const std::string& operation, double durationMicroseconds);
    void RecordFrameTiming(double frameTimeMicroseconds);
    bool ShouldMonitorProcess(DWORD pid);

    void CleanupOldOperationStats(uint64_t currentTimeMs = 0);
    void ResetStatistics();

    void AnalyzeAdvancedPatterns();
    CheatPattern AnalyzePatterns();
    CheatPattern AnalyzePatternsForProcess(DWORD pid);

    bool DetectESPCheat() { return false; }
    bool DetectAimbotCheat() { return false; }
    bool DetectTriggerbotCheat() { return false; }
    bool DetectDMACheat() { return DetectDMADevices(); }
    bool DetectKernelDriverCheat() { return DetectLoadedKernelDrivers(); }
    bool DetectTimingCheat() { return false; }
    bool DetectMemoryPatternCheat() { return false; }
};