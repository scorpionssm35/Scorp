#include "KernelCheatDetector.h"
#include "LogUtils.h"
#include "dllmain.h"
#include <Psapi.h>
#include <algorithm>

#pragma comment(lib, "Psapi.lib")

// ====================== FAST HASH ======================
uint64_t KernelCheatDetector::FNV1aHash(const void* data, size_t size)
{
    if (!data || size == 0) return 0;
    uint64_t hash = 0xcbf29ce484222325ULL;
    const uint8_t* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < size; ++i) {
        hash ^= p[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

// ====================== RAW HELPERS (только здесь __try) ======================
bool KernelCheatDetector::GetTextSection(HMODULE hMod, uintptr_t& start, size_t& size)
{
    __try {
        if (!hMod) return false;
        IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hMod);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<BYTE*>(hMod) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        IMAGE_SECTION_HEADER* section = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            reinterpret_cast<BYTE*>(&nt->OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader);

        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (strncmp(reinterpret_cast<const char*>(section[i].Name), ".text", 5) == 0) {
                start = reinterpret_cast<uintptr_t>(hMod) + section[i].VirtualAddress;
                size = section[i].Misc.VirtualSize;
                return true;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return false;
}

bool KernelCheatDetector::HashTextSectionUnsafe(uintptr_t addr, size_t size, uint64_t& outHash)
{
    __try {
        outHash = FNV1aHash(reinterpret_cast<void*>(addr), size);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        outHash = 0;
        return false;
    }
}
template<typename T>
void CheckCodeIntegrityUnsafeMessage(const T& bl) {
    LogFormat("[VEH] CODE INTEGRITY VIOLATION → %s", bl.name.c_str());
    StartSightImgDetection("[VEH] CODE INTEGRITY VIOLATION: " + bl.name);
}
bool KernelCheatDetector::CheckCodeIntegrityUnsafe()
{
    __try {
        for (const auto& bl : m_baselines) {
            uint64_t current = FNV1aHash(reinterpret_cast<void*>(bl.textStart), bl.textSize);
            if (current != bl.hash) {
                CheckCodeIntegrityUnsafeMessage(bl);
                return true;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return false;
}
void PerformHeuristicScanUnsafeMessage(MEMORY_BASIC_INFORMATION mbi) {
    LogFormat("[VEH] SUSPICIOUS EXECUTABLE PRIVATE region @ 0x%llX (size %zu)", reinterpret_cast<uintptr_t>(mbi.BaseAddress), mbi.RegionSize);
    StartSightImgDetection("[VEH] SUSPICIOUS MEMORY REGION (kernel cheat)");
}
bool KernelCheatDetector::PerformHeuristicScanUnsafe()
{
    __try {
        MEMORY_BASIC_INFORMATION mbi{};
        uintptr_t addr = 0;

        while (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
                mbi.Type == MEM_PRIVATE) {
                PerformHeuristicScanUnsafeMessage(mbi);
                return true;
            }
            addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (addr == 0) break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return false;
}

// ====================== PUBLIC FUNCTIONS (без __try) ======================
void KernelCheatDetector::CreateBaselines()
{
    std::vector<std::string> critical = { "dayz_x64.exe", "enfusion.dll" };

    for (const auto& modName : critical)
    {
        HMODULE hMod = GetModuleHandleA(modName.c_str());
        if (!hMod) continue;

        uintptr_t textStart = 0;
        size_t    textSize = 0;

        if (GetTextSection(hMod, textStart, textSize) && textSize > 0)
        {
            uint64_t hash = 0;
            if (!HashTextSectionUnsafe(textStart, textSize, hash))
                continue;

            ModuleBaseline bl;
            bl.name = modName;
            bl.base = reinterpret_cast<uintptr_t>(hMod);
            bl.textStart = textStart;
            bl.textSize = textSize;
            bl.hash = hash;

            m_baselines.push_back(bl);

            LogFormat("[VEH] Baseline: %s | .text=0x%llX | size=%zu | hash=0x%llX",
                modName.c_str(), textStart, textSize, hash);
        }
    }
    m_initialized = !m_baselines.empty();
}

bool KernelCheatDetector::CheckCodeIntegrity()
{
    uint64_t now = GetTickCount64();
    if (now - m_lastIntegrityCheck.load() < INTEGRITY_INTERVAL_MS) return false;
    m_lastIntegrityCheck = now;

    std::lock_guard<std::mutex> lock(m_scanMutex);   // RAII — нормально
    return CheckCodeIntegrityUnsafe();               // чистый SEH
}

bool KernelCheatDetector::PerformHeuristicScan()
{
    return PerformHeuristicScanUnsafe();             // чистый SEH
}

// ====================== ЗАГЛУШКИ ======================
void KernelCheatDetector::RecordTiming(const std::string& /*operation*/, double /*durationMicroseconds*/) {}
void KernelCheatDetector::RecordFrameTiming(double /*frameTimeMicroseconds*/) {}
bool KernelCheatDetector::ShouldMonitorProcess(DWORD /*pid*/) { return true; }

void KernelCheatDetector::CleanupOldOperationStats(uint64_t /*currentTimeMs*/) {}
void KernelCheatDetector::ResetStatistics() { ResetCache(); }

// ====================== ОСНОВНЫЕ ДЕТЕКЦИИ ======================
void KernelCheatDetector::AnalyzeAdvancedPatterns()
{
    if (!m_initialized) return;

    bool integrity = CheckCodeIntegrity();
    bool heuristic = PerformHeuristicScan();

    if (integrity || heuristic) {
        Log("[VEH] HIGH CHEAT PROBABILITY (integrity + heuristic)");
        StartSightImgDetection("[VEH] KERNEL CHEAT DETECTED (code + memory)");
    }
}

KernelCheatDetector::CheatPattern KernelCheatDetector::AnalyzePatterns()
{
    if (CheckCodeIntegrity()) return PATTERN_KERNEL_DELAY;
    if (PerformHeuristicScan()) return PATTERN_KERNEL_DELAY;
    return PATTERN_NONE;
}

KernelCheatDetector::CheatPattern KernelCheatDetector::AnalyzePatternsForProcess(DWORD /*pid*/)
{
    return AnalyzePatterns();
}

// ====================== КОНСТРУКТОР / ДЕСТРУКТОР ======================
KernelCheatDetector::KernelCheatDetector(const std::string& /*targetGameProcess*/, bool /*onlyMonitorGameProcess*/)
{
    m_highResTimer = QueryPerformanceFrequency(&m_frequency) != 0;
    CreateBaselines();
    Log("[VEH] KernelCheatDetector (integrity + heuristic) initialized");
}

KernelCheatDetector::~KernelCheatDetector()
{
    ResetCache();
}

void KernelCheatDetector::ResetCache()
{
    std::lock_guard<std::mutex> lock(m_scanMutex);
    m_baselines.clear();
    m_initialized = false;
    m_lastIntegrityCheck = 0;
    CreateBaselines();
    Log("[VEH] Cache fully reset + baselines recreated");
}