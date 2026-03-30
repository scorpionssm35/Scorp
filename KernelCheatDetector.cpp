#include "KernelCheatDetector.h"
#include "LogUtils.h"
#include "dllmain.h"
#include <Psapi.h>
#include <algorithm>
#include "DetectionAggregator.h"
#include "Manager.h"

#pragma comment(lib, "Psapi.lib")
std::string GetModulePathSimple(uintptr_t address) {
    char modulePath[MAX_PATH] = { 0 };
    HMODULE hMod = nullptr;

    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(address), &hMod)) {
        if (GetModuleFileNameA(hMod, modulePath, MAX_PATH) > 0) {
            return std::string(modulePath);
        }
    }
    return "";
}
bool IsWhitelistedPrivateRegion(const std::string& path) {
    if (path.empty()) return false;

    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (!Name_Dll.empty() && lower.find(Name_Dll) != std::string::npos) return true;
    if (!Name_Launcher.empty() && lower.find(Name_Launcher) != std::string::npos) return true;
    if (!Name_Launcher2.empty() && lower.find(Name_Launcher2) != std::string::npos) return true;

    if (lower.find("armourycrate") != std::string::npos) return true;
    if (lower.find("aura") != std::string::npos) return true;
    if (lower.find("\\windows\\") != std::string::npos) return true;
    if (lower.find("\\program files\\") != std::string::npos) return true;

    return false;
}
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
bool KernelCheatDetector::PerformHeuristicScanUnsafe() {
    __try {
        return PerformHeuristicScanImpl(); 
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
bool KernelCheatDetector::PerformHeuristicScanImpl() {
    static int privateCount = 0;

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0x10000;

    while (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
            mbi.Type == MEM_PRIVATE) {

            uintptr_t baseAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            std::string modulePath = GetModulePathSimple(baseAddr); 

            bool isSafe = false;
            if (IsWhitelistedPrivateRegion(modulePath)) {
                isSafe = true;
            }
            else if (baseAddr > 0x7FF000000000ULL ||
                mbi.RegionSize < 0x1000 ||
                mbi.RegionSize > 0x3000000) {
                isSafe = true;
            }
            std::wstring modulePathModule = GetFullModulePathFromAddress(baseAddr);
            if (Manager::GetInstance().ShouldIgnorePrivateRegion(modulePathModule))
            {
                return false;
            }
            if (!isSafe) {
                LogFormat("[VEH] SUSPICIOUS EXECUTABLE PRIVATE region @ 0x%llX (size: 0x%llX, module: %s)", baseAddr, mbi.RegionSize, modulePath.c_str());
                privateCount++;
                if (privateCount >= 3) {
                    privateCount = 0;
                    g_detectionAggregator.NotifyDangerousPlayer(0ULL);
                    return true;
                }
            }
        }

        addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (addr == 0 || addr > 0x7FFFFFFFFFFFULL) break;
    }

    return false;
}
bool KernelCheatDetector::DetectLoadedKernelDrivers()
{
    uint64_t now = GetTickCount64();
    if (now - m_lastKernelDriverCheck.load() < 15000) return false;
    m_lastKernelDriverCheck = now;

    ULONG size = 0;
    NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return false;

    std::vector<BYTE> buffer(size);
    status = NtQuerySystemInformation(SystemModuleInformation, buffer.data(), size, nullptr);
    if (!NT_SUCCESS(status)) return false;

    static const std::vector<std::string> blacklist = {
        "gdrv.sys", "rtcore64.sys", "dbutil_2_3.sys", "iqvw64.sys", "asio.sys",
        "s7.sys", "s7v.sys", "s7k.sys", "capcom.sys", "kdmapper", "vulnerable_driver"
    };

    RTL_PROCESS_MODULES* modules = reinterpret_cast<RTL_PROCESS_MODULES*>(buffer.data());

    for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
        auto& mod = modules->Modules[i];
        std::string name(mod.FullPathName + mod.OffsetToFileName);
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);

        for (const auto& bad : blacklist) {
            if (name.find(bad) != std::string::npos) {
                LogFormat("[VEH] BLACKLISTED DRIVER: %s", mod.FullPathName + mod.OffsetToFileName);
                g_detectionAggregator.NotifyDangerousPlayer(0ULL);
                StartSightImgDetection("[VEH] Suspicious driver: " + std::string(mod.FullPathName + mod.OffsetToFileName));
                return true;
            }
        }
    }
    return false;
}
bool KernelCheatDetector::IsTestSigningOrDebugEnabled()
{
    uint64_t now = GetTickCount64();
    if (now - m_lastTestSigningCheck.load() < 10000) return false;
    m_lastTestSigningCheck = now;

    SYSTEM_CODEINTEGRITY_INFORMATION sci = { sizeof(sci) };
    if (NT_SUCCESS(NtQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci), nullptr))) {
        if (sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGNING) {
            Log("[KERNEL] TEST SIGNING ENABLED → High chance of kernel cheat");
            g_detectionAggregator.NotifyDangerousPlayer(0ULL);
            return true;
        }
    }

    SYSTEM_KERNEL_DEBUGGER_INFORMATION kd = {};
    if (NT_SUCCESS(NtQuerySystemInformation(SystemKernelDebuggerInformation, &kd, sizeof(kd), nullptr))) {
        if (kd.KernelDebuggerEnabled) {
            g_detectionAggregator.NotifyDangerousPlayer(0ULL);
            return true;
        }
    }
    return false;
}
bool KernelCheatDetector::DetectDMADevices()
{
    if (m_dmaDetected) return true;

    uint64_t now = GetTickCount64();
    if (now - m_lastDMACheck.load() < 30000) return false;
    m_lastDMACheck = now;

    HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_SYSTEM, nullptr, nullptr, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return false;

    SP_DEVINFO_DATA devInfo = { sizeof(devInfo) };
    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfo); ++i) {
        char buffer[512] = {};
        if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfo, SPDRP_HARDWAREID, nullptr, (PBYTE)buffer, sizeof(buffer), nullptr)) {
            std::string hwId = buffer;
            std::transform(hwId.begin(), hwId.end(), hwId.begin(), ::tolower);

            if (hwId.find("vid_1234") != std::string::npos ||
                hwId.find("s7") != std::string::npos ||
                hwId.find("pci\\ven_1b73") != std::string::npos ||
                hwId.find("dma") != std::string::npos) {

                LogFormat("[VEH]DMA SUSPICIOUS DEVICE: %s", buffer);
                g_detectionAggregator.NotifyDangerousPlayer(0ULL);
                StartSightImgDetection("[VEH]DMA Suspicious hardware device detected");
                m_dmaDetected = true;
                SetupDiDestroyDeviceInfoList(hDevInfo);
                return true;
            }
        }
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);
    return false;
}
void KernelCheatDetector::AnalyzeAdvancedPatterns()
{
    if (!m_initialized) return;

    bool integrity = CheckCodeIntegrityUnsafe();
    bool heuristic = PerformHeuristicScanUnsafe();
    bool kernelDrv = DetectLoadedKernelDrivers();
    bool testSigning = IsTestSigningOrDebugEnabled();
    bool dma = DetectDMADevices();

    if (integrity || heuristic || kernelDrv || testSigning || dma) {
        g_detectionAggregator.NotifyDangerousPlayer(0ULL);
        Log("[VEH] DANGER DETECTED → screenshot triggered");
    }
}
KernelCheatDetector::CheatPattern KernelCheatDetector::AnalyzePatterns()
{
    if (CheckCodeIntegrityUnsafe()) return PATTERN_KERNEL_DELAY;
    if (PerformHeuristicScanUnsafe()) return PATTERN_KERNEL_DELAY;
    return PATTERN_NONE;
}
KernelCheatDetector::CheatPattern KernelCheatDetector::AnalyzePatternsForProcess(DWORD /*pid*/)
{
    return AnalyzePatterns();
}
void KernelCheatDetector::RecordTiming(const std::string& /*operation*/, double /*durationMicroseconds*/) {}
void KernelCheatDetector::RecordFrameTiming(double /*frameTimeMicroseconds*/) {}
bool KernelCheatDetector::ShouldMonitorProcess(DWORD /*pid*/) { return true; }
void KernelCheatDetector::CleanupOldOperationStats(uint64_t /*currentTimeMs*/) {}
void KernelCheatDetector::ResetStatistics() { ResetCache(); }
void KernelCheatDetector::CreateBaselines()
{
    // Используем Name_GameEXE из extern
    std::vector<std::string> criticalModules = { Name_Game };

    // Добавляем саму DLL, если нужно
    char dllName[MAX_PATH];
    GetModuleFileNameA(GetModuleHandle(nullptr), dllName, MAX_PATH);
    std::string dllPath = dllName;
    size_t pos = dllPath.find_last_of("\\/");
    if (pos != std::string::npos) {
        criticalModules.push_back(dllPath.substr(pos + 1));
    }

    for (const auto& modName : criticalModules) {
        HMODULE hMod = GetModuleHandleA(modName.c_str());
        if (!hMod) continue;

        uintptr_t textStart = 0;
        size_t    textSize = 0;

        if (GetTextSection(hMod, textStart, textSize) && textSize > 0) {
            uint64_t hash = 0;
            if (HashTextSectionUnsafe(textStart, textSize, hash)) {
                ModuleBaseline bl;
                bl.name = modName;
                bl.base = reinterpret_cast<uintptr_t>(hMod);
                bl.textStart = textStart;
                bl.textSize = textSize;
                bl.hash = hash;
                m_baselines.push_back(bl);

                LogFormat("[LOGEN] Baseline created: %s | .text=0x%llX | size=%zu", modName.c_str(), textStart, textSize);
            }
        }
    }

    m_initialized = !m_baselines.empty();
}
KernelCheatDetector::KernelCheatDetector(const std::string& /*targetGameProcess*/, bool /*onlyMonitorGameProcess*/)
{
    m_highResTimer = QueryPerformanceFrequency(&m_frequency) != 0;
    CreateBaselines();
    Log("[LOGEN] KernelCheatDetector v2.1 OPTIMIZED initialized");
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
    m_lastHeuristicCheck = 0;
    m_lastKernelDriverCheck = 0;
    m_lastTestSigningCheck = 0;
    m_lastDMACheck = 0;
    m_dmaDetected = false;
    CreateBaselines();
}