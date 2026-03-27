#pragma once
#include <windows.h>
#include <psapi.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <vector>
#include <string>
#include <cstdio>
#include "LogUtils.h"

// Отключаем предупреждения о безопасности
#pragma warning(disable : 4996)
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

// Необходимые определения для системных вызовов
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

// Типы для системных вызовов
typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI* pNtSetSystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength
    );

// Классы информации для SystemInformationClass
#define SystemFileCacheInformation 0x15  // Для очистки кэша файлов

// Структура для информации о файловом кэше
typedef struct _SYSTEM_FILE_CACHE_INFORMATION {
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
    SIZE_T MinimumWorkingSet;
    SIZE_T MaximumWorkingSet;
    SIZE_T CurrentSizeIncludingTransitionInPages;
    SIZE_T PeakSizeIncludingTransitionInPages;
    ULONG TransitionRePurposeCount;
    ULONG Flags;
} SYSTEM_FILE_CACHE_INFORMATION, * PSYSTEM_FILE_CACHE_INFORMATION;

class MemoryCleaner {
private:
    std::atomic<bool> m_running{ false };
    std::thread m_cleanerThread;
    int m_cleanupIntervalMinutes;

    // Функция для получения NtSetSystemInformation
    pNtSetSystemInformation GetNtSetSystemInformation() {
        static pNtSetSystemInformation fn = nullptr;
        if (!fn) {
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            if (hNtdll) {
                fn = (pNtSetSystemInformation)GetProcAddress(hNtdll, "NtSetSystemInformation");
            }
        }
        return fn;
    }

    // Получаем текущее использование памяти процессом
    SIZE_T GetCurrentMemoryUsage() {
        PROCESS_MEMORY_COUNTERS pmc;
        pmc.cb = sizeof(PROCESS_MEMORY_COUNTERS);
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            return pmc.WorkingSetSize; // Физическая память
        }
        return 0;
    }

    // Принудительная очистка кучи процесса
    void ForceHeapCleanup() {
        // Очищаем кучу по умолчанию
        HANDLE hHeap = GetProcessHeap();
        if (hHeap) {
            HeapCompact(hHeap, 0);
        }

        // Очищаем все дополнительные кучи
        DWORD heapCount = GetProcessHeaps(0, nullptr);
        if (heapCount > 0) {
            std::vector<HANDLE> heaps(heapCount);
            GetProcessHeaps(heapCount, heaps.data());

            for (HANDLE heap : heaps) {
                if (heap && heap != hHeap) {
                    HeapCompact(heap, 0);
                }
            }
        }
    }

    // Очистка рабочего набора памяти (Working Set)
    void TrimWorkingSet() {
        SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
    }

    // Очистка системного кэша (только если есть права)
    void TryClearSystemCache() {
        pNtSetSystemInformation NtSetSystemInfo = GetNtSetSystemInformation();
        if (!NtSetSystemInfo) return;

        // Пытаемся получить привилегии
        HANDLE hToken;
        TOKEN_PRIVILEGES tp;
        LUID luid;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            return;
        }

        if (!LookupPrivilegeValueA(NULL, "SeIncreaseQuotaPrivilege", &luid)) {
            CloseHandle(hToken);
            return;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        CloseHandle(hToken);

        if (!result || GetLastError() != ERROR_SUCCESS) {
            return; // Нет прав
        }

        // Пробуем очистить системный кэш
        SYSTEM_FILE_CACHE_INFORMATION cacheInfo = { 0 };
        cacheInfo.MinimumWorkingSet = (SIZE_T)-1;
        cacheInfo.MaximumWorkingSet = (SIZE_T)-1;

        NtSetSystemInfo(SystemFileCacheInformation, &cacheInfo, sizeof(cacheInfo));
    }

public:
    MemoryCleaner(int intervalMinutes = 5) : m_cleanupIntervalMinutes(intervalMinutes) {}

    void Start() {
        if (m_running.exchange(true)) return;

        m_cleanerThread = std::thread([this]() {
            while (m_running) {
                auto startTime = std::chrono::steady_clock::now();

                SIZE_T beforeMem = GetCurrentMemoryUsage();

                // 1. Очищаем кучи
                ForceHeapCleanup();

                // 2. Очищаем Working Set (основной метод)
               // TrimWorkingSet();

                // 3. Пробуем очистить системный кэш (не обязательно)
                // TryClearSystemCache(); // Закомментировано, т.к. требует прав
                SIZE_T afterMem = GetCurrentMemoryUsage();
                SIZE_T freed = (beforeMem > afterMem) ? (beforeMem - afterMem) : 0;

                if (freed > 10 * 1024 * 1024) { // Если освободили больше 10 МБ
                    Log((std::string("[LOGEN] Memory cleaned: ") + FormatBytes(beforeMem) + " -> " + FormatBytes(afterMem) + " (freed " + FormatBytes(freed) + ")").c_str());
                }
                static DWORD lastFullReset = 0;
                if (GetTickCount() - lastFullReset > 5 * 60 * 1000) {  // 30 минут
                    EPS::CleanupMemory(true);
                    lastFullReset = GetTickCount();
                }
                auto elapsed = std::chrono::steady_clock::now() - startTime;
                auto sleepTime = std::chrono::minutes(m_cleanupIntervalMinutes) - elapsed;

                if (sleepTime > std::chrono::seconds(0)) {
                    std::this_thread::sleep_for(sleepTime);
                }
            }
            });
    }

    void Stop() {
        m_running = false;
        if (m_cleanerThread.joinable()) {
            m_cleanerThread.join();
        }
    }

private:
    static std::string FormatBytes(SIZE_T bytes) {
        const char* units[] = { "B", "KB", "MB", "GB" };
        int unit = 0;
        double size = static_cast<double>(bytes);

        while (size >= 1024.0 && unit < 3) {
            size /= 1024.0;
            unit++;
        }

        char buffer[64];
        sprintf_s(buffer, sizeof(buffer), "%.1f %s", size, units[unit]);
        return std::string(buffer);
    }
};