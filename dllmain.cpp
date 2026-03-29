#include <windows.h>
#include <dbghelp.h>
#include <Psapi.h>
#include <winternl.h>
#include <ntstatus.h> 
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <tlhelp32.h>
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <map>
#include <shlobj.h>
#include <intrin.h>
#include <locale>
#include <codecvt>
#include <mutex>
#include <regex>
#include <memory>
#include <wintrust.h> 
#include <softpub.h> 
#include <wincrypt.h> 
#include <future>
#include <unordered_set>
#include <cstdarg>
#include <set>
#include <chrono>
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Advapi32.lib")
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#include "LogUtils.h"
#include <lm.h>
#include <sddl.h>
#pragma comment(lib, "Netapi32.lib")
#include "KernelCheatDetector.h" 
#include "UltimateScreenshotCapturer.h"
#include "DetectionAggregator.h"
#include "KeyToggleMonitor.h"
#include "dllmain.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Version.lib")
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <unordered_map>
#include "SystemInitializer.h"
#include "EntityPosSampler.h"
#include "VulkanDetector.h"
#include "BehaviorDetector.h"
#include "MemoryCleaner.h"
#include <random>
/*
* ВАЖНО ДОБАВЬ ИМЯ КЛИЕНТА в IsLegitimateModule
[WARNING MonitorSuspiciousFunctions] // отключил
[WARNING HOOK]
[WARNING Module]
[HOOK] ReadProcessMemory
[HOOK] WriteProcessMemory
[HOOK] NtReadVirtualMemory
[HOOK] NtWriteVirtualMemory
[HOOK] CreateRemoteThread
[VEH]
[LOGEN]
*/
#ifndef _SOCKLEN_T
#define _SOCKLEN_T
typedef int socklen_t;
#endif
std::string VerSVG = "1.1.6.6";
bool GameProjectdayzzona = false;

MemoryCleaner g_memoryCleaner(10);
const uint32_t SHA256::K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0b5f8, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
SHA256::SHA256() {
    std::memset(m_data, 0, sizeof(m_data));
    std::memset(m_hash, 0, sizeof(m_hash));

    m_state[0] = 0x6a09e667;
    m_state[1] = 0xbb67ae85;
    m_state[2] = 0x3c6ef372;
    m_state[3] = 0xa54ff53a;
    m_state[4] = 0x510e527f;
    m_state[5] = 0x9b05688c;
    m_state[6] = 0x1f83d9ab;
    m_state[7] = 0x5be0cd19;
    m_bitLength = 0;
    m_dataLength = 0;
}
void SHA256::update(const uint8_t* data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        m_data[m_dataLength] = data[i];
        m_dataLength++;
        if (m_dataLength == 64) {
            transform();
            m_bitLength += 512;
            m_dataLength = 0;
        }
    }
}
void SHA256::finalize() {
    m_bitLength += m_dataLength * 8;
    m_data[m_dataLength] = 0x80;
    m_dataLength++;

    if (m_dataLength > 56) {
        while (m_dataLength < 64) {
            m_data[m_dataLength++] = 0x00;
        }
        transform();
        m_dataLength = 0;
    }

    while (m_dataLength < 56) {
        m_data[m_dataLength++] = 0x00;
    }

    for (int i = 0; i < 8; ++i) {
        m_data[56 + i] = (uint8_t)((m_bitLength >> ((7 - i) * 8)) & 0xFF);
    }
    transform();
}
uint8_t* SHA256::getHash() {
    return m_hash;
}
void SHA256::transform() {
    uint32_t W[64];
    for (int i = 0; i < 16; ++i) {
        W[i] = (m_data[i * 4] << 24) | (m_data[i * 4 + 1] << 16) |
            (m_data[i * 4 + 2] << 8) | m_data[i * 4 + 3];
    }

    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = (W[i - 15] >> 7) | (W[i - 15] << (32 - 7));
        uint32_t s1 = (W[i - 2] >> 17) | (W[i - 2] << (32 - 17));
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    uint32_t a = m_state[0];
    uint32_t b = m_state[1];
    uint32_t c = m_state[2];
    uint32_t d = m_state[3];
    uint32_t e = m_state[4];
    uint32_t f = m_state[5];
    uint32_t g = m_state[6];
    uint32_t h = m_state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = (e >> 6) | (e << (32 - 6));
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = (a >> 2) | (a << (32 - 2));
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    m_state[0] += a;
    m_state[1] += b;
    m_state[2] += c;
    m_state[3] += d;
    m_state[4] += e;
    m_state[5] += f;
    m_state[6] += g;
    m_state[7] += h;

    for (int i = 0; i < 4; ++i) {
        m_hash[i] = (uint8_t)((m_state[0] >> (24 - i * 8)) & 0xFF);
        m_hash[i + 4] = (uint8_t)((m_state[1] >> (24 - i * 8)) & 0xFF);
        m_hash[i + 8] = (uint8_t)((m_state[2] >> (24 - i * 8)) & 0xFF);
        m_hash[i + 12] = (uint8_t)((m_state[3] >> (24 - i * 8)) & 0xFF);
        m_hash[i + 16] = (uint8_t)((m_state[4] >> (24 - i * 8)) & 0xFF);
        m_hash[i + 20] = (uint8_t)((m_state[5] >> (24 - i * 8)) & 0xFF);
        m_hash[i + 24] = (uint8_t)((m_state[6] >> (24 - i * 8)) & 0xFF);
        m_hash[i + 28] = (uint8_t)((m_state[7] >> (24 - i * 8)) & 0xFF);
    }
}

static bool isLicenseVersion;
bool DetermineAndSetGameProcessNames() {
    std::wstring processPath;
    bool foundDayZProcess = false;

    for (int attempt = 0; attempt < 25; attempt++) {
        if (attempt > 0) {
            Sleep(1000);
        }

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
           // Log("[LOGEN] Failed to create process snapshot");
            continue;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::wstring processName = pe32.szExeFile;
                std::wstring processNameLower = processName;
                std::transform(processNameLower.begin(), processNameLower.end(), processNameLower.begin(), ::towlower);

                if (processNameLower == L"dayz_x64.exe") {
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        wchar_t path[MAX_PATH] = { 0 };
                        DWORD pathSize = MAX_PATH;

                        if (QueryFullProcessImageNameW(hProcess, 0, path, &pathSize)) {
                            processPath = path;
                            foundDayZProcess = true;
                            CloseHandle(hProcess);
                            CloseHandle(hSnapshot);
                            goto PROCESS_FOUND;
                        }
                        else {
                           // Log("[LOGEN] Failed to get process path, error: " + std::to_string(GetLastError()));
                        }

                        CloseHandle(hProcess);
                    }
                    else {
                       // Log("[LOGEN] Failed to open process, error: " + std::to_string(GetLastError()));
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        else {
           // Log("[LOGEN] Process32First failed");
        }

        CloseHandle(hSnapshot);
    }

    return false;

PROCESS_FOUND:

    if (!foundDayZProcess) {
        Log("[LOGEN] Critical error: process found but flag not set");
        return false;
    }
    //Log("[LOGEN] Full path: " + WStringToString(processPath));
    size_t lastSlash = processPath.find_last_of(L"\\/");
    if (lastSlash == std::wstring::npos) {
        Log("[LOGEN] Error: cannot parse path");
        return false;
    }
    std::wstring parentDir = processPath.substr(0, lastSlash);
    size_t parentSlash = parentDir.find_last_of(L"\\/");
    std::wstring folderName;

    if (parentSlash != std::wstring::npos) {
        folderName = parentDir.substr(parentSlash + 1);
    }
    else {
        folderName = parentDir;
    }
    std::wstring folderNameLower = folderName;
    std::transform(folderNameLower.begin(), folderNameLower.end(), folderNameLower.begin(), ::towlower);

   // Log("[LOGEN] Game folder: " + WStringToString(folderName));
    bool isSteamVersion = (folderNameLower == L"dayz");

    if (isSteamVersion) {
      //  Log("[LOGEN] Detected: Steam version (folder: DayZ)");
        return false;
    }
    else {
       // Log("[LOGEN] Detected: Non-Steam version (folder: " + WStringToString(folderName) + ")");
        return true;
    }
}
std::string ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}
std::string Trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    size_t last = str.find_last_not_of(" \t\r\n");
    if (first == std::string::npos || last == std::string::npos)
        return "";
    return str.substr(first, last - first + 1);
}
std::string NormalizeProcessName(const std::string& name) {
    std::string result = ToLower(Trim(name));
    const std::string exeExt = ".exe";
    if (result.size() >= exeExt.size() &&
        result.compare(result.size() - exeExt.size(), exeExt.size(), exeExt) == 0) {
        result = result.substr(0, result.size() - exeExt.size());
    }
    return result;
}
std::string GetInjectedProcessName() {
    char processPath[MAX_PATH] = { 0 };
    if (GetModuleFileNameA(NULL, processPath, MAX_PATH)) {
        std::string fullPath = processPath;
        size_t lastSlash = fullPath.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            std::string exeName = fullPath.substr(lastSlash + 1);
            return NormalizeProcessName(exeName);
        }
    }
    return "";
}

std::atomic<bool> g_isProcessBusyServer{ false };
static void InfoOut(const std::string& hwid, const std::string& id) {
    try {
        static int InfoOutcallCount = 0;
        std::string encrypted = XorEncrypt(hwid, Name_Dll);
        std::string encoded = Base64Encode(encrypted);
        std::string Identifier = GetSecureIdentifier();
        std::string data = "CL01," + id + std::string("_SVG_") + encoded + "," + Identifier;
        const char* SERVER_IP = hostsc.c_str();
        const int SERVER_PORT = Port_Panel_Registered;
        std::string portStr = std::to_string(SERVER_PORT);
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            //Log("[LOGEN] TCP InfoOut WSAStartup failed");
            return;
        }
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
           // Log("[LOGEN] TCP InfoOut Socket creation failed");
            WSACleanup();
            return;
        }
        DWORD timeout = 5000; 
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(SERVER_PORT);
        struct hostent* host = gethostbyname(SERVER_IP);
        if (host == nullptr) {
            //Log("[LOGEN] TCP InfoOut Failed to resolve host: " + std::string(SERVER_IP));
            closesocket(sock);
            WSACleanup();
            return;
        }

        addr.sin_addr.s_addr = *((unsigned long*)host->h_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
            //Log("[LOGEN] TCP InfoOut Connection failed to " + std::string(SERVER_IP) + ":" + portStr);
            closesocket(sock);
            WSACleanup();
            return;
        }

        int bytesSent = send(sock, data.c_str(), (int)data.length(), 0);
        if (bytesSent == SOCKET_ERROR) {
           // Log("[LOGEN] TCP Send failed");
        }
        else {
            InfoOutcallCount++;
            if (InfoOutcallCount % 2 == 0) {
               // Log("[LOGEN] TCP TCP HWID sent OK: " + data + " (" + std::to_string(bytesSent) + " bytes)");
            }
        }

        closesocket(sock);
        WSACleanup();
    }
    catch (const std::exception& e) {
        //Log("[LOGEN] TCP InfoOut Error in HWID sent: " + std::string(e.what()));
    }
    catch (...) {
        //Log("[LOGEN] TCP InfoOut Unknown error in HWID sent");
    }
}
static void InfoOutStatus(const std::string& hwid, const std::string& id) {
    try {
        static int callCount = 0;
        std::string encrypted = XorEncrypt(hwid, Name_Dll);
        std::string encoded = Base64Encode(encrypted);
        std::string Identifier = GetSecureIdentifier();
        std::string data = "CL01," + VerSVG + "," + id + std::string("_SOG_") + encoded + "," + Identifier;
        const char* SERVER_IP = hostsc.c_str();
        const int SERVER_PORT = Port_Panel_Registered;
        std::string portStr = std::to_string(SERVER_PORT);
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
           // Log("[LOGEN] TCP InfoOutStatus WSAStartup failed");
            return;
        }
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            //Log("[LOGEN] TCP InfoOutStatus Socket creation failed");
            WSACleanup();
            return;
        }
        DWORD timeout = 5000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(SERVER_PORT);
        struct hostent* host = gethostbyname(SERVER_IP);
        if (host == nullptr) {
            //Log("[LOGEN] TCP InfoOutStatus Failed to resolve host: " + std::string(SERVER_IP));
            closesocket(sock);
            WSACleanup();
            return;
        }

        addr.sin_addr.s_addr = *((unsigned long*)host->h_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
            //Log("[LOGEN] TCP InfoOutStatus Connection failed to " + std::string(SERVER_IP) + ":" + portStr);
            closesocket(sock);
            WSACleanup();
            return;
        }

        int bytesSent = send(sock, data.c_str(), (int)data.length(), 0);
        if (bytesSent == SOCKET_ERROR) {
            //Log("[LOGEN] TCP InfoOutStatus Send failed");
        }
        else {
            callCount++;
            if (callCount % 60 == 0) {
                auto now = std::chrono::system_clock::now();
                auto time_t_now = std::chrono::system_clock::to_time_t(now);
                std::tm tm_now;
                localtime_s(&tm_now, &time_t_now);

                char time_buf[9];
                strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &tm_now);

              //  Log(std::string("[LOGEN] TCP InfoOutStatus sent OK: ") + time_buf + ":CL01_" + VerSVG + "_" + id + std::string("_SOG_") + hwid + "_" + " (" + std::to_string(bytesSent) + " bytes)");
                //Log("[LOGEN] InfoOutStatus sent OK (call #" + std::to_string(callCount) + ")");
            }
        }

        closesocket(sock);
        WSACleanup();
    }
    catch (const std::exception& e) {
        //Log("[LOGEN] TCP InfoOutStatus Error in InfoOutStatus sent: " + std::string(e.what()));
    }
    catch (...) {
       // Log("[LOGEN] TCP InfoOutStatus Unknown error in InfoOutStatus sent");
    }
}
void InfoOutMessageInternal(const std::string& data) {
    __try {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            return;
        }

        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            WSACleanup();
            return;
        }

        DWORD timeout = 1500;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(Port_Panel_Registered);

        struct hostent* host = gethostbyname(hostsc.c_str());
        if (host == nullptr) {
            closesocket(sock);
            WSACleanup();
            return;
        }
        addr.sin_addr.s_addr = *((unsigned long*)host->h_addr);

        connect(sock, (sockaddr*)&addr, sizeof(addr));

        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);

            if (so_error == 0) {
                send(sock, data.c_str(), (int)data.length(), 0);
            }
        }

        closesocket(sock);
        WSACleanup();
    }
    __finally {
    }
}
void InfoOutMessage(const std::string& hwid, const std::string& id, const std::string& message) {
    std::string injectedProcess;
    try {
        injectedProcess = GetInjectedProcessName();
        std::transform(injectedProcess.begin(), injectedProcess.end(), injectedProcess.begin(), ::tolower);
    }
    catch (...) {
        return;
    }

    if (injectedProcess != Name_Game2) {
        return;
    }

    if (g_isProcessBusyServer.load()) {
        return;
    }

    bool expectedServer = false;
    if (!g_isProcessBusyServer.compare_exchange_strong(expectedServer, true)) {
        return;
    }
    struct FlagReset {
        std::atomic<bool>& flag;
        bool active;
        FlagReset(std::atomic<bool>& f) : flag(f), active(true) {}
        void disarm() { active = false; }
        ~FlagReset() { if (active) flag.store(false); }
    } resetter(g_isProcessBusyServer);

    if (id == "---" || message == "---" || message.empty() || hwid.empty()) {
        return;
    }

    if (id.empty()) {
        if (!isLicenseVersion) {
            ReadSteamUIDStart();
        }
        else {
            ReadGoldbergUIDStart("Goldberg SteamEmu Saves\\settings\\user_steam_id.txt");
        }
    }
    std::string encrypted = XorEncrypt(message, Name_Dll);
    std::string encoded = Base64Encode(encrypted);
    std::string encrypted1 = XorEncrypt(hwid, Name_Dll);
    std::string encoded1 = Base64Encode(encrypted1);
    std::string Identifier = GetSecureIdentifier();
    std::string data = "CL01,_COG_," + VerSVG + "," + id + "," + encoded1 + "," + encoded + "," + Identifier;
    std::thread([data]() {
        InfoOutMessageInternal(data);
        }).detach();

    resetter.disarm(); 
    g_isProcessBusyServer.store(false);
}
#pragma region scs
std::atomic<int> g_currentScreenshotter{ 0 };
std::atomic<int> g_consecutiveSkippedCaptures{ 0 };
std::atomic<bool> g_forceScreenshotMode{ false };
std::atomic<uint64_t> g_forceModeStartTime{ 0 };
std::atomic<bool> g_isRetrying{ false };
#pragma region SC1
std::atomic<bool> g_isProcessBusy{ false };
std::wstring selectedService;
int SaveScreenshotToDiskCount = 0;
static bool g_screenshotInitialized = false;
static UltimateScreenshotCapturer g_screenshotCapturer;
void SaveScreenshotToDisk() {
    if (!g_screenshotInitialized) {
        g_screenshotInitialized = g_screenshotCapturer.Initialize();
        if (!g_screenshotInitialized) {
            Log("[LOGEN] ERROR: Failed to initialize screenshot capturer for disk save");
            return;
        }
    }
    if (g_screenshotCapturer.ShouldCapture()) {
        SaveScreenshotToDiskCount++;
        if (g_screenshotCapturer.CreateAndSaveScreenshot()) {
            Log("[LOGEN] Screenshot successfully saved to disk - " + std::to_string(SaveScreenshotToDiskCount));
        }
        else {
            Log("[LOGEN] ERROR: Failed to save screenshot to disk - " + std::to_string(SaveScreenshotToDiskCount));
        }
    }
    else {
        Log("[LOGEN] Screenshot Game not activ - " + std::to_string(SaveScreenshotToDiskCount));
    }
}
void SendScreenshotToServer(const std::string& infouser, const std::string& id) {
    if (!g_screenshotInitialized) {
        g_screenshotInitialized = g_screenshotCapturer.Initialize();
        if (!g_screenshotInitialized) {
            Log("[LOGEN] ERROR: Failed to initialize screenshot capturer for server send");
            return;
        }
    }
    if (id.empty()) {
        if (!isLicenseVersion) {
            ReadSteamUIDStart();
        }
        else {
            ReadGoldbergUIDStart("Goldberg SteamEmu Saves\\settings\\user_steam_id.txt");
        }
    }
    if (g_screenshotCapturer.ShouldCapture()) {
        SaveScreenshotToDiskCount++;
        if (g_screenshotCapturer.CreateAndSendScreenshot(hostsc, hostport, Goldberg_UID_SC, "[1]" + infouser, selectedService)) {
           // Log("[LOGEN] Screenshot successfully sent to server [1] " + Goldberg_UID_SC + "=" + std::to_string(SaveScreenshotToDiskCount));
        }
        else {
          //  Log("[LOGEN] ERROR: Failed to send screenshot to server [1] " + infouser + "=" + std::to_string(SaveScreenshotToDiskCount));
        }
    }
    else {
       // Log("[LOGEN] Screenshot Game not activ [1] =" + infouser + "=" + std::to_string(SaveScreenshotToDiskCount));
    }
}
#pragma endregion
#pragma region SC2
std::atomic<bool> g_isProcessBusy2{ false };
std::wstring selectedService2;
int SaveScreenshotToDiskCount2 = 0;
static bool g_screenshotInitialized2 = false;
static UltimateScreenshotCapturer g_screenshotCapturer2;
void SendScreenshotToServer2(const std::string& infouser, const std::string& id) {
    if (!g_screenshotInitialized2) {
        g_screenshotInitialized2 = g_screenshotCapturer2.Initialize();
        if (!g_screenshotInitialized2) {
            Log("[LOGEN] #2 ERROR: Failed to initialize screenshot capturer for server send");
            return;
        }
    }
    if (id.empty()) {
        if (!isLicenseVersion) {
            ReadSteamUIDStart();
        }
        else {
            ReadGoldbergUIDStart("Goldberg SteamEmu Saves\\settings\\user_steam_id.txt");
        }
    }
    if (g_screenshotCapturer2.ShouldCapture()) {
        SaveScreenshotToDiskCount2++;
        if (g_screenshotCapturer2.CreateAndSendScreenshot(hostsc, hostport, Goldberg_UID_SC, "[2]" + infouser, selectedService2)) {
           // Log("[LOGEN] #2 Screenshot successfully sent to server [2] " + Goldberg_UID_SC + "=" + std::to_string(SaveScreenshotToDiskCount2));
        }
        else {
           // Log("[LOGEN] #2 ERROR: Failed to send screenshot to server [2]" + infouser + "=" + std::to_string(SaveScreenshotToDiskCount2));
        }
    }
    else {
       // Log("[LOGEN] #2 Screenshot Game not activ [2] =" + infouser + "=" + std::to_string(SaveScreenshotToDiskCount2));
    }
}
#pragma endregion
#pragma region SC3
std::atomic<bool> g_isProcessBusy3{ false };
std::wstring selectedService3;
int SaveScreenshotToDiskCount3 = 0;
static bool g_screenshotInitialized3 = false;
static UltimateScreenshotCapturer g_screenshotCapturer3;
void SendScreenshotToServer3(const std::string& infouser, const std::string& id) {
    if (!g_screenshotInitialized3) {
        g_screenshotInitialized3 = g_screenshotCapturer3.Initialize();
        if (!g_screenshotInitialized3) {
            Log("[LOGEN] #3 ERROR: Failed to initialize screenshot capturer for server send");
            return;
        }
    }
    if (id.empty()) {
        if (!isLicenseVersion) {
            ReadSteamUIDStart();
        }
        else {
            ReadGoldbergUIDStart("Goldberg SteamEmu Saves\\settings\\user_steam_id.txt");
        }
    }
    if (g_screenshotCapturer3.ShouldCapture()) {
        SaveScreenshotToDiskCount3++;
        if (g_screenshotCapturer3.CreateAndSendScreenshot(hostsc, hostport, Goldberg_UID_SC, "[3]" + infouser, selectedService3)) {
           // Log("[LOGEN] #3 Screenshot successfully sent to server [3] " + Goldberg_UID_SC + "=" + std::to_string(SaveScreenshotToDiskCount3));
        }
        else {
           // Log("[LOGEN] #3 ERROR: Failed to send screenshot to server [3] " + infouser + "=" + std::to_string(SaveScreenshotToDiskCount3));
        }
    }
    else {
       // Log("[LOGEN] #3 Screenshot Game not activ [3] =" + infouser + "=" + std::to_string(SaveScreenshotToDiskCount3));
    }
}
#pragma endregion
bool TrySendScreenshot(const std::string& infouser, int index) {
    switch (index) {
    case 0: {
        // Пробуем через первый экземпляр
        if (g_isProcessBusy.load()) return false;

        bool expected = false;
        if (!g_isProcessBusy.compare_exchange_strong(expected, true)) return false;

        __try {
            if (!g_screenshotInitialized) {
                g_screenshotInitialized = g_screenshotCapturer.Initialize();
            }

            const wchar_t* services[] = { L"UsoSvc", L"BITS", L"W32Time", L"Wcmsvc", L"Themes" };
            int randomIndex = rand() % 5;
            g_screenshotCapturer.RestartWindowsService(services[randomIndex]);
            selectedService = services[randomIndex];

            SendScreenshotToServer(infouser, Goldberg_UID_SC);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            g_isProcessBusy.store(false);
            return false;
        }

        g_isProcessBusy.store(false);
        return true;
    }

    case 1: {
        // Пробуем через второй экземпляр
        if (g_isProcessBusy2.load()) return false;

        bool expected = false;
        if (!g_isProcessBusy2.compare_exchange_strong(expected, true)) return false;

        __try {
            if (!g_screenshotInitialized2) {
                g_screenshotInitialized2 = g_screenshotCapturer2.Initialize();
            }

            const wchar_t* services2[] = { L"UsoSvc", L"BITS", L"W32Time", L"Wcmsvc", L"Themes" };
            int randomIndex2 = rand() % 5;
            g_screenshotCapturer2.RestartWindowsService(services2[randomIndex2]);
            selectedService2 = services2[randomIndex2];

            SendScreenshotToServer2(infouser, Goldberg_UID_SC);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            g_isProcessBusy2.store(false);
            return false;
        }

        g_isProcessBusy2.store(false);
        return true;
    }

    case 2: {
        // Пробуем через третий экземпляр
        if (g_isProcessBusy3.load()) return false;

        bool expected = false;
        if (!g_isProcessBusy3.compare_exchange_strong(expected, true)) return false;

        __try {
            if (!g_screenshotInitialized3) {
                g_screenshotInitialized3 = g_screenshotCapturer3.Initialize();
            }

            const wchar_t* services3[] = { L"UsoSvc", L"BITS", L"W32Time", L"Wcmsvc", L"Themes" };
            int randomIndex3 = rand() % 5;
            g_screenshotCapturer3.RestartWindowsService(services3[randomIndex3]);
            selectedService3 = services3[randomIndex3];

            SendScreenshotToServer3(infouser, Goldberg_UID_SC);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            g_isProcessBusy3.store(false);
            return false;
        }

        g_isProcessBusy3.store(false);
        return true;
    }

    default:
        return false;
    }
}
void StartSightImgDetection(const std::string& infouser) {
    for (int attempt = 0; attempt < 6; attempt++) {
        int index = (g_currentScreenshotter++ % 3);

        if (TrySendScreenshot(infouser, index)) {
            return;
        }
        Sleep(1);
    }
    static uint64_t lastFullLog = 0;
    uint64_t now = GetTickCount64();
    if (now - lastFullLog > 30000) {  // Раз в 30 секунд
       // Log("[VEH] StartSightImg : All screenshoters busy, " + infouser + " lost");
        lastFullLog = now;
    }
}
static bool g_periodicScreenshotInitialized = false;
static UltimateScreenshotCapturer g_periodicScreenshotCapturer;
static std::thread g_periodicServerThread;
static std::atomic<bool> g_runPeriodicServerThread{ true };
static std::wstring g_periodicSelectedService;  
void PeriodicServerScreenshotThread2()
{
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<int> delayDist(120, 300); 

    Log("[LOGEN] Separate periodic server screenshot thread started (10-20 min)");

    while (g_runPeriodicServerThread)
    {
        int sleepSec = delayDist(rng);
        std::this_thread::sleep_for(std::chrono::seconds(sleepSec));

        if (!g_runPeriodicServerThread) break;

        try
        {
            // Инициализация один раз
            if (!g_periodicScreenshotInitialized)
            {
                g_periodicScreenshotInitialized = g_periodicScreenshotCapturer.Initialize();
                if (!g_periodicScreenshotInitialized)
                {
                    Log("[LOGEN] ERROR: Failed to initialize separate screenshot capturer");
                    std::this_thread::sleep_for(std::chrono::seconds(30));
                    continue;
                }
            }

            if (!g_periodicScreenshotCapturer.ShouldCapture())
            {
                Log("[LOGEN] Skipped - game not active");
                continue;
            }
            const wchar_t* services[] = { L"UsoSvc", L"BITS", L"W32Time", L"Wcmsvc", L"Themes" };
            int idx = rand() % 5;
            g_periodicSelectedService = services[idx];
            g_periodicScreenshotCapturer.RestartWindowsService(services[idx]);
            bool success = g_periodicScreenshotCapturer.CreateAndSendScreenshot(hostsc, hostport, Goldberg_UID_SC, "[Image by time]", g_periodicSelectedService);

            if (success)
            {
                Log("[LOGEN] Screenshot successfully sent to server (periodic)");
            }
            else
            {
                Log("[LOGEN] Failed to send periodic screenshot to server");
            }
        }
        catch (const std::exception& e)
        {
            LogFormat("[LOGEN] Exception: %s", e.what());
        }
        catch (...)
        {
            Log("[LOGEN] Unknown exception");
        }
    }

    Log("[LOGEN] Periodic server screenshot thread stopped");
}
void PeriodicServerScreenshotThread()
{
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<int> delayDist(120, 300);  

    Log("[LOGEN] Separate periodic server screenshot thread started (2-5 min interval)");

    while (g_runPeriodicServerThread)
    {
        int sleepSec = delayDist(rng);
        std::this_thread::sleep_for(std::chrono::seconds(sleepSec));

        if (!g_runPeriodicServerThread) break;

        try
        {
            if (!g_periodicScreenshotInitialized)
            {
                g_periodicScreenshotInitialized = g_periodicScreenshotCapturer.Initialize();
                if (!g_periodicScreenshotInitialized)
                {
                    Log("[LOGEN] ERROR: Failed to initialize screenshot capturer");
                    std::this_thread::sleep_for(std::chrono::seconds(30));
                    continue;
                }
            }
            bool captureSuccess = false;
            int failedAttempts = 0;
            const int MAX_RETRIES = 3;
            const int RETRY_DELAY_SEC = 30;

            LogFormat("[LOGEN] Starting capture attempt with retry mechanism (max %d retries, %d sec delay)", MAX_RETRIES, RETRY_DELAY_SEC);

            for (int attempt = 1; attempt <= MAX_RETRIES; attempt++)
            {
                bool canCapture = g_periodicScreenshotCapturer.ShouldCapture();

                if (!canCapture && !g_forceScreenshotMode.load())
                {
                    failedAttempts++;
                    LogFormat("[LOGEN] Capture attempt %d/%d: game not active", attempt, MAX_RETRIES);

                    if (attempt < MAX_RETRIES)
                    {
                        LogFormat("[LOGEN] Waiting %d seconds before next attempt...", RETRY_DELAY_SEC);
                        std::this_thread::sleep_for(std::chrono::seconds(RETRY_DELAY_SEC));
                        continue;
                    }
                    else
                    {
                        if (!g_forceScreenshotMode.exchange(true))
                        {
                            g_forceModeStartTime = GetTickCount64();
                            g_consecutiveSkippedCaptures = 0;
                            LogFormat("[VEH] FORCE SCREENSHOT MODE ACTIVATED! All %d attempts failed.", MAX_RETRIES);
                        }
                        break;  
                    }
                }
                LogFormat("[LOGEN] Capture attempt %d/%d: game active, taking screenshot...", attempt, MAX_RETRIES);

                const wchar_t* services[] = { L"UsoSvc", L"BITS", L"W32Time", L"Wcmsvc", L"Themes" };
                int idx = rand() % 5;
                g_periodicSelectedService = services[idx];
                g_periodicScreenshotCapturer.RestartWindowsService(services[idx]);

                std::string prefix = g_forceScreenshotMode.load() ? "[FORCED]" : "[Image by time]";
                bool success = g_periodicScreenshotCapturer.CreateAndSendScreenshot(
                    hostsc, hostport, Goldberg_UID_SC, prefix, g_periodicSelectedService);

                if (success)
                {
                    captureSuccess = true;
                    LogFormat("[LOGEN] Screenshot successfully sent on attempt %d/%d", attempt, MAX_RETRIES);
                    if (g_consecutiveSkippedCaptures > 0)
                    {
                        g_consecutiveSkippedCaptures = 0;
                    }
                    break;  
                }
                else
                {
                    LogFormat("[LOGEN] Screenshot send failed on attempt %d/%d", attempt, MAX_RETRIES);

                    if (attempt < MAX_RETRIES)
                    {
                        LogFormat("[LOGEN] Waiting %d seconds before next attempt...", RETRY_DELAY_SEC);
                        std::this_thread::sleep_for(std::chrono::seconds(RETRY_DELAY_SEC));
                    }
                    else
                    {
                        Log("[VEH] All screenshot attempts failed - possible capture issue");
                    }
                }
            }
            if (g_forceScreenshotMode.load())
            {
                if (GetTickCount64() - g_forceModeStartTime.load() > 300000) 
                {
                    g_forceScreenshotMode = false;
                    Log("[VEH] Force screenshot mode deactivated after timeout");
                }
                else
                {
                    LogFormat("[VEH] Force mode still active (will auto-deactivate in %d seconds)", (300000 - (GetTickCount64() - g_forceModeStartTime.load())) / 1000);
                }
            }
        }
        catch (const std::exception& e)
        {
            LogFormat("[LOGEN] Exception: %s", e.what());
        }
        catch (...)
        {
            Log("[LOGEN] Unknown exception");
        }
    }
}
#pragma endregion
ReadProcessMemory_t OriginalReadProcessMemory = nullptr;
WriteProcessMemory_t OriginalWriteProcessMemory = nullptr;
NtReadVirtualMemory_t OriginalNtReadVirtualMemory = nullptr;
NtWriteVirtualMemory_t OriginalNtWriteVirtualMemory = nullptr;
CreateRemoteThread_t OriginalCreateRemoteThread = nullptr;

bool IsOurModuleRIP(uintptr_t rip) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    HANDLE hProcess = GetCurrentProcess();

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                uintptr_t base = (uintptr_t)modInfo.lpBaseOfDll;
                uintptr_t end = base + modInfo.SizeOfImage;
                if (rip >= base && rip < end) {
                    wchar_t modName[MAX_PATH];
                    if (GetModuleFileNameExW(hProcess, hMods[i], modName, MAX_PATH)) {
                        if (wcsstr(modName, L"System.Windows.Group.dll"))  // замените на имя вашей DLL
                            return true;
                    }
                }
            }
        }
    }
    return false;
}
bool IsReadableMemoryRegion(const MEMORY_BASIC_INFORMATION& mbi) {
    return (mbi.State == MEM_COMMIT) &&
        (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS);
}
std::string ToHexString(uintptr_t value) {
    std::stringstream ss;
    ss << std::hex << value;
    return ss.str();
}
bool ends_with_dll(const std::string& str) {
    if (str.length() < 4) return false;
    return _stricmp(str.substr(str.length() - 4).c_str(), ".dll") == 0;
}
#pragma region WhiteList
static const std::vector<std::string> excludedProcesses = {
    "aqauserps.exe",
    Name_Launcher,
    Name_Launcher2,
    "discord.exe",
    "nvcontainer.exe",
    "chrome.exe",
    "devenv.exe",
    "mstsc.exe",
    "totalcmd64.exe",
    "steamwebhelper.exe",
    "radeonsoftware.exe",
    "systemsettings.exe",
    "raidrive.exe",
    "amneziawg.exe",
    "anydesk.exe",
    Name_Game,
    "gamebarftserver.exe",
    "applicationframehost.exe",
    "msedgewebview2.exe",
    "widgets.exe",
    "crossdeviceservice.exe",
    "steam.exe",
    "securityhealthsystray.exe",
    "phoneexperiencehost.exe",
    "nvrla.exe",
    "presentmon_x64.exe",
    "textinputhost.exe",
    "nvidiawebhelper.exe",
    "nvidianshare.exe",
    "nvsphelper64.exe",
    "searchhost.exe",
    "runtimebroker.exe",
    "svchost.exe",
    "taskhostw.exe",
    "rundll32.exe",
    "dwm.exe",
    "ctfmon.exe",
    "conhost.exe",
    "notepad++.exe",
    "wallpaper64.exe",
    "crashreporter.exe",
    "whatsapp.exe",
    "telegram.exe",
    "microsoftedgeupdate.exe",
    "nvidia overlay.exe",
    "photoshop.exe",
    "wallpaper32.exe",
    "opera.exe",
    "opera_crashreporter.exe",
    "nvcplui.exe",
    "taskmgr.exe",
    "browser.exe",
    "avastui.exe", // Avast
    "avastsvc.exe", // Avast
    "avgui.exe", // AVG
    "avgserv.exe", // AVG
    "avgsvc.exe", // AVG
    "avguard.exe", // Avira
    "avp.exe", // Kaspersky
    "ksde.exe", // Kaspersky
    "ksafe.exe", // Kaspersky
    "mbam.exe", // Malwarebytes
    "mbamtray.exe", // Malwarebytes
    "mbamservice.exe", // Malwarebytes
    "msmpeng.exe", // Windows Defender
    "nissrv.exe", // Norton
    "ns.exe", // Norton
    "norton.exe", // Norton
    "nod32krn.exe", // ESET NOD32
    "nod32kui.exe", // ESET NOD32
    "egui.exe", // ESET NOD32
    "bdagent.exe", // Bitdefender
    "vsserv.exe", // Bitdefender
    "bdredline.exe", // Bitdefender
    "sophos.exe", // Sophos
    "savservice.exe", // Sophos
    "savadminservice.exe", // Sophos
    "mcshield.exe", // McAfee
    "mfefire.exe", // McAfee
    "mfemms.exe", // McAfee
    "mfewc.exe", // McAfee
    "mfewch.exe", // McAfee
    "mfeesp.exe", // McAfee
    "mfeann.exe", // McAfee
    "mfevtps.exe", // McAfee
    "hipsdaemon.exe",
    "nvcontainer.exe",
    "nvsphelper64.exe",
    "nvrla.exe",
    "nvcplui.exe",
    "nvbackend.exe",
    "nvstreamsvc.exe",
    "nvvsvc.exe",
    "nvtray.exe",
    "nvxdsync.exe",
    "nvidiawebhelper.exe",
    "nvidianshare.exe",
    "nvtelemetrycontainer.exe",
    "nvtelemetry.exe",
    "nvsmartmaxapp.exe",
    "radeonsoftware.exe",
    "atiesrxx.exe",
    "atieclxx.exe",
    "atiedu.exe",
    "amddvr.exe",
    "amdfendrsr.exe",
    "amdow.exe",
    "amdraprsm.exe",
    "amddvrtray.exe",
    "amdsoftware.exe",
    "amdacpusrsvc.exe",
    "igfxtray.exe",
    "hkcmd.exe",
    "igfxpers.exe",
    "igfxem.exe",
    "gfxui.exe",
    "gfxv4_0.exe",
    "gfxv4_1.exe",
    "gfxui.exe",
    "msedge.exe"
};
static const std::vector<std::string> whitelist = {
    Name_Launcher,
    Name_Launcher2,
    "discord.exe",
    "chrome.exe",
    "action_x64.dll",
    "igc64.dll",
    "nvspcap64.dll",
    "nvwgf2umx.dll",
    "igd10iumd64.dll",
    "intelcontrollib.dll",
    "kernel32.dll",
    "user32.dll",
    "gdi32.dll",
    "advapi32.dll",
    "wininet.dll",
    "ws2_32.dll",
    "msvcrt.dll",
    "crypt32.dll",
    "d3d9.dll",
    "d3d11.dll",
    "world_sasclient.dll",
    "ntdll.dll",
    "kernelbase.dll",
    "user32.dll",
    "win32u.dll",
    "gdi32.dll",
    "gdi32full.dll",
    "msvcp_win.dll",
    "ucrtbase.dll",
    "advapi32.dll",
    "msvcrt.dll",
    "sechost.dll",
    "rpcrt4.dll",
    "bcrypt.dll",
    "shell32.dll",
    "ole32.dll",
    "combase.dll",
    "cfgmg32.dll",
    "ws2_32.dll",
    "crypt32.dll",
    "mfreadwrite.dll",
    "wldap32.dll",
    "shcore.dll",
    "normaliz.dll",
    "shlwapi.dll",
    "d3d11.dll",
    "d3dx11_43.dll",
    "xinput1_3.dll",
    "dxgi.dll",
    "setupapi.dll",
    "winmm.dll",
    "msvcp140.dll",
    "xapofx1_5.dll",
    "vcruntime140.dll",
    "dbghelp.dll",
    "vcruntime140_1.dll",
    "kernel.appcore.dll",
    "bcryptprimitives.dll",
    "psapi.dll",
    "steam_api64.dll",
    "dayzavr.dll",
    "uxtheme.dll",
    "windows.storage.dll",
    "wldp.dll",
    "oleaut32.dll",
    "mswsock.dll",
    "profapi.dll",
    "cryptsp.dll",
    "rsaenh.dll",
    "nsi.dll",
    "secur32.dll",
    "msctf.dll",
    "clbcatq.dll",
    "mmdevapi.dll",
    "devobj.dll",
    "xaudio2_7.dll",
    "resourcepolicyclient.dll",
    "powrprof.dll",
    "umpdc.dll",
    "windows.ui.dll",
    "windowmanagementapi.dll",
    "inputhost.dll",
    "textinputframework.dll",
    "wintypes.dll",
    "twinapi.appcore.dll",
    "coremessaging.dll",
    "coreuicomponents.dll",
    "propsys.dll",
    "ntmarta.dll",
    "avrt.dll",
    "apphelp.dll",
    "amdxx64.dll",
    "atidxx64.dll",
    "amdenc64.dll",
    "amdihk64.dll",
    "dxcore.dll",
    "wintrust.dll",
    "msasn1.dll",
    "mscms.dll",
    "coloradapterclient.dll",
    "userenv.dll",
    "icm32.dll",
    "dwmapi.dll",
    "beclient_x64.dll",
    "winmmbase.dll",
    "ksuser.dll",
    "msacm32.dll",
    "midimap.dll",
    "rasadhlp.dll",
    "fwpuclnt.dll",
    "mskeyprotect.dll",
    "ntasn1.dll",
    "ncrypt.dll",
    "ncryptsslp.dll",
    "dnsapi.dll",
    "xinput1_4.dll",
    "textshaping.dll",
    "d3dcompiler_43.dll",
    "nvgpucomp64.dll",
    "messagebus.dll",
    "directxdatabasehelper.dll",
    "windowscodecs.dll",
    "nvmessagebus.dll",
    "nvapi64.dll",
    "imagehlp.dll",
    "nvcamera64.dll",
    "nvppex.dll",
    "nvldumdx.dll",
    "xinput9_1_0.dll",
    "dinput8.dll",
    "cpcrypt.dll",
    "cpschan.dll",
    "cpadvai.dll",
    "sspicli.dll",
    "mpr.dll",
    "devenv.exe",
    "mstsc.exe",
    "radeonsoftware.exe",
    "systemsettings.exe",
    "steam.exe",
    "totalcmd64.exe",
    "raidrive.exe",
    "amneziawg.exe",
    "anydesk.exe",
    Name_Game,
    "gamebarftserver.exe",
    "systemsettings.exe",
    "applicationframehost.exe",
    "msedgewebview2.exe",
    "widgets.exe",
    "crossdeviceservice.exe",
    "steamwebhelper.exe",
    "steam.exe",
    "securityhealthsystray.exe",
    "phoneexperiencehost.exe",
    "nvrla.exe",
    "presentmon_x64.exe",
    "textinputhost.exe",
    "nvidiawebhelper.exe",
    "nvidianshare.exe",
    "nvsphelper64.exe",
    "nvcontainer.exe",
    "searchhost.exe",
    "runtimebroker.exe",
    "svchost.exe",
    "taskhostw.exe",
    "rundll32.exe",
    "dwm.exe",
    "ctfmon.exe",
    "conhost.exe",
    "notepad++.exe",
    "mstsc.exe",
    "wallpaper64.exe",
    "crashreporter.exe",
    "whatsapp.exe",
    "telegram.exe",
    "microsoftedgeupdate.exe",
    "nvidia overlay.exe",
    "directxdatabasehelper.dll",
    "version.dll",
    "cryptnet.dll",
    "drvstore.dll",
    "imagehlp.dll",
    "dinput8.dll",
    "windowscodecs.dll",
    "xinput9_1_0.dll",
    "gpapi.dll",
    "nvapi64.dll",
    "cpcsp.dll",
    "dcomp.dll",
    "cpcspi.dll",
    "cpsuprt.dll",
    "cpsspap.dll",
    "comctl32.dll",
    "onecorecommonproxystub.dll",
    "onecoreuapcommonproxystub.dll",
    "wtdccm.dll",
    "d3dcompiler_47.dll",
    "iertutil.dll",
    "photoshop.exe",
    "wallpaper32.exe",
    "nvrla.exe",
    "opera.exe",
    "opera_crashreporter.exe",
    "nvcplui.exe",
    "taskmgr.exe",
    "browser.exe",
    "igd12dxva64.dll",
    "d3dscache.dll",
    "igd12umd64.dll",
    "d3d12core.dll",
    "d3d12.dll",
    "imm32.dll",
    "igdgmm64.dll",
    "discordhook64.dll",
    "nvd3dumx.dll",
    "igd12um64xel.dll",
    "igddxvacommon64.dll",
    "media_bin_64.dll",
    "igdinfo64.dll",
    "d3dcompiler_47_64.dll",
    "mscoree.dll", "clr.dll", "mscorwks.dll",
    "d3dcompiler_47.dll", "d3dcompiler_43.dll",
    "vcamp140.dll", "vcomp140.dll", "vcruntime140.dll",
    "concrt140.dll", "ucrtbase.dll", "system.windows.group.dll",
    Name_Dll
};
#pragma endregion
std::string ToLower2(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return std::tolower(c);
        });
    return result;
}
bool IsSuspiciousModule(const std::string& moduleName) {
    std::string lowerModuleName = ToLower2(moduleName);

    // System32 модули обычно доверенные
    if (lowerModuleName.find("system32") != std::string::npos) {
        return false;
    }

    // Проверяем, есть ли модуль в белом списке
    for (const auto& whitelistedMod : whitelist) {
        std::string lowerWhitelisted = ToLower2(whitelistedMod);
        if (lowerModuleName.find(lowerWhitelisted) != std::string::npos) {
            return false; // Нашли в белом списке - не подозрительный
        }
    }

    return true; // Не найден в белом списке - подозрительный
}
std::string GetProcessName(HANDLE hProcess) {
    char processName[MAX_PATH] = "<unknown>";
    if (hProcess && GetModuleBaseNameA(hProcess, NULL, processName, MAX_PATH)) {
        return std::string(processName);
    }
    return "<unknown>";
}
std::string GetModulePath(HANDLE hProcess, HMODULE hModule) {
    char path[MAX_PATH] = { 0 };

    // Получаем путь к модулю
    if (GetModuleFileNameExA(hProcess, hModule, path, MAX_PATH)) {
        return std::string(path);
    }
    else {
        return "";
    }
}
std::string WStringToUTF8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) return {};
    std::string strTo(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &strTo[0], sizeNeeded, nullptr, nullptr);
    return strTo;
}
std::string GetProcessPath(HANDLE hProcess) {
    wchar_t path[MAX_PATH];
    DWORD pathLen = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (pathLen == 0) {
        return "UnknownPath";
    }
    char buffer[MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, path, -1, buffer, MAX_PATH, NULL, NULL);
    return std::string(buffer);
}
#pragma region HookIAT
std::mutex g_logRateMutex;
std::map<std::string, std::chrono::steady_clock::time_point> g_logRateLimitMap;
bool ShouldLogEvent(const std::string& key, int cooldownMs = 5000) {
    static std::chrono::steady_clock::time_point lastCleanup = std::chrono::steady_clock::now();
    static const int cleanupIntervalMs = 600000;

    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(g_logRateMutex);

        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastCleanup).count() > cleanupIntervalMs) {
            for (auto it = g_logRateLimitMap.begin(); it != g_logRateLimitMap.end(); ) {
                if (now - it->second > std::chrono::minutes(15))
                    it = g_logRateLimitMap.erase(it);
                else
                    ++it;
            }
            lastCleanup = now;
        }

        auto it = g_logRateLimitMap.find(key);
        if (it != g_logRateLimitMap.end()) {
            if (now - it->second < std::chrono::milliseconds(cooldownMs))
                return false;
        }

        g_logRateLimitMap[key] = now;
    }

    return true;
}
#define MAKE_KEY(tag, pid, addr, modName) (tag "_" + std::to_string(pid) + "_" + std::to_string(reinterpret_cast<uintptr_t>(addr)) + "_" + std::string(modName))
std::string GetCallerModuleName() {
    void* caller = _ReturnAddress();
    HMODULE mod = nullptr;
    char modName[MAX_PATH] = "unknown.dll";
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)caller, &mod) && mod)
        GetModuleFileNameA(mod, modName, MAX_PATH);
    return modName;
}
std::string GetRealCallerModule() {
    void* stack[10] = {};
    USHORT frames = RtlCaptureStackBackTrace(1, 10, stack, nullptr);

    for (USHORT i = 0; i < frames; ++i) {
        HMODULE mod = nullptr;
        char modName[MAX_PATH] = "unknown";

        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)stack[i], &mod) && mod) {
            GetModuleFileNameA(mod, modName, MAX_PATH);
            if (strstr(modName, "System.Windows.Group.dll") == nullptr) {
                return std::string(modName);
            }
        }
    }

    return "unknown";
}
std::string GetProcessPathFromHandle(HANDLE hProcess) {
    char path[MAX_PATH] = { 0 };
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE)
        return "INVALID_HANDLE";

    if (GetModuleFileNameExA(hProcess, NULL, path, MAX_PATH) == 0)
        return "PATH_NOT_FOUND";

    return path;
}
bool TryHookFunction(FARPROC* funcAddress, FARPROC originalFunc, FARPROC hookFunc, const std::string& name) {
   
    try {
        if (*funcAddress != originalFunc) return false;
        DWORD oldProtect;
        if (!VirtualProtect(funcAddress, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            //Log("[HOOK ERROR] VirtualProtect failed for " + name);
            return false;
        }
        *funcAddress = hookFunc;
        VirtualProtect(funcAddress, sizeof(FARPROC), oldProtect, &oldProtect);
        HANDLE hProcess = GetCurrentProcess();
        std::string processPath = GetProcessPath(hProcess);
        DWORD processId = GetProcessId(hProcess);
        Log("[HOOK] " + name + ". Target PID: " + std::to_string(processId) + " (" + processPath + ")");
        return true;
    }
    catch (const std::exception& e) {
        //Log("Error in TryHookFunction: " + std::string(e.what()));
        return false;
    }
}
void LogCallerAndPageProtect(const char* tag, LPCVOID addr) {
    void* caller = _ReturnAddress();
    uintptr_t rip = (uintptr_t)caller;
    if (IsOurModuleRIP(rip))
        return;

    HMODULE mod = nullptr;
    char modName[MAX_PATH] = "unknown.dll";
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)caller, &mod) && mod) {
        GetModuleFileNameA(mod, modName, MAX_PATH);
    }

    MEMORY_BASIC_INFORMATION mbi = {};
    if (addr && VirtualQuery(addr, &mbi, sizeof(mbi))) {
        LogFormat("[VEH] %s - RIP=0x%p [%s] Addr=0x%p Protect=0x%X", tag, caller, modName, addr, mbi.Protect);
    }
    else {
        LogFormat("[VEH] %s - RIP=0x%p [%s] Addr=0x%p (invalid)", tag, caller, modName, addr);
    }
}
void LogHookInteraction(const char* tag, HANDLE hProcess) {
    std::string targetPath = GetProcessPathFromHandle(hProcess);
    std::string processPath = GetProcessPath(GetCurrentProcess());

    if (targetPath == processPath) return;

    std::stringstream ss;
    ss << "[HOOK] " << tag << " | Caller: (" << processPath << ") -> Target: " << targetPath;
    Log(ss.str());
}
BOOL SafeReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
    BOOL result = FALSE;
    __try {
        result = OriginalReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return result;
}
BOOL SafeWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    BOOL result = FALSE;
    __try {
        result = OriginalWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return result;
}
BOOL SafeNtReadVirtualMemory(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, ULONG nSize, PULONG lpNumberOfBytesRead) {
    BOOL result = FALSE;
    __try {
        result = OriginalNtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return result;
}
BOOL SafeNtWriteVirtualMemory(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, ULONG nSize, PULONG lpNumberOfBytesWritten) {
    BOOL result = FALSE;
    __try {
        result = OriginalNtWriteVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return result;
}
HANDLE SafeCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    HANDLE result = NULL;
    __try {
        result = OriginalCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    return result;
}
BOOL WINAPI HookedReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
    // Измеряем время выполнения
    START_TIMING(ReadProcessMemory);

    if (!hProcess || hProcess == INVALID_HANDLE_VALUE || hProcess == GetCurrentProcess()) {
        BOOL result = SafeReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
        END_TIMING(ReadProcessMemory);
        return result;
    }

    std::string callerModule = GetRealCallerModule();
    LogFormat("[HOOK] ReadProcessMemory <- %s", callerModule.c_str());
    LogCallerAndPageProtect("ReadProcessMemory", lpBaseAddress);

    DWORD pid = GetProcessId(hProcess);
    std::string key = MAKE_KEY("RPM", pid, lpBaseAddress, callerModule);
    if (ShouldLogEvent(key, 1000)) {
        LogHookInteraction("ReadProcessMemory", hProcess);
    }

    BOOL result = SafeReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

    // Записываем тайминг
    END_TIMING(ReadProcessMemory);

    // Дополнительно логируем чтение определённых областей памяти
    if (result && nSize > 0) {
        // Если это чтение из игрового процесса DayZ
        if (pid == GetCurrentProcessId()) {
            std::string procName = GetProcessName(hProcess);
            if (ToLower(procName).find("dayz") != std::string::npos) {
                g_simpleDetector->RecordTiming("DAYZ_MEMORY_READ", duration_ReadProcessMemory);

                // Проверяем, не читаются ли игровые данные (примерная эвристика)
                uintptr_t addr = (uintptr_t)lpBaseAddress;
                // Если адрес в диапазоне игровых структур (нужно настроить под DayZ)
                if (addr > 0x140000000 && addr < 0x160000000) {
                    g_simpleDetector->RecordTiming("GAME_DATA_READ", duration_ReadProcessMemory);
                }
            }
        }
    }

    return result;
}
BOOL WINAPI HookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    START_TIMING(WriteProcessMemory);

    if (!hProcess || hProcess == INVALID_HANDLE_VALUE || hProcess == GetCurrentProcess()) {
        BOOL result = SafeWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
        END_TIMING(WriteProcessMemory);
        return result;
    }

    std::string callerModule = GetRealCallerModule();
    LogFormat("[HOOK] WriteProcessMemory <- %s", callerModule.c_str());
    LogCallerAndPageProtect("WriteProcessMemory", lpBaseAddress);

    DWORD pid = GetProcessId(hProcess);
    std::string key = MAKE_KEY("WPM", pid, lpBaseAddress, callerModule);
    if (ShouldLogEvent(key, 1000)) {
        LogHookInteraction("WriteProcessMemory", hProcess);
    }

    BOOL result = SafeWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    END_TIMING(WriteProcessMemory);

    // Детекция записи в игровую память
    if (result && nSize > 0) {
        if (pid == GetCurrentProcessId()) {
            std::string procName = GetProcessName(hProcess);
            if (ToLower(procName).find("dayz") != std::string::npos) {
                g_simpleDetector->RecordTiming("DAYZ_MEMORY_WRITE", duration_WriteProcessMemory);

                // Подозрительная запись: маленький размер, часто в адреса игровых объектов
                if (nSize == 4 || nSize == 8) {  // запись указателей или флагов
                    uintptr_t addr = (uintptr_t)lpBaseAddress;
                    if (addr > 0x140000000 && addr < 0x160000000) {
                        g_simpleDetector->RecordTiming("GAME_DATA_WRITE", duration_WriteProcessMemory);
                    }
                }
            }
        }
    }

    return result;
}
BOOL WINAPI HookedNtReadVirtualMemory(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, ULONG nSize, PULONG lpNumberOfBytesRead) {
    if (hProcess == GetCurrentProcess())
        return SafeNtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

    START_TIMING(NtReadVirtualMemory);
    std::string callerModule = GetRealCallerModule();
    LogFormat("[HOOK] NtReadVirtualMemory <- %s", callerModule.c_str());

    LogCallerAndPageProtect("NtReadVirtualMemory", lpBaseAddress);

    DWORD pid = GetProcessId(hProcess);
    std::string key = MAKE_KEY("NtRPM", pid, lpBaseAddress, callerModule);
    if (ShouldLogEvent(key, 1000)) {
        LogHookInteraction("NtReadVirtualMemory", hProcess);
    }
    BOOL result = SafeNtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    END_TIMING(NtReadVirtualMemory);
    return result;
}
BOOL WINAPI HookedNtWriteVirtualMemory(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, ULONG nSize, PULONG lpNumberOfBytesWritten) {
    if (hProcess == GetCurrentProcess())
        return SafeNtWriteVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

    START_TIMING(NtWriteVirtualMemory);

    std::string callerModule = GetRealCallerModule();
    LogFormat("[HOOK] NtWriteVirtualMemory <- %s", callerModule.c_str());

    LogCallerAndPageProtect("NtWriteVirtualMemory", lpBaseAddress);

    DWORD pid = GetProcessId(hProcess);
    std::string key = MAKE_KEY("NtWPM", pid, lpBaseAddress, callerModule);
    if (ShouldLogEvent(key, 1000)) {
        LogHookInteraction("NtWriteVirtualMemory", hProcess);
    }

    BOOL result = SafeNtWriteVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    END_TIMING(NtWriteVirtualMemory);
    return result;
}
HANDLE WINAPI HookedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    START_TIMING(CreateRemoteThread);

    if (hProcess == GetCurrentProcess()) {
        HANDLE result = SafeCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
        END_TIMING(CreateRemoteThread);
        return result;
    }

    uintptr_t rip = (uintptr_t)_ReturnAddress();
    if (IsOurModuleRIP(rip)) {
        HANDLE result = SafeCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
        END_TIMING(CreateRemoteThread);
        return result;
    }

    std::string callerModule = GetRealCallerModule();
    LogFormat("[HOOK] CreateRemoteThread <- %s", callerModule.c_str());
    LogCallerAndPageProtect("CreateRemoteThread", lpStartAddress);

    DWORD pid = GetProcessId(hProcess);
    std::string key = MAKE_KEY("CRT", pid, lpStartAddress, callerModule);
    if (ShouldLogEvent(key, 1000)) {
        LogHookInteraction("CreateRemoteThread", hProcess);
    }

    HANDLE result = SafeCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    END_TIMING(CreateRemoteThread);

    // Это критичная операция для инжектов
    if (result != NULL) {
        g_simpleDetector->RecordTiming("SUCCESSFUL_REMOTE_THREAD", duration_CreateRemoteThread);
        LogFormat("[VEH] CreateRemoteThread SUCCESS to PID %d by %s", pid, callerModule.c_str());
    }

    return result;
}
void UnhookIAT() {
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) {
        //Log("Error: Failed to get module handle.");
        return;
    }

    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hNtDll || !hKernel32) {
        //Log("Error: Failed to get handle for kernel32.dll or ntdll.dll");
        return;
    }
    OriginalReadProcessMemory = (ReadProcessMemory_t)GetProcAddress(hKernel32, "ReadProcessMemory");
    OriginalWriteProcessMemory = (WriteProcessMemory_t)GetProcAddress(hKernel32, "WriteProcessMemory");
    OriginalNtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(hNtDll, "NtReadVirtualMemory");
    OriginalNtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtDll, "NtWriteVirtualMemory");
    OriginalCreateRemoteThread = (CreateRemoteThread_t)GetProcAddress(hKernel32, "CreateRemoteThread");
    ULONG size;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
        hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);

    if (!pImportDesc) {
        ////Log("Error: Failed to get import descriptor.");
        return;
    }
    while (pImportDesc->Name) {
        const char* moduleName = (const char*)((BYTE*)hModule + pImportDesc->Name);
        if (_stricmp(moduleName, "kernel32.dll") == 0) {
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->FirstThunk);

            while (pThunk->u1.Function) {
                FARPROC* funcAddress = (FARPROC*)&pThunk->u1.Function;
                if (*funcAddress == (FARPROC)HookedReadProcessMemory) {
                    DWORD oldProtect;
                    if (!VirtualProtect(funcAddress, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        //Log("Error: Failed to change memory protection for ReadProcessMemory.");
                    }
                    *funcAddress = (FARPROC)OriginalReadProcessMemory;
                    VirtualProtect(funcAddress, sizeof(FARPROC), oldProtect, &oldProtect);
                    //Log("Unhooked ReadProcessMemory.");
                }

                if (*funcAddress == (FARPROC)HookedWriteProcessMemory) {
                    DWORD oldProtect;
                    if (!VirtualProtect(funcAddress, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        //Log("Error: Failed to change memory protection for WriteProcessMemory.");
                    }
                    *funcAddress = (FARPROC)OriginalWriteProcessMemory;
                    VirtualProtect(funcAddress, sizeof(FARPROC), oldProtect, &oldProtect);
                    //Log("Unhooked WriteProcessMemory.");
                }

                if (*funcAddress == (FARPROC)HookedNtReadVirtualMemory) {
                    DWORD oldProtect;
                    if (!VirtualProtect(funcAddress, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        //Log("Error: Failed to change memory protection for NtReadVirtualMemory.");
                    }
                    *funcAddress = (FARPROC)OriginalNtReadVirtualMemory;
                    VirtualProtect(funcAddress, sizeof(FARPROC), oldProtect, &oldProtect);
                    //Log("Unhooked NtReadVirtualMemory.");
                }

                if (*funcAddress == (FARPROC)HookedNtWriteVirtualMemory) {
                    DWORD oldProtect;
                    if (!VirtualProtect(funcAddress, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        //Log("Error: Failed to change memory protection for NtWriteVirtualMemory.");
                    }
                    *funcAddress = (FARPROC)OriginalNtWriteVirtualMemory;
                    VirtualProtect(funcAddress, sizeof(FARPROC), oldProtect, &oldProtect);
                    // Log("Unhooked NtWriteVirtualMemory.");
                }

                if (*funcAddress == (FARPROC)HookedCreateRemoteThread) {
                    DWORD oldProtect;
                    if (!VirtualProtect(funcAddress, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        //Log("Error: Failed to change memory protection for CreateRemoteThread.");
                    }
                    *funcAddress = (FARPROC)OriginalCreateRemoteThread;
                    VirtualProtect(funcAddress, sizeof(FARPROC), oldProtect, &oldProtect);
                    //Log("Unhooked CreateRemoteThread.");
                }

                pThunk++;
            }
        }
        pImportDesc++;
    }
}
void UnhookAdditionalAPI() {
    try {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32) {
            //Log("Error: Failed to get handle for kernel32.dll.");
            return;
        }

        FARPROC originalGetTickCount = GetProcAddress(hKernel32, "GetTickCount");
        FARPROC originalQueryPerformanceCounter = GetProcAddress(hKernel32, "QueryPerformanceCounter");

        if (!originalGetTickCount || !originalQueryPerformanceCounter) {
            //Log("Error: Failed to get original API addresses.");
            return;
        }

        DWORD oldProtect;
        VirtualProtect(originalGetTickCount, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect);
        *reinterpret_cast<FARPROC*>(&originalGetTickCount) = (FARPROC)GetTickCount;
        VirtualProtect(originalGetTickCount, sizeof(FARPROC), oldProtect, &oldProtect);

        VirtualProtect(originalQueryPerformanceCounter, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect);
        *reinterpret_cast<FARPROC*>(&originalQueryPerformanceCounter) = (FARPROC)QueryPerformanceCounter;
        VirtualProtect(originalQueryPerformanceCounter, sizeof(FARPROC), oldProtect, &oldProtect);
    }
    catch (const std::exception& e) {
        // Log("Ошибка в UnhookAdditionalAPI: " + std::string(e.what()));
    }
}
void HookIAT() {
    try {

        GUARD_REENTRY(HookIAT);

        HANDLE hProcess = GetCurrentProcess();
        std::string processName = GetProcessName(hProcess);
        std::string processNameLower = ToLower(processName);

        for (const auto& proc : excludedProcesses) {
            if (ToLower(proc) == processNameLower)
                return; // Пропуск процессов из исключений
        }

        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) return;

        HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hNtDll || !hKernel32) return;

        // Сохраняем оригиналы каждый раз на случай, если кто-то их подменил
        OriginalReadProcessMemory = (ReadProcessMemory_t)GetProcAddress(hKernel32, "ReadProcessMemory");
        OriginalWriteProcessMemory = (WriteProcessMemory_t)GetProcAddress(hKernel32, "WriteProcessMemory");
        OriginalNtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(hNtDll, "NtReadVirtualMemory");
        OriginalNtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtDll, "NtWriteVirtualMemory");
        OriginalCreateRemoteThread = (CreateRemoteThread_t)GetProcAddress(hKernel32, "CreateRemoteThread");

        ULONG size = 0;
        auto* pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
        if (!pImportDesc) return;

        while (pImportDesc->Name) {
            const char* moduleName = (const char*)((BYTE*)hModule + pImportDesc->Name);
            if (_stricmp(moduleName, "kernel32.dll") == 0 || _stricmp(moduleName, "ntdll.dll") == 0) {
                auto* pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->FirstThunk);

                while (pThunk->u1.Function) {
                    FARPROC* funcAddress = (FARPROC*)&pThunk->u1.Function;

                    // Только если оригинал ещё не захвачен — поставим хук
                    TryHookFunction(funcAddress, (FARPROC)OriginalReadProcessMemory, (FARPROC)HookedReadProcessMemory, "ReadProcessMemory");
                    TryHookFunction(funcAddress, (FARPROC)OriginalWriteProcessMemory, (FARPROC)HookedWriteProcessMemory, "WriteProcessMemory");
                    TryHookFunction(funcAddress, (FARPROC)OriginalNtReadVirtualMemory, (FARPROC)HookedNtReadVirtualMemory, "NtReadVirtualMemory");
                    TryHookFunction(funcAddress, (FARPROC)OriginalNtWriteVirtualMemory, (FARPROC)HookedNtWriteVirtualMemory, "NtWriteVirtualMemory");
                    TryHookFunction(funcAddress, (FARPROC)OriginalCreateRemoteThread, (FARPROC)HookedCreateRemoteThread, "CreateRemoteThread");

                    pThunk++;
                }
            }
            pImportDesc++;
        }
    }
    catch (const std::exception& e) {
       // Log("[HOOK] Exception in HookIAT: " + std::string(e.what()));
    }
}

#pragma endregion
#pragma region ListLoadedModulesAndReadMemory
BOOL SafeGetModuleInformation(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb) {
    return GetModuleInformation(hProcess, hModule, lpmodinfo, cb);
}
inline BOOL SafeEnumProcessModules(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded) {
    return EnumProcessModules(hProcess, lphModule, cb, lpcbNeeded);
}
std::string GetModuleNameFromAddress(HANDLE hProcess, uintptr_t address) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (SafeEnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            if (SafeGetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                if (address >= (uintptr_t)modInfo.lpBaseOfDll &&
                    address < (uintptr_t)modInfo.lpBaseOfDll + modInfo.SizeOfImage) {

                    wchar_t modPathW[MAX_PATH] = { 0 };
                    if (GetModuleFileNameExW(hProcess, hMods[i], modPathW, MAX_PATH)) {
                        return WStringToUTF8(modPathW);
                    }
                }
            }
        }
    }
    return "Unknown";
}
bool IsHighFrequencyCall(const std::string& functionName) {
    static std::map<std::string, int> functionCallCount;

    functionCallCount[functionName]++;
    if (functionCallCount[functionName] > 20) { // Например, 100 вызовов в секунду
        return true;
    }
    return false;
}
void MonitorSuspiciousFunctions(const std::string& processName, const std::string& moduleName, const std::string& modulePath) 
{
    std::string lowerModulePath = modulePath;
    std::transform(lowerModulePath.begin(), lowerModulePath.end(), lowerModulePath.begin(),
        [](unsigned char c) { return std::tolower(c); });

    if (lowerModulePath.find("system32") == std::string::npos) {
        if (IsHighFrequencyCall("ReadProcessMemory")) {
            Log("[WARNING MonitorSuspiciousFunctions] High frequency of ReadProcessMemory calls detected. " +
                processName + " [moduleName:" + moduleName + "] [modulePath:" + modulePath + "]");
        }
        if (IsHighFrequencyCall("WriteProcessMemory")) {
            Log("[WARNING MonitorSuspiciousFunctions] High frequency of WriteProcessMemory calls detected. " +
                processName + " [moduleName:" + moduleName + "] [modulePath:" + modulePath + "]");
        }
        if (IsHighFrequencyCall("CreateRemoteThread")) {
            Log("[WARNING MonitorSuspiciousFunctions] High frequency of CreateRemoteThread calls detected. " +
                processName + " [moduleName:" + moduleName + "] [modulePath:" + modulePath + "]");
        }
        if (IsHighFrequencyCall("NtReadVirtualMemory")) {
            Log("[WARNING MonitorSuspiciousFunctions] High frequency of NtReadVirtualMemory calls detected. " +
                processName + " [moduleName:" + moduleName + "] [modulePath:" + modulePath + "]");
        }
        if (IsHighFrequencyCall("NtWriteVirtualMemory")) {
            Log("[WARNING MonitorSuspiciousFunctions] High frequency of NtWriteVirtualMemory calls detected. " +
                processName + " [moduleName:" + moduleName + "] [modulePath:" + modulePath + "]");
        }
    }
}
std::string calculateSHA256(const std::vector<char>& data) {
    SHA256 sha256;
    sha256.update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    sha256.finalize();
    uint8_t* hash = sha256.getHash();

    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::setw(2) << std::setfill('0') << std::hex << (int)hash[i];
    }
    return ss.str();
}
bool DoesModuleUseReadWriteMemory(HMODULE hModule) {
    if (!hModule) return false;

    static auto pReadProcessMemory = GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadProcessMemory");
    static auto pWriteProcessMemory = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteProcessMemory");
    static auto pCreateRemoteThread = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateRemoteThread");
    static auto pNtReadVirtualMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
    static auto pNtWriteVirtualMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");

    // Проверка импортов
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

    // Проверка на наличие таблицы импорта
    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0) {
        return false;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule +
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pImportDesc->Name) {
        const char* moduleName = (const char*)((BYTE*)hModule + pImportDesc->Name);
        if (_stricmp(moduleName, "kernel32.dll") == 0 || _stricmp(moduleName, "ntdll.dll") == 0) {
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->FirstThunk);
            while (pThunk->u1.Function) {
                FARPROC* funcAddress = (FARPROC*)&pThunk->u1.Function;
                HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
                HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

                if (hKernel32 && hNtdll) {
                    if (*funcAddress == (FARPROC)GetProcAddress(hKernel32, "ReadProcessMemory") ||
                        *funcAddress == (FARPROC)GetProcAddress(hKernel32, "WriteProcessMemory") ||
                        *funcAddress == (FARPROC)GetProcAddress(hKernel32, "CreateRemoteThread") ||
                        *funcAddress == (FARPROC)GetProcAddress(hNtdll, "NtReadVirtualMemory") ||
                        *funcAddress == (FARPROC)GetProcAddress(hNtdll, "NtWriteVirtualMemory")) {
                        return true;
                    }
                }
                pThunk++;
            }
        }
        pImportDesc++;
    }

    // Проверка на динамическую загрузку функций
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hKernel32 && hNtdll) {
        if (GetProcAddress(hKernel32, "ReadProcessMemory") || GetProcAddress(hKernel32, "WriteProcessMemory") ||
            GetProcAddress(hKernel32, "CreateRemoteThread") || GetProcAddress(hNtdll, "NtReadVirtualMemory") ||
            GetProcAddress(hNtdll, "NtWriteVirtualMemory")) {
            return true;
        }
    }

    return false;
}
std::string GetProcessNameById(DWORD processId) {
    char processName[MAX_PATH] = "<unknown>";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess) {
        if (GetProcessImageFileNameA(hProcess, processName, MAX_PATH) == 0) {
            strcpy_s(processName, "<error>");
        }
        CloseHandle(hProcess);
    }
    return std::string(processName);
}
bool CalculateFileSHA256_CStyle(const wchar_t* filePath, BYTE outHash[32], DWORD dwShareMode = FILE_SHARE_READ) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD bytesRead = 0;

    __try {
        // Открываем файл с переданными флагами доступа (используем W-версию)
        hFile = CreateFileW(
            filePath,
            GENERIC_READ,
            dwShareMode,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN,
            NULL
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            // Если файл заблокирован, пробуем открыть с максимальным доступом
            if (error == ERROR_SHARING_VIOLATION && dwShareMode != (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)) {
                CloseHandle(hFile);
                return CalculateFileSHA256_CStyle(filePath, outHash, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
            }
            __leave;
        }

        // Криптопровайдер SHA-256
        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
            __leave;

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
            __leave;

        BYTE buffer[4096];
        while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
            if (!CryptHashData(hHash, buffer, bytesRead, 0)) __leave;
        }

        DWORD hashSize = 32;
        if (!CryptGetHashParam(hHash, HP_HASHVAL, outHash, &hashSize, 0)) __leave;

        CloseHandle(hFile);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        memset(outHash, 0, 32);
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
        if (hHash) CryptDestroyHash(hHash);
        if (hProv) CryptReleaseContext(hProv, 0);
        return false;
    }
}
std::string HashToHex(const BYTE hash[32]) {
    std::stringstream ss;
    for (int i = 0; i < 32; ++i)
        ss << std::setw(2) << std::setfill('0') << std::hex << (hash[i] & 0xFF);
    return ss.str();
}
std::string CalculateFileSHA256Safe(const std::wstring& filePathW) {
    BYTE hash[32] = { 0 };

    if (filePathW.empty())
        return "empty_path";

    // Проверка существования
    if (GetFileAttributesW(filePathW.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return "file_not_found";
    }

    // Попытки чтения
    if (CalculateFileSHA256_CStyle(filePathW.c_str(), hash, FILE_SHARE_READ)) {
        return HashToHex(hash);
    }
    if (CalculateFileSHA256_CStyle(filePathW.c_str(), hash, FILE_SHARE_READ | FILE_SHARE_WRITE)) {
        return HashToHex(hash);
    }
    if (CalculateFileSHA256_CStyle(filePathW.c_str(), hash, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)) {
        return HashToHex(hash);
    }

    // Последняя попытка через копию
    wchar_t tempPath[MAX_PATH], tempFile[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPath)) {
        std::wstring fileName = filePathW;
        size_t pos = fileName.find_last_of(L"\\/");
        if (pos != std::wstring::npos) fileName = fileName.substr(pos + 1);

        swprintf_s(tempFile, L"%s\\%s_%u.tmp", tempPath, fileName.c_str(), GetTickCount());

        if (CopyFileW(filePathW.c_str(), tempFile, FALSE)) {
            if (CalculateFileSHA256_CStyle(tempFile, hash, FILE_SHARE_READ)) {
                std::string result = HashToHex(hash);
                DeleteFileW(tempFile);
                return result;
            }
            DeleteFileW(tempFile);
        }
    }

    return "failed_to_read_file_or_compute_hash";
}
std::string CalculateFileSHA256Safe(const std::string& filePath) {
    if (filePath.empty()) return "empty_path";

    // Конвертируем string → wstring правильно
    int needed = MultiByteToWideChar(CP_UTF8, 0, filePath.c_str(), -1, nullptr, 0);
    std::wstring wpath(needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, filePath.c_str(), -1, &wpath[0], needed);

    return CalculateFileSHA256Safe(wpath);
}
void ReadModuleMemoryWithChecksum(HANDLE hProcess, uintptr_t baseAddress, size_t size, DWORD processId, const std::string& processName, const std::string& moduleName, const std::string& modulePath) {
    try {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(baseAddress), &mbi, sizeof(mbi)) == 0)
            return;

        if (!IsReadableMemoryRegion(mbi))
            return;

        static std::map<uintptr_t, std::string> previousHashes;
        std::wstring modulePathW;
        if (!modulePath.empty()) {
            int needed = MultiByteToWideChar(CP_UTF8, 0, modulePath.c_str(), -1, nullptr, 0);
            if (needed > 0) {
                modulePathW.resize(needed);
                MultiByteToWideChar(CP_UTF8, 0, modulePath.c_str(), -1, &modulePathW[0], needed);
                if (!modulePathW.empty() && modulePathW.back() == L'\0')
                    modulePathW.pop_back();
            }
        }

        if (modulePathW.empty() && baseAddress != 0) {
            wchar_t pathW[MAX_PATH] = { 0 };
            if (GetModuleFileNameExW(hProcess, (HMODULE)baseAddress, pathW, MAX_PATH)) {
                modulePathW = pathW;
            }
        }

        if (modulePathW.empty()) {
            Log("[ERROR] Cannot get module path for: " + moduleName);
            return;
        }
        std::string currentHash = CalculateFileSHA256Safe(modulePathW);
        std::string modifyingModule = GetModuleNameFromAddress(hProcess, baseAddress);
        std::string modifyingModuleHash = CalculateFileSHA256Safe(modulePathW);  // тот же путь!

        if (previousHashes.find(baseAddress) != previousHashes.end()) {
            if (previousHashes[baseAddress] != currentHash) {
                Log("[WARNING HOOK] CHANGED at " + std::to_string(baseAddress) + " in process " + processName + "(" + std::to_string(processId) + ")" + " by module: " + modifyingModule + " | SHA256: " + modifyingModuleHash);
                previousHashes[baseAddress] = currentHash;
            }
        }
        else {
            previousHashes[baseAddress] = currentHash;
            Log("[WARNING HOOK] FIRST read at " + std::to_string(baseAddress) + " in process " + processName + "(" + std::to_string(processId) + ")" + " by module: " + modifyingModule + " | SHA256: " + modifyingModuleHash);
        }
    }
    catch (const std::exception& e) {
        // Log("[ERROR] ReadModuleMemoryWithChecksum exception: " + std::string(e.what()));
    }
}
void ReadModuleMemory(HANDLE hProcess, uintptr_t baseAddress, size_t size, DWORD processId, const std::string& processName, const std::string& moduleName, const std::string& modulePath) {
    try {
        START_TIMING(ReadModuleMemory);
        if (!hProcess || hProcess == INVALID_HANDLE_VALUE || size == 0)
            return;

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(baseAddress), &mbi, sizeof(mbi)) == 0)
            return;

        if (!IsReadableMemoryRegion(mbi))
            return;

       // MonitorSuspiciousFunctions(processName, moduleName, modulePath);

        // Чтение и проверка хеша дважды для обнаружения изменений
        ReadModuleMemoryWithChecksum(hProcess, baseAddress, size, processId, processName, moduleName, modulePath);
        Sleep(2000); // пауза перед повторной проверкой
        ReadModuleMemoryWithChecksum(hProcess, baseAddress, size, processId, processName, moduleName, modulePath);
        END_TIMING(ReadModuleMemory);
        std::string opName = std::string("READ_MODULE_") + moduleName;
        g_simpleDetector->RecordTiming(opName, duration_ReadModuleMemory);
    }
    catch (const std::exception& e) {
        // Log("[ERROR] ReadModuleMemory exception: " + std::string(e.what()));
    }
}
void ListLoadedModulesAndReadMemoryLimited() {
    const int maxAttempts = 3;
    for (int attempt = 0; attempt < maxAttempts; ++attempt) {

        HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
        HANDLE hProcess = NULL;

        try {
            DWORD processId = GetCurrentProcessId();
            hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
            if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
                Log("[LOGEN] Cannot open process, skipping attempt " + std::to_string(attempt));
                continue;
            }

            std::string processName = GetProcessName(hProcess);
            if (ToLower(processName) != Name_Game) {
                continue;
            }
            hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
            if (hModuleSnap == INVALID_HANDLE_VALUE) {
                Log("[LOGEN] Cannot create module snapshot, skipping attempt " + std::to_string(attempt));
                if (hProcess) CloseHandle(hProcess);
                continue;
            }

            MODULEENTRY32 me32;
            me32.dwSize = sizeof(MODULEENTRY32);

            if (Module32First(hModuleSnap, &me32)) {
                do {

                    std::wstring moduleNameW = me32.szModule;
                    std::wstring modulePathW = me32.szExePath;
                    std::string moduleName = WStringToUTF8(moduleNameW);
                    std::string modulePath = WStringToUTF8(modulePathW);

                    if (!ends_with_dll(moduleName)) continue;

                    bool isSuspicious = IsSuspiciousModule(moduleName);
                    bool usesMemoryFunctions = DoesModuleUseReadWriteMemory(me32.hModule);

                    DWORD moduleProcessId = me32.th32ProcessID;
                    std::string parentProcessName = GetProcessNameById(moduleProcessId);

                    uintptr_t baseAddress = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
                    size_t moduleSize = me32.modBaseSize;
                    if (moduleSize == 0) continue;
                    std::string fileHash = CalculateFileSHA256Safe(modulePathW);
                    std::string lowerModulePath = modulePath;
                    std::transform(lowerModulePath.begin(), lowerModulePath.end(), lowerModulePath.begin(), ::tolower);
                    if (isSuspicious || usesMemoryFunctions) {
                        if (lowerModulePath.find("system32") == std::string::npos && lowerModulePath.find("windows") == std::string::npos) {
                            if (isSuspicious && usesMemoryFunctions) {
                                Log("[WARNING HOOK] INJECTED DLL: " + modulePath + " (" + parentProcessName + ") SHA256: " + fileHash);
                                ReadModuleMemory(hProcess, baseAddress, moduleSize, processId, processName, moduleName, modulePath);
                                StartSightImgDetection("[WARNING HOOK] INJECTED DLL: " + modulePath + " (" + parentProcessName + ") SHA256: " + fileHash);
                            }
                            else if (isSuspicious) {
                                Log("[WARNING HOOK] SUSPICIOUS DLL: " + modulePath + " (" + parentProcessName + ") SHA256: " + fileHash);
                            }
                            else if (usesMemoryFunctions) {
                                Log("[WARNING HOOK] MEMORY-ACCESS DLL: " + modulePath + " (" + parentProcessName + ") SHA256: " + fileHash);
                                ReadModuleMemory(hProcess, baseAddress, moduleSize, processId, processName, moduleName, modulePath);
                            }
                        }
                    }
                } while (Module32Next(hModuleSnap, &me32));
            }

        }
        catch (const std::exception& e) {
            Log("[LOGEN] in ListLoadedModulesAndReadMemoryLimited: " + std::string(e.what()));
        }

        if (hModuleSnap != INVALID_HANDLE_VALUE) CloseHandle(hModuleSnap);
        if (hProcess) CloseHandle(hProcess);

        Sleep(4000);
    }
}
void ListLoadedModulesAndReadMemory() {
    try {
        GUARD_REENTRY(ListLoadedModulesAndReadMemory);

        HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
        HANDLE hProcess = NULL;

        try {
            DWORD processId = GetCurrentProcessId();
            hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
            if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return;

            std::string processName = GetProcessName(hProcess);
            if (ToLower(processName) != Name_Game) {
                return;
            }
            hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
            if (hModuleSnap == INVALID_HANDLE_VALUE) return;

            MODULEENTRY32 me32;
            me32.dwSize = sizeof(MODULEENTRY32);

            if (Module32First(hModuleSnap, &me32)) {
                do {

                    std::wstring moduleNameW = me32.szModule;
                    std::wstring modulePathW = me32.szExePath;
                    std::string moduleName = WStringToUTF8(moduleNameW);
                    std::string modulePath = WStringToUTF8(modulePathW);

                    if (!ends_with_dll(moduleName)) continue;
                    std::string fileHash = CalculateFileSHA256Safe(modulePathW);
                    bool isSuspicious = IsSuspiciousModule(moduleName);
                    bool usesMemoryFunctions = DoesModuleUseReadWriteMemory(me32.hModule);
                    DWORD moduleProcessId = me32.th32ProcessID;
                    std::string parentProcessName = GetProcessNameById(moduleProcessId);

                    uintptr_t baseAddress = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
                    size_t moduleSize = me32.modBaseSize;
                    if (moduleSize == 0) continue;

                    std::string lowerModulePath = modulePath;
                    std::transform(lowerModulePath.begin(), lowerModulePath.end(), lowerModulePath.begin(), ::tolower);

                    if (isSuspicious || usesMemoryFunctions) {
                        if (lowerModulePath.find("system32") == std::string::npos && lowerModulePath.find("windows") == std::string::npos) {

                            if (isSuspicious && usesMemoryFunctions) {
                                Log("[WARNING HOOK] INJECTED DLL: " + modulePath + " (" + parentProcessName + ") SHA256: " + fileHash);
                                ReadModuleMemory(hProcess, baseAddress, moduleSize, processId, processName, moduleName, modulePath);
                                StartSightImgDetection("[WARNING HOOK] INJECTED DLL: " + modulePath + " (" + parentProcessName + ") SHA256: " + fileHash);
                            }
                            else if (isSuspicious) {
                                Log("[WARNING HOOK] SUSPICIOUS DLL: " + modulePath + " (" + parentProcessName + ") SHA256: " + fileHash);
                            }
                            else if (usesMemoryFunctions) {
                                Log("[WARNING HOOK] MEMORY-ACCESS DLL: " + modulePath + " (" + parentProcessName + ") SHA256: " + fileHash);
                                ReadModuleMemory(hProcess, baseAddress, moduleSize, processId, processName, moduleName, modulePath);
                            }
                        }
                    }
                } while (Module32Next(hModuleSnap, &me32));
            }
        }
        catch (...) { }

        if (hModuleSnap != INVALID_HANDLE_VALUE) CloseHandle(hModuleSnap);
        if (hProcess) CloseHandle(hProcess);
    }
    catch (...) { }
}
#pragma endregion
#pragma region ModulHiden
bool IsSpoofedSystemModule(const std::string& modulePath) {
    std::string lowerPath = ToLower(modulePath);
    if (lowerPath.find("system32") != std::string::npos) {
        char realSystem32[MAX_PATH];
        GetSystemDirectoryA(realSystem32, MAX_PATH);
        std::string realSystem32Lower = ToLower(realSystem32);
        if (lowerPath.find(realSystem32Lower) == std::string::npos) {
            return true;
        }
    }

    return false;
}
bool IsLikelyInjected(const std::string& modulePath, const std::string& moduleName) {
    std::string lowerPath = ToLower(modulePath);
    const std::vector<std::string> suspiciousPaths = {
        "temp\\", "appdata\\", "users\\", "programdata\\",
        "windows\\temp\\", "downloads\\", "desktop\\"
    };

    for (const auto& path : suspiciousPaths) {
        if (lowerPath.find(path) != std::string::npos) {
            return true;
        }
    }
    const std::vector<std::string> suspiciousNames = {
        "inject", "hook", "cheat", "hack", "mod", "loader",
        "dinput", "dxgi", "d3d", "opengl", "trainer"
    };

    std::string lowerName = ToLower(moduleName);
    for (const auto& name : suspiciousNames) {
        if (lowerName.find(name) != std::string::npos) {
            return true;
        }
    }

    return false;
}
void EnhancedModuleCheck() {
    DWORD currentPid = GetCurrentProcessId();
    char currentProcessName[MAX_PATH] = "";

    if (GetModuleBaseNameA(GetCurrentProcess(), NULL, currentProcessName, MAX_PATH)) {
        if (_stricmp(currentProcessName, "DayZ_x64.exe") != 0) {
            return;
        }
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, currentPid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);

    if (Module32First(hSnapshot, &me)) {
        do {
            std::wstring moduleNameW = me.szModule;
            std::wstring modulePathW = me.szExePath;
            std::string moduleName = WStringToUTF8(moduleNameW);
            std::string modulePath = WStringToUTF8(modulePathW);
            std::string lowerPath = ToLower(modulePath);

            if (!ends_with_dll(moduleName)) continue;

            // Пропускаем системные и доверенные пути
            if (lowerPath.find("system32") != std::string::npos ||
                lowerPath.find("syswow64") != std::string::npos ||
                lowerPath.find("\\windows\\") != std::string::npos ||
                lowerPath.find("\\steam\\") != std::string::npos ||
                lowerPath.find("\\battleye\\") != std::string::npos) {
                continue;
            }

            bool isSuspicious = IsSuspiciousModule(moduleName);
            bool usesMemoryFunctions = DoesModuleUseReadWriteMemory(me.hModule);
            bool likelyInjected = IsLikelyInjected(modulePath, moduleName);

            // Только действительно подозрительные модули
            if ((isSuspicious && usesMemoryFunctions) || likelyInjected) {
                std::string fileHash = CalculateFileSHA256Safe(modulePathW);
                Log("[WARNING HOOK] INJECTED DLL: " + modulePath + " | SHA256: " + fileHash);
                StartSightImgDetection("[WARNING HOOK] INJECTED DLL: " + modulePath + " | SHA256: " + fileHash);
            }

        } while (Module32Next(hSnapshot, &me));
    }

    CloseHandle(hSnapshot);
}
void DetectHiddenModules() {
    DWORD currentPid = GetCurrentProcessId();

    // Проверяем только в DayZ
    char currentProcessName[MAX_PATH] = "";
    if (GetModuleBaseNameA(GetCurrentProcess(), NULL, currentProcessName, MAX_PATH)) {
        if (_stricmp(currentProcessName, Name_GameEXE.c_str()) != 0) return;
    }

    std::set<std::string> toolhelpModules;
    std::set<std::string> enumModules;

    auto IsSystemModule = [](const std::string& modulePath) -> bool {
        std::string lowerPath = ToLower(modulePath);

        static const std::vector<std::string> systemPaths = {
            "c:\\windows\\", "d:\\windows\\", "e:\\windows\\",
            "c:\\winnt\\",
            "\\windows\\system32\\", "\\windows\\syswow64\\",
            "\\windows\\winsxs\\", "\\windows\\temp\\",
            "\\windows\\installer\\", "\\windows\\assembly\\",
            "c:\\program files\\", "d:\\program files\\",
            "c:\\program files (x86)\\", "d:\\program files (x86)\\",
            "\\appdata\\local\\microsoft\\",
            "\\appdata\\local\\google\\",
            "\\appdata\\local\\temp\\",
            "\\appdata\\roaming\\microsoft\\",
            "\\appdata\\locallow\\microsoft\\",
            "\\steam\\", "\\steamapps\\", "\\common\\",
            "\\battleye\\", "\\easy anti-cheat\\",
            "\\amd\\", "\\nvidia\\", "\\intel\\",
            "\\radeonsoftware\\", "\\cnext\\",
            "\\programdata\\", "\\common files\\",
            "\\windowsapps\\", "\\microsoft\\",
            "\\system32\\", "\\syswow64\\"
        };

        for (const auto& path : systemPaths) {
            if (lowerPath.find(path) != std::string::npos) {
                return true;
            }
        }

        char systemDir[MAX_PATH];
        if (GetSystemDirectoryA(systemDir, MAX_PATH)) {
            std::string systemDirLower = ToLower(systemDir);
            if (lowerPath.find(systemDirLower) != std::string::npos) {
                return true;
            }
        }

        static const std::vector<std::string> systemFiles = {
            "kernel32.dll", "user32.dll", "ntdll.dll", "advapi32.dll",
            "gdi32.dll", "shell32.dll", "ole32.dll", "combase.dll",
            "rpcrt4.dll", "crypt32.dll", "ws2_32.dll", "wininet.dll",
            "shlwapi.dll", "msvcrt.dll", "ucrtbase.dll", "sechost.dll",
            "imm32.dll", "dinput8.dll", "xinput1_4.dll", "d3d11.dll",
            "dxgi.dll", "opengl32.dll", "dbghelp.dll", "version.dll", Name_Dll
        };

        std::string fileName = lowerPath;
        size_t lastSlash = fileName.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            fileName = fileName.substr(lastSlash + 1);
        }

        for (const auto& sysFile : systemFiles) {
            if (fileName == ToLower(sysFile)) {
                return true;
            }
        }

        return false;
        };
    auto IsSuspiciousHiddenModule = [](const std::string& modulePath) -> bool {
        std::string lowerPath = ToLower(modulePath);

        static const std::vector<std::string> executableExtensions = {
            ".dll", ".exe", ".node"
        };

        bool isExecutable = false;
        for (const auto& ext : executableExtensions) {
            if (lowerPath.length() >= ext.length() &&
                lowerPath.substr(lowerPath.length() - ext.length()) == ext) {
                isExecutable = true;
                break;
            }
        }
        if (!isExecutable) return false;

        std::string fileName = lowerPath;
        size_t lastSlash = fileName.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            fileName = fileName.substr(lastSlash + 1);
        }

        static const std::vector<std::string> cheatPatterns = {
            "dayzint", "cheat", "hack", "inject", "trigger", "aimbot",
            "wallhack", "esp", "memory", "trainer", "loader"
        };

        for (const auto& pattern : cheatPatterns) {
            if (fileName.find(pattern) != std::string::npos) {
                return true;
            }
        }

        static const std::vector<std::string> suspiciousPaths = {
            "\\desktop\\", "\\downloads\\", "\\documents\\",
            "\\cheats\\", "\\hacks\\", "\\trainers\\",
            "c:\\users\\", "d:\\users\\"
        };

        for (const auto& path : suspiciousPaths) {
            if (lowerPath.find(path) != std::string::npos) {
                return true;
            }
        }

        return false;
        };

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, currentPid);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me = { sizeof(me) };
        if (Module32First(hSnapshot, &me)) {
            do {
                if (me.th32ProcessID == currentPid) {
                    std::wstring modulePathW = me.szExePath;
                    std::string modulePath = WStringToUTF8(modulePathW);
                    if (!IsSystemModule(modulePath)) {
                        toolhelpModules.insert(ToLower(modulePath));
                    }
                }
            } while (Module32Next(hSnapshot, &me));
        }
        CloseHandle(hSnapshot);
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char modName[MAX_PATH];
            if (GetModuleFileNameA(hMods[i], modName, sizeof(modName))) {
                std::string modulePath = modName;
                if (!IsSystemModule(modulePath)) {
                    enumModules.insert(ToLower(modulePath));
                }
            }
        }
    }
    // Проверяем модули из EnumProcessModules, которых нет в Toolhelp32
    for (const auto& mod : enumModules) {
        if (toolhelpModules.find(mod) == toolhelpModules.end()) {
            if (IsSuspiciousHiddenModule(mod) && !IsSystemModule(mod)) {
                Log("[WARNING HOOK] HIDDEN SUSPICIOUS MODULE: " + mod);
            }
        }
    }

    // Проверяем модули из Toolhelp32, которых нет в EnumProcessModules
    for (const auto& mod : toolhelpModules) {
        if (enumModules.find(mod) == enumModules.end()) {
            if (IsSuspiciousHiddenModule(mod) && !IsSystemModule(mod)) {
                Log("[WARNING HOOK] HIDDEN SUSPICIOUS MODULE (Toolhelp only): " + mod);
            }
        }
    }
}
void DetectExternalCheatProcesses() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    auto IsCheatProcess = [](const std::string& processName, const std::wstring& processPathW) -> bool {
        std::string lowerName = ToLower(processName);
        std::string lowerPath = WStringToUTF8(processPathW); // конвертируем для проверки
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);

        if (lowerPath.find("\\windows\\") != std::string::npos ||
            lowerPath.find("\\program files") != std::string::npos ||
            lowerPath.find("\\steam\\") != std::string::npos) {
            return false;
        }

        static const std::vector<std::string> cheatPatterns = {
            "dayzint", "cheat", "hack", "inject", "trigger", "aimbot",
            "wallhack", "esp", "memory", "trainer", "loader"
        };

        for (const auto& pattern : cheatPatterns) {
            if (lowerName.find(pattern) != std::string::npos ||
                lowerPath.find(pattern) != std::string::npos) {
                return true;
            }
        }
        return false;
        };

    if (Process32First(hSnapshot, &pe)) {
        do {
            std::wstring exeNameW = pe.szExeFile;
            std::string processName = WStringToUTF8(exeNameW);

            if (_stricmp(processName.c_str(), "DayZ_x64.exe") == 0)
                continue;

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (hProcess) {
                wchar_t processPathW[MAX_PATH] = { 0 };

                // Получаем путь в Unicode (правильно!)
                if (GetModuleFileNameExW(hProcess, NULL, processPathW, MAX_PATH)) {
                    std::string processPathUTF8 = WStringToUTF8(processPathW);

                    if (IsCheatProcess(processName, processPathW)) {
                        std::string fileHash = CalculateFileSHA256Safe(processPathW);  // ← правильно, wstring

                        Log("[WARNING HOOK] EXTERNAL CHEAT PROCESS: " + processPathUTF8 + " | SHA256: " + fileHash);
                        StartSightImgDetection("[WARNING HOOK] EXTERNAL CHEAT PROCESS: " + processPathUTF8 + " | SHA256: " + fileHash);
                    }
                }
                CloseHandle(hProcess);
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
}
#pragma endregion
#pragma region PcPlayer
std::string hwid = "---";
static std::string BuildMonitorsCompactString() {
    std::ostringstream out;
    DISPLAY_DEVICEA dd;
    ZeroMemory(&dd, sizeof(dd));
    dd.cb = sizeof(dd);

    bool addedAny = false;
    for (DWORD i = 0; EnumDisplayDevicesA(nullptr, i, &dd, 0); ++i) {
        DEVMODEA dm;
        ZeroMemory(&dm, sizeof(dm));
        dm.dmSize = sizeof(dm);

        if (dd.DeviceName && dd.DeviceName[0]) {
            if (EnumDisplaySettingsA(dd.DeviceName, ENUM_CURRENT_SETTINGS, &dm)) {
                uint64_t pixels = uint64_t(dm.dmPelsWidth) * uint64_t(dm.dmPelsHeight);
                if (addedAny) out << "|";
                out << pixels << ":" << dm.dmPelsWidth << "x" << dm.dmPelsHeight << ":"
                    << (dm.dmDisplayFrequency ? dm.dmDisplayFrequency : 0);
                addedAny = true;
            }
        }
        ZeroMemory(&dd, sizeof(dd));
        dd.cb = sizeof(dd);
    }
    return addedAny ? out.str() : "";
}
std::string GetSMBIOS_UUID() {
    const DWORD BufferSize = 4096;
    std::vector<BYTE> buffer(BufferSize);
    DWORD retSize = GetSystemFirmwareTable('RSMB', 0, buffer.data(), BufferSize);
    if (retSize == 0 || retSize > BufferSize) return "";

    for (size_t i = 0; i + 24 <= retSize; ++i) {
        if (buffer[i] == 0x01 && buffer[i + 1] >= 0x12) {
            std::stringstream ss;
            for (int j = 8; j < 24; ++j) {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i + j];
            }
            return ss.str();
        }
    }
    return "";
}
std::string GetSIDForUser(const std::wstring& userName) {
    BYTE sidBuffer[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof(sidBuffer);
    WCHAR domainName[256];
    DWORD domainSize = (DWORD)(sizeof(domainName) / sizeof(WCHAR));
    SID_NAME_USE sidType;

    BOOL success = LookupAccountNameW(nullptr, userName.c_str(), sidBuffer, &sidSize, domainName, &domainSize, &sidType);
    if (!success) return "";

    LPSTR stringSid = nullptr;
    if (ConvertSidToStringSidA(sidBuffer, &stringSid)) {
        std::string sidStr(stringSid);
        LocalFree(stringSid);
        return sidStr;
    }
    return "";
}
std::string GetPrimaryUserSID() {
    DWORD level = 0;
    DWORD prefmaxlen = MAX_PREFERRED_LENGTH;
    DWORD entriesread = 0, totalentries = 0, resume_handle = 0;
    USER_INFO_0* pBuf = nullptr;

    NET_API_STATUS nStatus = NetUserEnum(nullptr, level, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf,
        prefmaxlen, &entriesread, &totalentries, &resume_handle);

    std::vector<std::string> userSIDs;
    if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) {
        for (DWORD i = 0; i < entriesread; ++i) {
            std::wstring wUserName = pBuf[i].usri0_name;
            std::string sid = GetSIDForUser(wUserName);
            if (!sid.empty() && sid.find("-500") == std::string::npos) 
                userSIDs.push_back(sid);
        }
        if (pBuf) NetApiBufferFree(pBuf);
    }

    std::sort(userSIDs.begin(), userSIDs.end());
    for (const auto& sid : userSIDs) {
        if (sid.find("-1000") != std::string::npos) return sid;
    }
    return !userSIDs.empty() ? userSIDs.front() : "";
}
unsigned GetCpuMaxMHzNormalized() {
    int r[4] = { 0 };
    __cpuid(r, 0x16);
    unsigned baseMHz = (unsigned)r[0];
    unsigned maxMHz = (unsigned)r[1];
    unsigned freq = (maxMHz != 0 ? maxMHz : baseMHz);
    return (freq / 100) * 100;
}
uint64_t ReadRamMiBNormalized() {
    MEMORYSTATUSEX ms{ sizeof(ms) };
    if (GlobalMemoryStatusEx(&ms))
        return (ms.ullTotalPhys / (1024ull * 1024ull)); // уже в MiB
    return 0;
}
uint64_t SumFixedDisksGiBNormalized() {
    char buf[4096];
    DWORD n = GetLogicalDriveStringsA(sizeof(buf), buf);
    if (!n || n > sizeof(buf)) return 0;

    uint64_t sumBytes = 0;
    for (char* p = buf; *p; p += lstrlenA(p) + 1) {
        if (GetDriveTypeA(p) != DRIVE_FIXED) continue;
        ULARGE_INTEGER totalBytes{};
        if (GetDiskFreeSpaceExA(p, nullptr, &totalBytes, nullptr))
            sumBytes += totalBytes.QuadPart;
    }
    return (sumBytes / (1024ull * 1024 * 1024 * 10)) * 10; // округление до 10 ГБ
}
void GenerateStableHWID() {
    try {
        std::string smbios = GetSMBIOS_UUID();
        std::string primarySID = GetPrimaryUserSID();
        unsigned cpu = GetCpuMaxMHzNormalized();
        uint64_t ram = ReadRamMiBNormalized();
        uint64_t dsk = SumFixedDisksGiBNormalized();

        std::ostringstream raw;
        if (!smbios.empty()) raw << "B:" << smbios << "|";
        if (!primarySID.empty()) raw << "S:" << primarySID << "|";
        if (cpu) raw << "CPUFREQ:" << cpu << "MHz|";
        if (ram) raw << "RAM:" << ram << "|";
        if (dsk) raw << "DSK:" << dsk << "|";

        std::string monitorsCompact = BuildMonitorsCompactString();
        if (!monitorsCompact.empty()) raw << monitorsCompact << "|";
        if (GameProjectdayzzona) {
            hwid = "---";
        }
        else
        {
            hwid = raw.str();
            if (hwid.empty()) hwid = "FallbackHWID";
            Log("[LOGEN] HWID: " + hwid);
        }
    }
    catch (...) {
        Log("[LOGEN] HWID: HWID_ERROR");
    }
}
void HWID() {
    __try {
        GenerateStableHWID();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
#pragma endregion
std::unique_ptr<VulkanDetector> g_vulkanDetector;
void InitializeVulkanDetection() {
    if (!g_vulkanDetector) {
        g_vulkanDetector = std::make_unique<VulkanDetector>();

        // Настройка конфигурации
        VulkanDetectorConfig config;
        config.enableHookDetection = true;
        config.enableModuleScan = true;
        config.enableSignatureCheck = true;
        config.enableScreenshotOnDetection = true;
        config.hookConfidenceThreshold = 80;

        // Специфичные для DayZ настройки
        config.whitelistedModules.push_back("dayz_x64.exe");
        config.whitelistedPaths.push_back("\\dayz\\");
        config.whitelistedPaths.push_back("\\steamapps\\common\\dayz");

        g_vulkanDetector->SetConfig(config);

        if (g_vulkanDetector->Initialize()) {
            g_vulkanDetector->Start();
            Log("[LOGEN] Vulkan detector started for DayZ");
        }
    }
}
std::atomic<bool> g_vulkanMonitorRunning{ false };
std::thread g_vulkanMonitorThread;
void CheckProcessForVulkan(HANDLE hProcess, const std::string& processName, DWORD pid) {
    HMODULE hMods[256];
    DWORD cbNeeded;

    // ===== RATE LIMITER =====
    static std::map<std::string, uint64_t> lastLogTime;
    static std::map<std::string, int> logCounter;
    static std::mutex rateMutex;
    const uint64_t COOLDOWN_MS = 60000; 
    const int MAX_SCREENSHOTS_PER_HOUR = 5; 

    auto ShouldLog = [&](const std::string& key, const std::string& hash, bool takeScreenshot = false) -> bool {
        std::lock_guard<std::mutex> lock(rateMutex);
        uint64_t now = GetTickCount64();

        std::string fullKey = key + "_" + hash;
        auto it = lastLogTime.find(fullKey);

        if (it == lastLogTime.end() || (now - it->second) > COOLDOWN_MS) {
            lastLogTime[fullKey] = now;
            logCounter[fullKey] = 1;
            static int screenshotCount = 0;
            static uint64_t screenshotHourStart = now;

            if (takeScreenshot) {
                if (now - screenshotHourStart > 3600000) {
                    screenshotCount = 0;
                    screenshotHourStart = now;
                }
                if (screenshotCount < MAX_SCREENSHOTS_PER_HOUR) {
                    screenshotCount++;
                    return true; 
                }
                return false; 
            }
            return true;
        }

        logCounter[fullKey]++;
        return false; 
        };

    auto IsWhitelistedProcess = [](const std::string& name) -> bool {
        std::string lowerName = name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        size_t lastSlash = lowerName.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            lowerName = lowerName.substr(lastSlash + 1);
        }

        static const std::set<std::string> whitelist = {
            "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
            "svchost.exe", "dwm.exe", "conhost.exe", "ctfmon.exe",
            "taskhostw.exe", "runtimebroker.exe", "searchhost.exe",
            "sihost.exe", "fontdrvhost.exe", "smss.exe", "system",
            "system idle process", "winlogon.exe",
            "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe",
            "discord.exe", "discordptb.exe", "discordcanary.exe",
           Name_Game, "dayz.exe",
        Name_Dll
        };

        return whitelist.find(lowerName) != whitelist.end();
        };
    auto IsSystemPath = [](const std::wstring& path) -> bool {
        std::wstring lower = path;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        if (lower.find(L"\\windows\\") == 0 ||
            lower.find(L"\\program files") == 0 ||
            lower.find(L"\\program files (x86)") == 0 ||
            lower.find(L"\\system32\\") != std::wstring::npos ||
            lower.find(L"\\syswow64\\") != std::wstring::npos) {
            return true;
        }
        if (lower.find(L"\\windowsapps\\") != std::wstring::npos) {
            return true;
        }

        return false;
        };
    if (IsWhitelistedProcess(processName)) {
        return;
    }

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        return;
    }

    for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        WCHAR modPathW[MAX_PATH] = { 0 };
        if (GetModuleFileNameExW(hProcess, hMods[i], modPathW, MAX_PATH) == 0) {
            continue;
        }
        if (IsSystemPath(modPathW)) {
            continue;
        }
        char modPathUTF8[MAX_PATH * 2] = { 0 };
        WideCharToMultiByte(CP_UTF8, 0, modPathW, -1, modPathUTF8, sizeof(modPathUTF8), NULL, NULL);
        std::wstring modPathStr = modPathW;
        size_t lastSlash = modPathStr.find_last_of(L"\\/");
        std::wstring fileName = (lastSlash != std::wstring::npos) ?
            modPathStr.substr(lastSlash + 1) : modPathStr;

        std::transform(fileName.begin(), fileName.end(), fileName.begin(), ::towlower);
        if (fileName == L"vulkan-1.dll") {
            std::wstring lowerPath = modPathStr;
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

            if (lowerPath.find(L"discord") != std::wstring::npos) {
                continue;
            }
            std::string hash = CalculateFileSHA256Safe(modPathUTF8);
            std::string key = "vulkan_non_system_" + std::string(modPathUTF8);

            if (ShouldLog(key, hash, true)) { 
                Log("[VEH] Vulkan detected in process: " + processName +" (PID: " + std::to_string(pid) + ")" + " | Path: " + std::string(modPathUTF8) + " | SHA256: " + hash);
                StartSightImgDetection("[VEH] Vulkan process: " + processName);
            }
            continue;
        }

        // ===== Подозрительные ключевые слова =====
        bool hasSuspiciousKeyword =
            fileName.find(L"hook") != std::wstring::npos ||
            fileName.find(L"inject") != std::wstring::npos ||
            fileName.find(L"cheat") != std::wstring::npos ||
            fileName.find(L"hack") != std::wstring::npos;

        if (hasSuspiciousKeyword) {
            // Игнорируем, если это Discord hook (легитимный)
            if (fileName.find(L"discord") != std::wstring::npos) {
                continue;
            }

            std::string hash = CalculateFileSHA256Safe(modPathUTF8);
            std::string key = "suspicious_" + std::string(modPathUTF8);

            // Для подозрительных модулей логируем, но скриншоты делаем реже
            bool takeScreenshot = (fileName.find(L"hook.dll") != std::wstring::npos); // только hook.dll
            if (ShouldLog(key, hash, takeScreenshot)) {
                Log("[VEH] Suspicious module in " + processName + ": " + modPathUTF8 + " | SHA256: " + hash);

                if (takeScreenshot) {
                   // StartSightImgDetection("[VEH] Suspicious module: " + std::string(modPathUTF8) + " | SHA256: " + hash);
                }
            }
            continue;
        }
    }
}
void VulkanProcessMonitor() {
    Log("[LOGEN] Vulkan process monitor started");

    std::set<DWORD> knownPids;

    while (g_vulkanMonitorRunning) {
        try {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe; // Используем W версию
                pe.dwSize = sizeof(pe);

                if (Process32FirstW(hSnapshot, &pe)) {
                    do {
                        if (pe.th32ProcessID == GetCurrentProcessId()) continue;

                        std::wstring moduleNameW = pe.szExeFile;
                        std::string processName = WStringToUTF8(moduleNameW);

                        if (knownPids.find(pe.th32ProcessID) == knownPids.end()) {
                            knownPids.insert(pe.th32ProcessID);

                            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);

                            if (hProcess) {
                                CheckProcessForVulkan(hProcess, processName, pe.th32ProcessID);
                                CloseHandle(hProcess);
                            }
                        }
                    } while (Process32NextW(hSnapshot, &pe));
                }
                CloseHandle(hSnapshot);
            }

            static uint64_t lastCleanup = GetTickCount64();
            uint64_t now = GetTickCount64();
            if (now - lastCleanup > 60000) {
                knownPids.clear();
                lastCleanup = now;
            }

            Sleep(15000);
        }
        catch (...) {
            Sleep(10000);
        }
    }
}
void StartVulkanMonitor() {
    if (g_vulkanMonitorRunning.exchange(true)) return;

    try {
        g_vulkanMonitorThread = std::thread(VulkanProcessMonitor);
        Log("[LOGEN] Vulkan process monitor thread created");
    }
    catch (const std::exception& e) {
        Log("[LOGEN] Failed to start Vulkan monitor: " + std::string(e.what()));
        g_vulkanMonitorRunning = false;
    }
}
void StopVulkanMonitor() {
    if (!g_vulkanMonitorRunning.exchange(false)) return;

    if (g_vulkanMonitorThread.joinable()) {
        g_vulkanMonitorThread.join();
    }
}

void LogHardwareInfo() {
    int cpuInfo[4] = { -1 };
    char cpuBrand[0x40] = { 0 };

    __cpuid(cpuInfo, 0x80000002);
    memcpy(cpuBrand, cpuInfo, sizeof(cpuInfo));

    __cpuid(cpuInfo, 0x80000003);
    memcpy(cpuBrand + 16, cpuInfo, sizeof(cpuInfo));

    __cpuid(cpuInfo, 0x80000004);
    memcpy(cpuBrand + 32, cpuInfo, sizeof(cpuInfo));

   // LogFormat("[VEH] CPU: %s", cpuBrand);

    // Информация о памяти
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);

   // LogFormat("[VEH] RAM: Total: %lluMB Available: %lluMB", memStatus.ullTotalPhys / (1024 * 1024), memStatus.ullAvailPhys / (1024 * 1024));
}
void PerformCriticalActions(KernelCheatDetector::CheatPattern pattern) {
    switch (pattern) {
    case KernelCheatDetector::PATTERN_DMA_BURST:
        LogHardwareInfo();
        break;
    default:
        break;
    }
}
bool IsLikelySafeKernelActivity() {
    return true;        // Пока игнорируем все KERNEL_DELAY (ASUS и т.д.)
}
std::string GetOSVersionString() {
    OSVERSIONINFOEX osvi = { 0 };
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
#pragma warning(push)
#pragma warning(disable: 4996)
    if (GetVersionEx((OSVERSIONINFO*)&osvi))
#pragma warning(pop)
        return std::to_string(osvi.dwMajorVersion) + "." + std::to_string(osvi.dwMinorVersion);
    return "Unknown";
}
int GetCPUCoreCount() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors;
}
int GetRAMGB() {
    MEMORYSTATUSEX mem = { 0 };
    mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem))
        return static_cast<int>(mem.ullTotalPhys / (1024ULL * 1024 * 1024));
    return 0;
}
void LogCriticalDetection(KernelCheatDetector::CheatPattern pattern, const std::string& processName, DWORD pid)
{
    static SmartRateLimiter criticalRateLimiter;
    static int kernelDelayCount = 0;
    static int dmaCount = 0;

    if (pattern == KernelCheatDetector::PATTERN_KERNEL_DELAY)
    {
        kernelDelayCount++;

        if (IsLikelySafeKernelActivity())
        {
            if (kernelDelayCount % 15 == 0) {
                Log("[VEH] Ignored safe kernel-mode activity (ASUS/Armoury/legitimate driver)");
            }
            return;
        }

        if (kernelDelayCount < 4) {
            return;
        }
    }
    else if (pattern == KernelCheatDetector::PATTERN_DMA_BURST)
    {
        dmaCount++;
        if (dmaCount < 2) return;
    }

    // Если дошли сюда — это уже стоит внимания
    std::string key = "CRITICAL_" + std::to_string(pid);
    if (!criticalRateLimiter.ShouldLog(key, 120000)) {
        return;
    }

    std::stringstream criticalLog;
    criticalLog << "[VEH] CRITICAL: ";

    switch (pattern) {
    case KernelCheatDetector::PATTERN_DMA_BURST:
        criticalLog << "DMA CHEAT DETECTED! Hardware-level memory access.";
        break;
    case KernelCheatDetector::PATTERN_KERNEL_DELAY:
        criticalLog << "KERNEL DRIVER CHEAT DETECTED! Suspicious kernel-mode activity.";
        break;
    default:
        return;
    }

    criticalLog << " | Target: " << processName
        << " | OS: Windows " << GetOSVersionString()
        << " | CPU Cores: " << GetCPUCoreCount()
        << " | RAM: " << GetRAMGB() << "GB";

    Log(criticalLog.str());

    StartSightImgDetection(criticalLog.str());
    PerformCriticalActions(pattern);

    // Сброс счётчиков
    if (pattern == KernelCheatDetector::PATTERN_KERNEL_DELAY)
        kernelDelayCount = 0;
    else
        dmaCount = 0;
}
void KERNEL() {
    static uint64_t lastAggregationTime = 0;
    static uint64_t lastStatsLogTime = 0;
    static uint64_t lastCriticalScreenshotTime = 0;
    static std::map<std::string, uint64_t> lastCriticalLog;

    uint64_t currentTime = GetTickCount64();
    DWORD pid = GetCurrentProcessId();

    if (!g_simpleDetector->ShouldMonitorProcess(pid)) {
        return;
    }

    char processName[MAX_PATH] = { 0 };
    GetModuleBaseNameA(GetCurrentProcess(), NULL, processName, MAX_PATH);
    std::string exeName = processName;
    std::string processKey = exeName + "_" + std::to_string(pid);

    // Основной анализ (внутри уже есть логирование и скриншоты)
    g_simpleDetector->AnalyzeAdvancedPatterns();

    // Дополнительная логика для КРИТИЧЕСКИХ детекций
    auto pattern = g_simpleDetector->AnalyzePatterns(); // Быстрая проверка

    if (pattern == KernelCheatDetector::PATTERN_DMA_BURST ||
        pattern == KernelCheatDetector::PATTERN_KERNEL_DELAY) {

        // Логирование критических детекций (раз в 2 минуты)
        if (lastCriticalLog.find(processKey) == lastCriticalLog.end() ||
            currentTime - lastCriticalLog[processKey] > 120000) {

            LogCriticalDetection(pattern, exeName, pid);
            lastCriticalLog[processKey] = currentTime;

            // Дополнительный скриншот для критических детекций
            if (currentTime - lastCriticalScreenshotTime > 120000) {
                lastCriticalScreenshotTime = currentTime;
            }
        }
    }

    // Агрегация логов (раз в минуту)
    if (g_config.enableAggregation && currentTime - lastAggregationTime > 60000) {
        g_detectionAggregator.ProcessAndLog(false);
        lastAggregationTime = currentTime;
    }

    // Статистика (раз в 5 минут)
    if (currentTime - lastStatsLogTime > 300000) {
        int total = g_totalDetections.load();
        int logged = g_loggedDetections.load();
        int ratio = (total > 0) ? (logged * 100) / total : 0;

       // Log("[VEH] STATS: Total detections: " + std::to_string(total) +" | Logged: " + std::to_string(logged) + " | Ratio: " + std::to_string(ratio) + "%");

        lastStatsLogTime = currentTime;

        // Периодическая информация о системе
        static int statsCounter = 0;
        if (++statsCounter % 3 == 0) { // Каждые 15 минут
            LogHardwareInfo();
        }
    }
}

SIZE_T GetCurrentMemoryUsageMB() {
    PROCESS_MEMORY_COUNTERS pmc;
    pmc.cb = sizeof(PROCESS_MEMORY_COUNTERS);
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / (1024 * 1024);
    }
    return 0;
}
void ForceFullSystemReset() {
    LogFormat("[LOGEN] ForceFullSystemReset START - Current memory: %zu MB", GetCurrentMemoryUsageMB());
    BD_ResetSuspicionMetrics();
    BD_ClearLogData();
    if (g_keyMonitor) {
        g_keyMonitor->ClearAllData();
        g_keyMonitor->ResetStats();
    }
    if (g_vulkanDetector) {
        g_vulkanDetector->ClearDetectedHooks();
        g_vulkanDetector->CleanupOldData();
    }
    g_logRateLimitMap.clear();

    if (messageCache.size() > 0) {
        std::lock_guard<std::mutex> lock(cacheMutex);
        messageCache.clear();
    }
    g_simpleDetector->CleanupOldOperationStats();
    EPS::CleanupMemory(true);
    BD_ApplySmartReset();
    SaveScreenshotToDiskCount = 0;
    SaveScreenshotToDiskCount2 = 0;
    SaveScreenshotToDiskCount3 = 0;
    SIZE_T afterMemoryMB = GetCurrentMemoryUsageMB();
    LogFormat("[LOGEN] ForceFullSystemReset END - Memory: %zu MB (freed %zu MB)", afterMemoryMB, (afterMemoryMB < GetCurrentMemoryUsageMB() ? GetCurrentMemoryUsageMB() - afterMemoryMB : 0));
}
void CheckMemoryAndCleanup() {
    PROCESS_MEMORY_COUNTERS pmc;
    pmc.cb = sizeof(PROCESS_MEMORY_COUNTERS);

    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        SIZE_T memoryMB = pmc.WorkingSetSize / (1024 * 1024);

        static SIZE_T lastMemoryMB = 0;
        static int cleanupCount = 0;
        if (memoryMB > 7000) {
            LogFormat("[LOGEN] WARNING: Memory at %zu MB", memoryMB);
            if (memoryMB > 8000) {
                LogFormat("[LOGEN] CRITICAL: Memory at %zu MB - FORCING CLEANUP", memoryMB);
                ForceFullSystemReset();
                cleanupCount++;
                if (cleanupCount > 3 && memoryMB > 9000) {
                    LogFormat("[LOGEN] EXTREME: Memory still at %zu MB after %d cleanups", memoryMB, cleanupCount);

                    // Экстренные меры
                    BD_ResetSuspicionMetrics();
                    if (g_keyMonitor) {
                        g_keyMonitor->ClearAllData();
                    }
                    messageCache.clear();
                    cleanupCount = 0;
                }
            }
        }
        else {
            cleanupCount = 0;
        }

        // Логируем каждые 1000 MB (1 GB) роста
        if (memoryMB > lastMemoryMB + 1000) {
            LogFormat("[LOGEN] Memory milestone: %zu MB", memoryMB);
            lastMemoryMB = memoryMB;
        }
    }
}

void HookIATStart() {
    __try {
        HookIAT();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
void ListLoadedModulesAndReadMemoryLimitedStart() {
    __try {
        ListLoadedModulesAndReadMemoryLimited();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
void DetectHiddenModulesStart() {
    __try {
        DetectHiddenModules();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
void EnhancedModuleCheckStart() {
    __try {
        EnhancedModuleCheck();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
void DetectExternalCheatProcessesStart() {
    __try {
        DetectExternalCheatProcesses();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
void KERNELStart() {
    __try {
        KERNEL();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
#pragma region Monitor_Only
bool ValidateWorldPtr(uintptr_t worldPtr) {
    if (!worldPtr || worldPtr < 0x10000 || worldPtr == 0xFFFFFFFFFFFFFFFF || !IsValidAddress(worldPtr)) {
        return false;
    }

    uintptr_t entityArray = 0;
    SIZE_T bytesRead = 0;

    // Проверяем NearEntList (OFFSET_WORLD_ENTITYARRAY)
    if (!IsValidAddress(worldPtr + OFFSET_WORLD_ENTITYARRAY)) return false;
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(worldPtr + OFFSET_WORLD_ENTITYARRAY), &entityArray, sizeof(entityArray), &bytesRead) ||
        bytesRead != sizeof(entityArray)) {
        return false;
    }

    if (!IsValidAddress(entityArray)) return false;

    LogFormat("[LOGEN] ValidateWorldPtr Validated: 0x%p (NearEntList: 0x%p)",
        (void*)worldPtr, (void*)entityArray);

    return true;
}
uintptr_t FindWorldByStaticOffsetWorker128() {
    static uintptr_t g_FirstValidWorldPtr = 0;

    if (g_FirstValidWorldPtr != 0)
        return g_FirstValidWorldPtr;

    uintptr_t base = (uintptr_t)GetModuleHandleA("DayZ_x64.exe");
    if (!base) return 0;

    uintptr_t offsets[] = { OFFSET_WORLD_STATIC }; //0xF4B0A0, 0xF4A0D0 //0xF4B0A0
    for (uintptr_t offset : offsets) {
        uintptr_t address = base + offset;
        if (IsValidAddress(address)) {
            uintptr_t candidate = *(uintptr_t*)address;
            if (IsValidAddress(candidate)) {
                g_FirstValidWorldPtr = candidate;
                return g_FirstValidWorldPtr;
            }
        }
    }
    return 0;
}
DWORD WINAPI InitializeSystemsCycle(LPVOID) {
    try {
        int slowCheckCounter = 0;
        int errorCount = 0;
        uint64_t lastResetTime = GetTickCount64();
        static uint64_t lastKernelCleanup = 0;
        while (true) {
            try {
                ListLoadedModulesAndReadMemoryLimitedStart();

                slowCheckCounter++;
                if (slowCheckCounter >= 3) {
                    DetectHiddenModulesStart();

                    if (slowCheckCounter >= 6) {
                        EnhancedModuleCheckStart();

                        if (slowCheckCounter >= 12) {
                            DetectExternalCheatProcessesStart();
                            slowCheckCounter = 0;
                        }
                    }
                }
                if (lastResetTime - lastKernelCleanup > 360000) {
                    if (g_simpleDetector->IsValid()) {
                        g_simpleDetector->CleanupOldOperationStats(lastResetTime);
                    }
                    ForceFullSystemReset();
                    lastKernelCleanup = lastResetTime;
                }
                KERNELStart();
                if (g_config.enableAggregation) {
                    g_detectionAggregator.ProcessAndLog(true);
                }
                Sleep(10000);
                errorCount = 0;
            }
            catch (...) {
                errorCount++;
                g_simpleDetector->RecordTiming("CYCLE_EXCEPTION", errorCount * 1000.0);

                if (errorCount == 1) Sleep(10000);
                else if (errorCount == 2) Sleep(30000);
                else Sleep(60000);
            }
        }
    }
    catch (...) {}
    return 0;
}
DWORD WINAPI InitializeSystemsThread(LPVOID lpParam) {
    if (!lpParam) {
        Log("[LOGEN] CRITICAL: lpParam is NULL!");
        return 0;
    }
    auto* args = static_cast<std::pair<uintptr_t, uintptr_t>*>(lpParam);
    uintptr_t world = args->first;
    uintptr_t entityArray = args->second;
    delete args;
    bool epsRunning = false;
    try {
        epsRunning = EPS::IsRunning();
        LogFormat("[LOGEN] EPS::IsRunning = %d", epsRunning);
    }
    catch (...) {
        Log("[LOGEN] EPS::IsRunning EXCEPTION!");
        return 0;
    }
    bool ok = false;
    try {
        Log("[LOGEN] Calling InitializeSystemsWithStability...");
        ok = InitializeSystemsWithStability(world, entityArray);
        LogFormat("[LOGEN] InitializeSystemsWithStability returned: %d", ok);
    }
    catch (const std::exception& e) {
        LogFormat("[LOGEN] EXCEPTION: %s", e.what());
    }
    catch (...) {
        Log("[LOGEN] UNKNOWN EXCEPTION");
    }
    g_memoryCleaner.Start();
    HANDLE systemsThreadCycle = CreateThread(nullptr, 0, InitializeSystemsCycle, nullptr, 0, nullptr);
    if (!systemsThreadCycle) {
        Log("[LOGEN] Failed to create systemsThreadCycle thread");
    }
    else {
        Log("[LOGEN] systemsThreadCycle thread created");
        CloseHandle(systemsThreadCycle);
    }
    Log("[LOGEN] Thread finished");
    return 0;
}
void InitializeProtection() {
    static std::atomic<bool> g_ProtectionInitialized{ false };
    if (g_ProtectionInitialized) {
        Log("[LOGEN] InitializeProtection already running, skipping...");
        return;
    }
    g_ProtectionInitialized = true;
    try {
        Log("[LOGEN] InitializeProtection ...");
        uintptr_t world = 0;
        for (int i = 0; i < 10; ++i) {
            world = FindWorldByStaticOffsetWorker128();
            if (IsValidAddress(world)) break;
            Log("[LOGEN] World not found, retrying...");
            Sleep(500);
        }
        if (!IsValidAddress(world)) {
            Log("[LOGEN] World not found after retries, skipping protection.");
            return;
        }
        LogFormat("[LOGEN] World found @ 0x%p", (void*)world);
        if (!ValidateWorldPtr(world)) {
            Log("[LOGEN] Invalid World ptr aborting protection.");
            return;
        }
        uintptr_t entityArray = 0;
        if (!SafeReadPtr(world + OFFSET_WORLD_ENTITYARRAY, entityArray) || !IsValidAddress(entityArray)) {
            Log("[LOGEN] Invalid EntityArray (NearEntList), aborting protection.");
            return;
        }
        LogFormat("[LOGEN] EntityArray read OK @ 0x%p", (void*)entityArray);
        Sleep(10000);
        auto* systemsArgs = new std::pair<uintptr_t, uintptr_t>(world, entityArray);
        HANDLE systemsThread = CreateThread(nullptr, 0, InitializeSystemsThread, systemsArgs, 0, nullptr);
        if (!systemsThread) {
            Log("[LOGEN] Failed to create InitializeSystems thread");
        }
        else {
            Log("[LOGEN] InitializeSystems thread created");
        }
        Log("[LOGEN] InitializeProtection succesful");
    }
    catch (...) {
        Log("[LOGEN] InitializeProtection crashed");
    }
}
#pragma endregion
void InitializeMonitoring() {
    try {
        g_totalDetections = 0;
        g_loggedDetections = 0;
        g_config.logCooldownNormal = 60000;
        g_config.logCooldownCritical = 30000;
        g_config.minDetectionsForLog = 3;
        g_config.enableAggregation = true;
        g_config.logMissedDetections = true;
        isLicenseVersion = DetermineAndSetGameProcessNames();
        if (!isLicenseVersion) {
            ReadSteamUIDStart();
        }
        else {
            ReadGoldbergUIDStart("Goldberg SteamEmu Saves\\settings\\user_steam_id.txt");
        }
        Sleep(1500);
        HWID();
        Sleep(1500);
        try {
            ListLoadedModulesAndReadMemoryLimitedStart();
        }
        catch (...) {}
        try {
            HookIATStart();
        }
        catch (...) {}
        Sleep(1500);
        InfoOut(hwid, Goldberg_UID_SC);
        Sleep(1500);
        if (GameProjectdayzzona) {
            try {
                std::string injectedProcess = GetInjectedProcessName();
                std::transform(injectedProcess.begin(), injectedProcess.end(), injectedProcess.begin(), ::tolower);
                if (injectedProcess == Name_Game2) {
                    std::thread([]() {
                        for (int i = 0; i < 60; i++) {
                            Sleep(1000);
                            if (i % 60 == 0) {
                                int remaining = 60 - i;
                                LogFormat("[LOGEN] StartKeyToggleMonitoring starts in %d:%02d", remaining / 60, remaining % 60);
                            }
                        }
                        Log("[LOGEN] Starting KeyToggleMonitoring...");
                        StartKeyToggleMonitoring();
                        Sleep(2000);
                        while (true) {
                            Sleep(120000);
                            if (IsKeyMonitoringActive()) {
                                Log("[LOGEN] KeyMonitor stats: " + GetKeyMonitorStats());
                            }
                        }
                        }).detach();
                }
            }
            catch (const std::exception& e) {
                Log("[LOGEN] KeyToggleMonitoring: " + std::string(e.what()));
            }
        }
        try {
            std::string injectedProcess = GetInjectedProcessName();
            std::transform(injectedProcess.begin(), injectedProcess.end(), injectedProcess.begin(), ::tolower);
            if (injectedProcess == Name_Game2) {
                Log("[LOGEN] SVG START :" + Name_Game2);

                for (int i = 0; i < 240; i++) {
                    Sleep(1000);
                    if (i % 60 == 0) {
                        int remaining = 240 - i;
                        LogFormat("[LOGEN] Protection starts in %d:%02d", remaining / 60, remaining % 60);
                    }
                }
                std::thread([]() {
                    Log("[LOGEN] Config: Normal CD=" + std::to_string(g_config.logCooldownNormal) + "ms Critical CD=" + std::to_string(g_config.logCooldownCritical) + "ms");
                    InitializeProtection();
                    Sleep(1000);
                    if (g_screenshotCapturer.IsOverlayUnderAttack()) {
                        Log("[LOGEN] Overlay debug mode activated due to attack");
                    }
                    if (!g_simpleDetector) {
                        g_simpleDetector = std::make_unique<KernelCheatDetector>(Name_Game, true);
                        Log("[LOGEN] KernelCheatDetector initialized");
                    }
                    Sleep(1000);
                    InitializeVulkanDetection();
                    Sleep(5000);
                    StartVulkanMonitor();
                    while (true) {
                        try {
                            InfoOutStatus(hwid, Goldberg_UID_SC);
                            Sleep(10000);
                            CheckMemoryAndCleanup();
                        }
                        catch (const std::exception& e) {
                            Log("[ERROR] InfoOutStatus update failed: " + std::string(e.what()));
                        };
                    }
                    }).detach();
                g_runPeriodicServerThread = true;
                g_periodicServerThread = std::thread(PeriodicServerScreenshotThread);
            }
        }
        catch (const std::exception& e) {
            Log("[LOGEN] injectedProcess: " + std::string(e.what()));
        }
        Sleep(1000);
    }
    catch (...) {}
}
DWORD WINAPI SafeInitialize(LPVOID) {
    __try {
       InitializeMonitoring();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
    return 0;
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ulReason, LPVOID lpReserved) {
    if (ulReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        HANDLE hThread = CreateThread(nullptr, 0, SafeInitialize, nullptr, 0, nullptr);
        if (hThread) CloseHandle(hThread);
    }
    else if (ulReason == DLL_PROCESS_DETACH) {
        g_runPeriodicServerThread = false;
        if (g_periodicServerThread.joinable()) {
            g_periodicServerThread.join();
        }
        g_memoryCleaner.Stop();
        UnhookIAT();
        UnhookAdditionalAPI();
    }
    return TRUE;
}
