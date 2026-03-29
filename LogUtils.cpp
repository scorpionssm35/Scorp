#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "Ws2_32.lib")
#include "LogUtils.h"
#include <wincrypt.h>
#include <sstream>
#include <iomanip>
#include <cstdarg>
#include <dbghelp.h>
#include <Psapi.h>
#include <winternl.h>
#include <ntstatus.h> 
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <tlhelp32.h>
#include <algorithm>
#include <cctype>
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
#include <future>
#include <unordered_set>
#include <shlwapi.h>
#include <chrono>
#include "dllmain.h"
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

std::string Name_Dll = "system.windows.group.dll";
std::string hostsc = "registration.dayzavr-tech.ru";
//std::string hostsc = "78.136.220.94";//dayzzona
std::string Name_Launcher = "dayzavr dayz.exe";
std::string Name_Launcher2 = "dayzzona launcher.exe";
std::string Name_Window = "DayZ";
int hostport = 18000;
int Port_Panel_Registered = 17000;
std::string Name_Game = "dayz_x64.exe";
std::string Name_Game2 = "dayz_x64";
std::string Name_GameEXE = "DayZ_x64.exe";
std::string Name_GameEXE2 = "DayZ_x64";

std::string Base64Encode(const std::string& in) {
    static const char* base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}
std::string XorEncrypt(const std::string& input, const std::string& key) {
    std::string result = input;
    for (size_t i = 0; i < input.size(); ++i)
        result[i] ^= key[i % key.size()];
    return result;
}
static std::string GetCurrentName() {
    HMODULE hModule = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        (LPCWSTR)&GetCurrentName, &hModule);

    if (!hModule) {
        return "Unknown.dll";
    }

    WCHAR dllPathW[MAX_PATH];
    DWORD result = GetModuleFileNameW(hModule, dllPathW, MAX_PATH);

    if (result == 0 || result == MAX_PATH) {
        return "Unknown.dll";
    }
    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, dllPathW, -1, NULL, 0, NULL, NULL);
    if (bufferSize <= 0) {
        return "Unknown.dll";
    }

    std::string path(bufferSize - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, dllPathW, -1, &path[0], bufferSize, NULL, NULL);

    size_t pos = path.find_last_of("\\/");
    if (pos != std::string::npos) {
        return path.substr(pos + 1);
    }
    return path;
}
static std::string GetDLLSHA256() {
    HMODULE hModule = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        (LPCWSTR)&GetCurrentName, &hModule);

    if (!hModule) {
        return "";
    }

    WCHAR dllPathW[MAX_PATH];
    GetModuleFileNameW(hModule, dllPathW, MAX_PATH);
    HANDLE hFile = CreateFileW(dllPathW, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        WCHAR tempPath[MAX_PATH];
        WCHAR tempFile[MAX_PATH];

        if (GetTempPathW(MAX_PATH, tempPath)) {
            const WCHAR* fileName = wcsrchr(dllPathW, L'\\');
            if (!fileName) fileName = wcsrchr(dllPathW, L'/');
            if (!fileName) fileName = dllPathW;
            else fileName++; 
            if (GetTempFileNameW(tempPath, L"DLL", 0, tempFile)) {
                if (CopyFileW(dllPathW, tempFile, FALSE)) {
                    hFile = CreateFileW(tempFile, GENERIC_READ,
                        FILE_SHARE_READ, NULL, OPEN_EXISTING,
                        FILE_FLAG_DELETE_ON_CLOSE, NULL); 
                }
            }
        }

        if (hFile == INVALID_HANDLE_VALUE) {
            return "";
        }
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return "";
    }

    std::vector<BYTE> buffer(fileSize);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        CloseHandle(hFile);
        return "";
    }

    CloseHandle(hFile);
    SHA256 sha;
    sha.update(buffer.data(), buffer.size());
    sha.finalize();

    uint8_t* hash = sha.getHash();
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 32; i++) {
        ss << std::setw(2) << (int)hash[i];
    }
    return ss.str();
}
std::string GetSecureIdentifier() {
    std::string dllName = GetCurrentName();
    std::string sha256Hash = GetDLLSHA256();

    if (sha256Hash.empty()) {
        std::string encrypted = XorEncrypt(dllName + "|", Name_Dll);
        std::string encoded = Base64Encode(encrypted);
        return encoded;
    }
    std::string identifier = dllName + "|" + sha256Hash;
    std::string encrypted = XorEncrypt(identifier, Name_Dll);
    std::string encoded = Base64Encode(encrypted);
    return encoded;
}
static std::chrono::steady_clock::time_point lastForcedCleanup = std::chrono::steady_clock::now();
std::string GetModuleNameFromRIP(uintptr_t rip) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    HANDLE hProcess = GetCurrentProcess();

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < cbNeeded / sizeof(HMODULE); ++i) {
            MODULEINFO mi = {};
            if (GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) {
                uintptr_t base = (uintptr_t)mi.lpBaseOfDll;
                if (rip >= base && rip < base + mi.SizeOfImage) {
                    wchar_t wpath[MAX_PATH];
                    if (GetModuleFileNameExW(hProcess, hMods[i], wpath, MAX_PATH)) {
                        const wchar_t* wfile = PathFindFileNameW(wpath); // ? только имя
                        char fileA[MAX_PATH];
                        WideCharToMultiByte(CP_ACP, 0, wfile, -1, fileA, MAX_PATH, NULL, NULL);
                        return std::string(fileA);
                    }
                }
            }
        }
    }
    return "";
}
std::string GetLogFilePath() {
    wchar_t appDataPath[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath) != S_OK)
        return "dlc.tmp";

    std::wstring folder(appDataPath);
    folder += L"\\DayZ\\";
    CreateDirectoryW(folder.c_str(), NULL);

    std::wstring finalPath = folder + L"dlc.tmp";
    return std::string(finalPath.begin(), finalPath.end());
}
#pragma region SteamID
std::string Goldberg_UID_SC = "---";
uint64_t Steam2ToSteam64(const std::string& steam2) {
    try {
        if (steam2.empty()) return 0;

        // Формат: STEAM_X:Y:Z
        size_t pos1 = steam2.find('_');
        size_t pos2 = steam2.find(':');
        size_t pos3 = steam2.find(':', pos2 + 1);

        if (pos1 == std::string::npos || pos2 == std::string::npos || pos3 == std::string::npos)
            return 0;

        int universe = std::stoi(steam2.substr(pos1 + 1, pos2 - pos1 - 1));
        int accountType = std::stoi(steam2.substr(pos2 + 1, pos3 - pos2 - 1));
        int accountNumber = std::stoi(steam2.substr(pos3 + 1));

        return (uint64_t)accountNumber * 2 + (uint64_t)accountType + 76561197960265728ULL;
    }
    catch (...) {
        return 0;
    }
}
uint64_t Steam32ToSteam64(uint32_t steam32) {
    return steam32 + 76561197960265728ULL;
}
void ReadGoldbergUID(const std::string& relativePath) {
    try {
        char appDataPath[MAX_PATH] = {};
        if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath) != S_OK) {
            //Log("[LOGEN] SHGetFolderPathA failed in ReadGoldbergUID");
            return;
        }

        std::string fullPath = std::string(appDataPath) + "\\" + relativePath;

        std::ifstream file(fullPath);
        if (!file.is_open()) {
            //Log("[LOGEN] Failed to open user_steam_id.txt");
            return;
        }

        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) {
                Goldberg_UID_SC = line;
                break;
            }
        }
    }
    catch (...) {
        //Log("[LOGEN] ReadGoldbergUID failed unexpectedly");
    }
}
void ReadGoldbergUIDSteam() {
    try {
        // Получаем путь к Steam
        HKEY hKey;
        char steamPath[MAX_PATH] = {};
        DWORD bufferSize = sizeof(steamPath);
        LONG result;

        // Пробуем разные пути в реестре
        bool foundPath = false;

        // Сначала пробуем HKCU (пользовательский путь)
        result = RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Valve\\Steam", 0, KEY_READ, &hKey);
        if (result == ERROR_SUCCESS) {
            bufferSize = sizeof(steamPath);
            if (RegQueryValueExA(hKey, "SteamPath", NULL, NULL, (LPBYTE)steamPath, &bufferSize) == ERROR_SUCCESS) {
                foundPath = true;
            }
            RegCloseKey(hKey);
        }

        // Если не нашли в HKCU, пробуем HKLM
        if (!foundPath) {
            result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Valve\\Steam", 0, KEY_READ, &hKey);
            if (result == ERROR_SUCCESS) {
                bufferSize = sizeof(steamPath);
                if (RegQueryValueExA(hKey, "InstallPath", NULL, NULL,
                    (LPBYTE)steamPath, &bufferSize) == ERROR_SUCCESS) {
                    foundPath = true;
                }
                RegCloseKey(hKey);
            }
        }

        // Последняя попытка: обычный HKLM путь
        if (!foundPath) {
            result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Valve\\Steam", 0, KEY_READ, &hKey);
            if (result == ERROR_SUCCESS) {
                bufferSize = sizeof(steamPath);
                if (RegQueryValueExA(hKey, "InstallPath", NULL, NULL,
                    (LPBYTE)steamPath, &bufferSize) == ERROR_SUCCESS) {
                    foundPath = true;
                }
                RegCloseKey(hKey);
            }
        }

        if (!foundPath) {
           // Log("[LOGEN] Steam path not found in registry");
            Goldberg_UID_SC = "---";
            return;
        }

        LogFormat("[LOGEN] Steam path found: %s", steamPath);

        // Проверяем три возможных места для Steam ID
        std::string possiblePaths[] = {
            std::string(steamPath) + "\\config\\loginusers.vdf",
            std::string(steamPath) + "\\config\\config.vdf",
            std::string(steamPath) + "\\logs\\connection_log.txt"
        };

        const char* pathNames[] = {
            "loginusers.vdf",
            "config.vdf",
            "connection_log.txt"
        };

        bool foundSteamID = false;
        std::string foundInFile = "";

        // Проверяем каждый файл по очереди
        for (int i = 0; i < 3; i++) {
            std::string filePath = possiblePaths[i];
            std::string fileName = pathNames[i];

           // LogFormat("[LOGEN] Checking %s at: %s", fileName.c_str(), filePath.c_str());

            // Проверяем существование файла
            DWORD fileAttrib = GetFileAttributesA(filePath.c_str());
            if (fileAttrib == INVALID_FILE_ATTRIBUTES ||
                (fileAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
               // LogFormat("[LOGEN] %s not found or is directory", fileName.c_str());
                continue;
            }

            std::ifstream file(filePath);
            if (!file.is_open()) {
               // LogFormat("[LOGEN] Failed to open %s", fileName.c_str());
                continue;
            }

            std::string line;
            std::string fileContent;

            // Читаем весь файл
            while (std::getline(file, line)) {
                fileContent += line + "\n";
            }
            file.close();

           // LogFormat("[LOGEN] Read %zu bytes from %s", fileContent.length(), fileName.c_str());

            // В зависимости от файла используем разные методы поиска
            if (fileName == "loginusers.vdf") {
                // Парсим loginusers.vdf - формат Valve Data Format
                // Ищем SteamID в формате: "SteamID"		"7656119xxxxxxxxxx"
                std::regex steamIdPattern("\"SteamID\"\\s+\"(\\d{17})\"");
                std::smatch match;

                if (std::regex_search(fileContent, match, steamIdPattern) && match.size() > 1) {
                    std::string steamId = match[1].str();
                    if (steamId.length() == 17 && steamId.substr(0, 7) == "7656119") {
                        Goldberg_UID_SC = steamId;
                        foundSteamID = true;
                        foundInFile = fileName;
                       // LogFormat("[LOGEN] Found SteamID in %s: %s", fileName.c_str(), steamId.c_str());
                        break;
                    }
                }

                // Альтернативный поиск: ищем любые 17-значные числа
                std::regex anySteam64("\\b(7656119\\d{10})\\b");
                std::sregex_iterator begin(fileContent.begin(), fileContent.end(), anySteam64);
                std::sregex_iterator end;

                for (auto it = begin; it != end; ++it) {
                    std::string steamId = (*it)[1].str();
                    if (steamId.length() == 17) {
                        Goldberg_UID_SC = steamId;
                        foundSteamID = true;
                        foundInFile = fileName;
                       // LogFormat("[LOGEN] Found SteamID (alt method) in %s: %s", fileName.c_str(), steamId.c_str());
                        break;
                    }
                }

                if (foundSteamID) break;

            }
            else if (fileName == "config.vdf") {
                // Парсим config.vdf - ищем SteamID в различных местах
                // Ищем "SteamID" или "SteamId" в разных форматах
                std::vector<std::regex> patterns;
                patterns.push_back(std::regex("\"SteamID\"\\s*\"(\\d{17})\""));
                patterns.push_back(std::regex("\"SteamId\"\\s*\"(\\d{17})\""));
                patterns.push_back(std::regex("\"steamid\"\\s*\"(\\d{17})\""));
                patterns.push_back(std::regex("\"AccountID\"\\s*\"(\\d+)\""));

                for (const auto& pattern : patterns) {
                    std::smatch match;
                    if (std::regex_search(fileContent, match, pattern) && match.size() > 1) {
                        std::string steamId = match[1].str();

                        // Если это AccountID (32-битный), конвертируем в Steam64
                        if (steamId.length() <= 10 && std::all_of(steamId.begin(), steamId.end(), ::isdigit)) {
                            try {
                                uint32_t accountId = std::stoul(steamId);
                                uint64_t steam64 = Steam32ToSteam64(accountId);
                                if (steam64 > 76561197960265728ULL) {
                                    Goldberg_UID_SC = std::to_string(steam64);
                                    foundSteamID = true;
                                    foundInFile = fileName;
                                   // LogFormat("[LOGEN] Found AccountID in %s, converted to Steam64: %s", fileName.c_str(), Goldberg_UID_SC.c_str());
                                    break;
                                }
                            }
                            catch (...) {
                                // Пропускаем
                            }
                        }
                        // Если это Steam64 ID
                        else if (steamId.length() == 17 && steamId.substr(0, 7) == "7656119") {
                            Goldberg_UID_SC = steamId;
                            foundSteamID = true;
                            foundInFile = fileName;
                           // LogFormat("[LOGEN] Found SteamID in %s: %s", fileName.c_str(), steamId.c_str());
                            break;
                        }
                    }
                }

                if (foundSteamID) break;

            }
            else if (fileName == "connection_log.txt") {
                // Парсим connection_log.txt - ищем последние успешные логины
                // Разделяем на строки и ищем снизу вверх
                std::vector<std::string> lines;
                std::istringstream iss(fileContent);
                std::string singleLine;

                while (std::getline(iss, singleLine)) {
                    lines.push_back(singleLine);
                }

                // Ищем снизу вверх (последние записи)
                for (auto it = lines.rbegin(); it != lines.rend(); ++it) {
                    std::string line = *it;

                    // Ищем индикаторы успешного входа
                    bool hasLoginIndicator =
                        line.find("LogOnResponse") != std::string::npos ||
                        line.find("logged on OK") != std::string::npos ||
                        line.find("Login succeeded") != std::string::npos ||
                        line.find("Logon success") != std::string::npos ||
                        line.find("SteamID") != std::string::npos ||
                        line.find("7656119") != std::string::npos;

                    if (hasLoginIndicator) {
                        // Пытаемся найти Steam64 ID (17 цифр, начинается с 7656119)
                        std::regex steam64Pattern("\\b(7656119\\d{10})\\b");
                        std::smatch match;

                        if (std::regex_search(line, match, steam64Pattern) && match.size() > 1) {
                            std::string steamId = match[1].str();
                            if (steamId.length() == 17) {
                                Goldberg_UID_SC = steamId;
                                foundSteamID = true;
                                foundInFile = fileName;
                                LogFormat("[LOGEN] Found SteamID in %s (line): %s",
                                    fileName.c_str(), steamId.c_str());
                                break;
                            }
                        }

                        // Пытаемся найти Steam2 ID
                        std::regex steam2Pattern("STEAM_[0-5]:[0-1]:\\d+");
                        if (std::regex_search(line, match, steam2Pattern) && match.size() > 0) {
                            std::string steam2Id = match[0].str();
                            uint64_t steam64 = Steam2ToSteam64(steam2Id);
                            if (steam64 > 76561197960265728ULL) {
                                Goldberg_UID_SC = std::to_string(steam64);
                                foundSteamID = true;
                                foundInFile = fileName;
                                LogFormat("[LOGEN] Found Steam2 ID in %s, converted to Steam64: %s",
                                    fileName.c_str(), Goldberg_UID_SC.c_str());
                                break;
                            }
                        }
                    }
                }

                if (foundSteamID) break;
            }
        }

        if (!foundSteamID) {
           // Log("[LOGEN] No valid Steam ID found in any file");
            Goldberg_UID_SC = "---";
        }
        else {
            LogFormat("[LOGEN] Steam ID successfully found in %s: %s", foundInFile.c_str(), Goldberg_UID_SC.c_str());
        }

    }
    catch (const std::exception& e) {
       // Log("[LOGEN] Exception in ReadGoldbergUIDSteam: " + std::string(e.what()));
        Goldberg_UID_SC = "---";
    }
    catch (...) {
       // Log("[LOGEN] Unknown exception in ReadGoldbergUIDSteam");
        Goldberg_UID_SC = "---";
    }
}
void ReadGoldbergUIDStart(const std::string& relativePath) {
    __try {
        ReadGoldbergUID(relativePath);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
void ReadSteamUIDStart() {
    __try {
        ReadGoldbergUIDSteam();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}
#pragma endregion
void LogTest(const std::string& message) {
    try {
        if (message.empty()) return;
        if (message.empty() || message.find("[LOGEN] TCP") != std::string::npos) {
            return;
        }

        // Попытка получить путь %LOCALAPPDATA%
        wchar_t appDataPath[MAX_PATH] = {};
        if (SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath) != S_OK) {
            std::ofstream fallback("C:\\dlc_test.tmp", std::ios::app);
            if (fallback.is_open()) {
                fallback << message << "\n";
                fallback.close();
            }
            return;
        }

        std::wstring tempDir = std::wstring(appDataPath) + L"\\Temp\\";
        CreateDirectoryW(tempDir.c_str(), NULL);
        std::wstring finalPath = tempDir + L"dlc_test.tmp";

        std::string narrowPath(finalPath.begin(), finalPath.end());
        std::ofstream logFile(narrowPath, std::ios::app);
        if (!logFile.is_open()) return;

        logFile << message << "\n";
        logFile.close();
    }
    catch (...) {
        // Silent fail
    }
}
#include <unordered_map>
std::unordered_map<size_t, CachedMessage> messageCache;
std::mutex cacheMutex;
static const size_t MAX_CACHE_SIZE = 5000;
static const auto CACHE_DURATION = std::chrono::minutes(5);
static std::chrono::steady_clock::time_point lastCleanup = std::chrono::steady_clock::now();
size_t HashMessage(const std::string& msg)
{
    return std::hash<std::string>{}(msg);
}
void CleanupOldMessages()
{
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - CACHE_DURATION;

    for (auto it = messageCache.begin(); it != messageCache.end(); )
    {
        if (it->second.time < cutoff)
            it = messageCache.erase(it);
        else
            ++it;
    }
}
bool IsMessageCached(const std::string& message)
{
    std::lock_guard<std::mutex> lock(cacheMutex);

    size_t hash = HashMessage(message);

    auto it = messageCache.find(hash);

    if (it == messageCache.end())
        return false;

    return true;
}
void CacheMessage(const std::string& message)
{
    size_t hash = HashMessage(message);

    auto now = std::chrono::steady_clock::now();

    std::lock_guard<std::mutex> lock(cacheMutex);

    messageCache[hash] = { now };

    if (messageCache.size() > MAX_CACHE_SIZE)
    {
        CleanupOldMessages();

        if (messageCache.size() > MAX_CACHE_SIZE)
            messageCache.clear();
    }
}
void LogTXTOld(const std::string& message) {
    try {
        if (message.empty()) return;
        if (message.empty() || message.find("[LOGEN] TCP") != std::string::npos) {
            return;
        }
        std::string uidPrefix = VerSVG + "[Goldberg-" + Goldberg_UID_SC + "] ";
        std::string fullMessage = uidPrefix + message;
        LogTest(fullMessage);
        /*
        std::string encrypted = XorEncrypt(fullMessage, Name_Dll);
        std::string encoded = Base64Encode(encrypted);
        wchar_t appDataPath[MAX_PATH] = {};
        if (SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataPath) != S_OK) {
            std::ofstream fallback("C:\\dlc.tmp", std::ios::app | std::ios::binary);
            if (fallback.is_open()) {
                fallback << encoded << "\n";
                fallback.close();
            }
            return;
        }
        std::wstring tempDir = std::wstring(appDataPath) + L"\\Temp\\";
        CreateDirectoryW(tempDir.c_str(), NULL);
        std::wstring finalPath = tempDir + L"dlc.tmp";
        std::string narrowPath(finalPath.begin(), finalPath.end());
        std::ofstream logFile(narrowPath, std::ios::app | std::ios::binary);
        if (!logFile.is_open()) return;
        logFile << encoded << "\n";
        logFile.close();
        */
        InfoOutMessage(hwid, Goldberg_UID_SC, message);
    }
    catch (...) {
        // Silent fail
    }
}
void LogTXT(const std::string& message) {
    try {
        if (message.empty()) return;
        if (message.empty() || message.find("[LOGEN] TCP") != std::string::npos) {
            return;
        }
        std::string processedMessage = message;
        for (char drive = 'A'; drive <= 'Z'; ++drive) {
            std::string upperDrivePrefix = std::string(1, drive) + ":\\";
            std::string lowerDrivePrefix = std::string(1, tolower(drive)) + ":\\";
            size_t pos = processedMessage.find(upperDrivePrefix);
            while (pos != std::string::npos) {
                processedMessage.replace(pos, 3, "");
                pos = processedMessage.find(upperDrivePrefix, pos);
            }

            // Удаляем строчный вариант
            pos = processedMessage.find(lowerDrivePrefix);
            while (pos != std::string::npos) {
                processedMessage.replace(pos, 3, "");
                pos = processedMessage.find(lowerDrivePrefix, pos);
            }
        }

        std::string uidPrefix = VerSVG + "[Goldberg-" + Goldberg_UID_SC + "] ";
        std::string fullMessage = uidPrefix + processedMessage;
        LogTest(fullMessage);
        InfoOutMessage(hwid, Goldberg_UID_SC, processedMessage);
    }
    catch (...) {
    }
}
void LogAdd(const std::string& message)
{
    __try
    {
        LogTXT(message);
        CacheMessage(message);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}
void Log(const std::string& message)
{
    if (message.empty())
        return;

    if (IsMessageCached(message))
        return;

    LogAdd(message);

    auto now = std::chrono::steady_clock::now();

    if (now - lastCleanup > std::chrono::minutes(1))
    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        CleanupOldMessages();
        lastCleanup = now;
    }
}
void LogFormat(const char* format, ...)
{
    char buffer[512];

    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    Log(buffer);
}

bool IsValidAddress(uintptr_t addr) {
    if (addr == 0 || addr < 0x10000 || addr > 0x7FFFFFFFFFFF)
        return false;

    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0)
        return false;

    // Если страница выделена — считаем адрес валидным, даже если она PAGE_NOACCESS
    return mbi.State == MEM_COMMIT;
}
bool SafeReadPtr(uintptr_t addr, uintptr_t& out) {
    if (addr == 0 || addr == 0xFFFFFFFFFFFFFFFF || addr < 0x10000 || !IsValidAddress(addr))
        return false;

    if (addr > 0x00007FFFFFFFFFFF) {
        LogFormat("[LOGEN] Skipped invalid high address: 0x%p", (void*)addr);
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0)
        return false;

    bool restoreProt = false;
    DWORD oldProt = 0;

    // Если стоит PAGE_NOACCESS — временно разрешаем чтение
    if (mbi.Protect & PAGE_NOACCESS) {
        if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProt))
            restoreProt = true;
        else
            return false;
    }

    bool success = false;
    __try {
        out = *(volatile uintptr_t*)addr;
        success = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        success = false;
    }

    // Восстанавливаем защиту
    if (restoreProt)
        VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProt, &oldProt);

    return success;
}
bool IsGameRIP(uintptr_t rip) {
    static uintptr_t gameBase = 0;
    static uintptr_t gameEnd = 0;

    // Кешируем базовый адрес игры
    if (gameBase == 0) {
        HMODULE gameModule = GetModuleHandleA(Name_GameEXE.c_str());
        if (gameModule) {
            MODULEINFO modInfo;
            if (GetModuleInformation(GetCurrentProcess(), gameModule, &modInfo, sizeof(modInfo))) {
                gameBase = (uintptr_t)modInfo.lpBaseOfDll;
                gameEnd = gameBase + modInfo.SizeOfImage;
                LogFormat("[LOGEN] Game code range: 0x%p - 0x%p", (void*)gameBase, (void*)gameEnd);
            }
        }
    }

    return (rip >= gameBase && rip < gameEnd);
}