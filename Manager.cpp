#include "Manager.h"
#include <wintrust.h>
#include <softpub.h>
#include <codecvt>
#include <locale>

#pragma comment(lib, "wintrust.lib")

Manager& Manager::GetInstance() {
    static Manager instance;
    return instance;
}

void Manager::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_dllEntries.empty()) return;
    AddDefaultEntries();
}

std::wstring Manager::ToWString(const std::string& str) const {
    if (str.empty()) return L"";
    try {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        return converter.from_bytes(str);
    }
    catch (...) {
        std::wstring result;
        result.reserve(str.size());
        for (char c : str) result += static_cast<wchar_t>(static_cast<unsigned char>(c));
        return result;
    }
}

void Manager::AddDefaultEntries() {
    AddDLL(LR"(.*steam_api64\.dll$)", "", true);
    AddDLL(LR"(.*DayZavr\.dll$)", "", true);
    AddDLL(LR"(.*BEClient_x64\.dll$)", "", true);
    AddDLL(LR"(.*NVIDIA Corporation\\NVIDIA App\\MessageBus\\MessageBus\.dll$)", "", true);

    AddDLL(LR"(.*DayZavr_Launcher.*System\.Windows\.Group\.dll$)",
        "a565cf7f7958aba702ad4e48a03203b8ec2832af7b939651ebfbb53b117200d7", true);


    m_privateRegionRegexes.push_back(LR"(.*TranslucentTB.*ExplorerHooks\.dll$)");

    // Другие легитимные
    AddDLL(LR"(.*discord_game_overlay\.dll$)", "", true);
    AddDLL(LR"(.*NVIDIA.*FrameView.*)", "", true);
    AddDLL(LR"(.*NVIDIA.*NvContainer.*)", "", true);
    AddDLL(LR"(.*MSI Afterburner.*)", "", true);
    AddDLL(LR"(.*RivaTuner.*)", "", true);
    AddDLL(LR"(.*RTSS.*)", "", true);
    AddDLL(LR"(.*Overwolf.*)", "", true);
    AddDLL(LR"(.*XboxGameBar.*)", "", true);
}

void Manager::AddDLL(const std::wstring& path_regex, const std::string& sha256,
    bool checkSig, bool ignorePrivate) {
    WhitelistEntry e{ path_regex, sha256, checkSig, ignorePrivate };
    m_dllEntries.push_back(std::move(e));
}

bool Manager::IsWhitelistedDLL(const std::string& fullPath, const std::string& sha256) {
    return IsWhitelistedDLL(ToWString(fullPath), sha256);
}

bool Manager::IsWhitelistedDLL(const std::wstring& fullPath, const std::string& sha256) {
    if (fullPath.empty()) return false;

    std::lock_guard<std::mutex> lock(m_mutex);
    std::wstring cacheKey = fullPath + L"|" + ToWString(sha256);
    if (m_dllCache.count(cacheKey)) return m_dllCache[cacheKey];

    try {
        std::wstring wpath = fullPath;
        bool signatureOk = CheckDigitalSignature(wpath);

        for (const auto& entry : m_dllEntries) {
            if (std::regex_search(wpath, std::wregex(entry.path_regex, std::regex::icase))) {
                bool hashOk = entry.required_sha256.empty() || entry.required_sha256 == sha256;
                bool result = hashOk && (!entry.check_signature || signatureOk);
                m_dllCache[cacheKey] = result;
                return result;
            }
        }
    }
    catch (...) {
    }

    m_dllCache[cacheKey] = false;
    return false;
}

bool Manager::ShouldIgnorePrivateRegion(const std::string& fullPath) {
    return ShouldIgnorePrivateRegion(ToWString(fullPath));
}

bool Manager::ShouldIgnorePrivateRegion(const std::wstring& fullPath) {
    if (fullPath.empty()) return false;

    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_privateCache.count(fullPath)) return m_privateCache[fullPath];

    try {
        for (const auto& regexStr : m_privateRegionRegexes) {
            if (std::regex_search(fullPath, std::wregex(regexStr, std::regex::icase))) {
                m_privateCache[fullPath] = true;
                return true;
            }
        }
    }
    catch (...) {}

    m_privateCache[fullPath] = false;
    return false;
}

bool Manager::CheckDigitalSignature(const std::wstring& filePath) {
    if (filePath.empty()) return false;

    WINTRUST_FILE_INFO fileInfo = { sizeof(WINTRUST_FILE_INFO), const_cast<LPWSTR>(filePath.c_str()), nullptr };
    WINTRUST_DATA trustData = { sizeof(WINTRUST_DATA) };
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    return (status == ERROR_SUCCESS);
}