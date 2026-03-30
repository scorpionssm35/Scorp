#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <regex>
#include <windows.h>

struct WhitelistEntry {
    std::wstring path_regex;        
    std::string  required_sha256;   
    bool check_signature = true;
    bool ignore_private_region = false;
};

class Manager {
public:
    static Manager& GetInstance();

    void Initialize();                                     

    // Поддержка и string, и wstring (удобно)
    bool IsWhitelistedDLL(const std::string& fullPath, const std::string& sha256 = "");
    bool IsWhitelistedDLL(const std::wstring& fullPath, const std::string& sha256 = "");

    bool ShouldIgnorePrivateRegion(const std::string& fullPath);
    bool ShouldIgnorePrivateRegion(const std::wstring& fullPath);

    // Добавление в рантайме (если нужно)
    void AddDLL(const std::wstring& path_regex, const std::string& sha256 = "",
        bool checkSig = true, bool ignorePrivate = false);

private:
    Manager() = default;

    void AddDefaultEntries();
    bool CheckDigitalSignature(const std::wstring& filePath);

    std::wstring ToWString(const std::string& str) const;  

    std::vector<WhitelistEntry> m_dllEntries;
    std::vector<std::wstring>   m_privateRegionRegexes;

    mutable std::unordered_map<std::wstring, bool> m_dllCache;
    mutable std::unordered_map<std::wstring, bool> m_privateCache;

    std::mutex m_mutex;
};