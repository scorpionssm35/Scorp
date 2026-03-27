#pragma once
extern std::string hwid;
extern std::atomic<int> g_currentScreenshotter;
extern void StartSightImgDetection(const std::string& infouser);
void InfoOutMessage(const std::string& hwid, const std::string& id, const std::string& message);
extern bool DetermineAndSetGameProcessNames();
extern int SaveScreenshotToDiskCount;
extern std::string CalculateFileSHA256Safe(const std::string& filePath);
class SHA256 {
public:
    SHA256();
    void update(const uint8_t* data, size_t length);
    void finalize();
    uint8_t* getHash();

private:
    void transform();
    uint32_t m_state[8];
    uint64_t m_bitLength;
    uint32_t m_dataLength;
    uint8_t m_data[64];
    uint8_t m_hash[32];
    static const uint32_t K[64];  // ← только объявление, без инициализации
};