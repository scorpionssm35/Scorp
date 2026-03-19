#pragma once
extern std::string hwid;
extern std::atomic<int> g_currentScreenshotter;
extern void StartSightImgDetection(const std::string& infouser);
void InfoOutMessage(const std::string& hwid, const std::string& id, const std::string& message);
extern bool DetermineAndSetGameProcessNames();
extern int SaveScreenshotToDiskCount;
extern std::string CalculateFileSHA256Safe(const std::string& filePath);