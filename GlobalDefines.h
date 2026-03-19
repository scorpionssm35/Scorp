#pragma once
#include <atomic>
#include <cstdint>

// ќбъ€влени€ глобальных переменных (без определени€)
extern std::atomic<int> g_cameraFailures;
extern std::atomic<uintptr_t> g_globalEntityArray; // переименуем чтобы избежать конфликта