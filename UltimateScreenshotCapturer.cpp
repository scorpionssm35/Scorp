#include "UltimateScreenshotCapturer.h"
#include "InvisibleOverlay.h"
#include <chrono>
#include <sstream>
#include <iomanip>
#include <shlobj.h>
#include <algorithm>
#include <random>
#include <thread>
#include <dwmapi.h>
#include <Gdiplus.h>
#include "LogUtils.h"
#include "dllmain.h"
#pragma comment(lib, "gdiplus.lib")
using namespace Gdiplus;

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3d11.lib")

static ULONG_PTR g_gdiplusToken = 0;
static bool g_gdiplusInitialized = false;
bool InitializeGDIPlus() {
    if (g_gdiplusInitialized) return true;

    GdiplusStartupInput gdiplusStartupInput;
    if (GdiplusStartup(&g_gdiplusToken, &gdiplusStartupInput, NULL) == Ok) {
        g_gdiplusInitialized = true;
        return true;
    }
    return false;
}

void ShutdownGDIPlus() {
    if (g_gdiplusInitialized) {
        GdiplusShutdown(g_gdiplusToken);
        g_gdiplusInitialized = false;
    }
}
inline std::string HResultToString(HRESULT hr)
{
    std::stringstream ss;
    ss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << hr;
    return ss.str();
}
UltimateScreenshotCapturer::UltimateScreenshotCapturer()
    : m_gameWindow(nullptr),
    m_d3dDevice(nullptr),
    m_d3dContext(nullptr),
    m_dxgiDuplication(nullptr),
    m_dxgiInitialized(false),
    m_screenWidth(0),
    m_screenHeight(0)
{
    InitializeGDIPlus();
}

UltimateScreenshotCapturer::~UltimateScreenshotCapturer() {
    Shutdown();
    ShutdownGDIPlus();
}

bool UltimateScreenshotCapturer::Initialize() {
    if (m_initialized) return true;

    Log("[LOGEN] Screenshot capturer: looking for DayZ window...");

    // Пытаемся найти окно несколько раз
    for (int attempt = 0; attempt < 5; attempt++) {
        if (attempt > 0) {
            LogFormat("[LOGEN] Window not found, retry %d/5...", attempt + 1);
            Sleep(2000);
        }

        if (!m_gameWindow) {
            m_gameWindow = FindDayZWindow();
        }

        if (m_gameWindow) {
            m_initialized = true;
            Log("[LOGEN] Screenshot capturer initialized: Window found");
            return true;
        }
    }
    Log("[LOGEN] WARNING: DayZ window not found, but trying fallback capture");
    m_initialized = true; 
    return true;         
}
void UltimateScreenshotCapturer::Shutdown() {
    m_initialized = false;

    if (m_overlay) {
        m_overlay->Destroy();
        m_overlay.reset();  
    }
    ReleaseDXGIResources();     
}

// ===================== DXGI DESKTOP DUPLICATION =====================

bool UltimateScreenshotCapturer::InitializeDXGICapture() {
    if (m_dxgiInitialized) return true;
    ReleaseDXGIResources();
    Log("[LOGEN] Initializing DXGI Desktop Duplication...");

    // Create D3D11 device
    D3D_FEATURE_LEVEL featureLevels[] = {
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0
    };

    HRESULT hr = D3D11CreateDevice(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        0,
        featureLevels,
        ARRAYSIZE(featureLevels),
        D3D11_SDK_VERSION,
        &m_d3dDevice,
        nullptr,
        &m_d3dContext
    );

    if (FAILED(hr)) {
        Log("[LOGEN] Failed to create D3D11 device: " + HResultToString(hr));
        return false;
    }

    // Get DXGI device
    IDXGIDevice* dxgiDevice = nullptr;
    hr = m_d3dDevice->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxgiDevice);
    if (FAILED(hr)) {
        Log("[LOGEN] Failed to get DXGI device: " + HResultToString(hr));
        return false;
    }

    // Get DXGI adapter
    IDXGIAdapter* dxgiAdapter = nullptr;
    hr = dxgiDevice->GetAdapter(&dxgiAdapter);
    dxgiDevice->Release();

    if (FAILED(hr)) {
        Log("[LOGEN] Failed to get DXGI adapter: " + HResultToString(hr));
        return false;
    }

    // Get primary output
    IDXGIOutput* dxgiOutput = nullptr;
    hr = dxgiAdapter->EnumOutputs(0, &dxgiOutput);
    dxgiAdapter->Release();

    if (FAILED(hr)) {
        Log("[LOGEN] Failed to get DXGI output: " + HResultToString(hr));
        return false;
    }

    // Get output description
    DXGI_OUTPUT_DESC outputDesc;
    dxgiOutput->GetDesc(&outputDesc);
    m_screenWidth = outputDesc.DesktopCoordinates.right - outputDesc.DesktopCoordinates.left;
    m_screenHeight = outputDesc.DesktopCoordinates.bottom - outputDesc.DesktopCoordinates.top;

    // Get DXGIOutput1 for duplication
    IDXGIOutput1* dxgiOutput1 = nullptr;
    hr = dxgiOutput->QueryInterface(__uuidof(IDXGIOutput1), (void**)&dxgiOutput1);
    dxgiOutput->Release();

    if (FAILED(hr)) {
        Log("[LOGEN] Failed to get DXGIOutput1: " + HResultToString(hr));
        return false;
    }

    // Create desktop duplication (захватывает ВСЁ включая оверлеи)
    hr = dxgiOutput1->DuplicateOutput(m_d3dDevice, &m_dxgiDuplication);
    dxgiOutput1->Release();

    if (FAILED(hr)) {
        Log("[LOGEN] Desktop duplication not available: " + HResultToString(hr));
        // Это не фатально - будем использовать fallback
        return false;
    }

    Log("[LOGEN] DXGI capture initialized: " + std::to_string(m_screenWidth) + "x" + std::to_string(m_screenHeight));

    m_dxgiInitialized = true;
    return true;
}
bool UltimateScreenshotCapturer::CaptureViaDXGI(std::vector<BYTE>& output)
{
    output.clear();
    if (!ShouldCapture()) return false;

    // Если нужно — переинициализируем
    if (!m_dxgiInitialized || !m_dxgiDuplication)
    {
        if (!InitializeDXGICapture()) {
            return false;
        }
    }

    if (!m_dxgiDuplication) {
        Log("[LOGEN] No duplication interface available");
        return false;
    }

    DXGI_OUTDUPL_FRAME_INFO frameInfo{};
    IDXGIResource* desktopResource = nullptr;
    HRESULT hr = E_FAIL;

    const int MAX_ATTEMPTS = 4;

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; ++attempt)
    {
        hr = m_dxgiDuplication->AcquireNextFrame(400, &frameInfo, &desktopResource);

        if (SUCCEEDED(hr))
            break;

        // Всегда освобождаем frame!
        if (m_dxgiDuplication)
            m_dxgiDuplication->ReleaseFrame();

        if (hr == DXGI_ERROR_ACCESS_LOST)
        {
            Log("[LOGEN] ACCESS_LOST detected - resetting resources");
            ReleaseDXGIResources();
            if (!InitializeDXGICapture())
                return false;
            continue;
        }
        else if (hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET)
        {
            Log("[LOGEN] Device removed/reset - critical error");
            ReleaseDXGIResources();
            return false;
        }
        else if (hr == DXGI_ERROR_WAIT_TIMEOUT)
        {
            if (attempt >= 3)
                Log("[LOGEN] Timeout on attempt " + std::to_string(attempt));
        }
        else
        {
            Log("[LOGEN] Unexpected error " + HResultToString(hr) + " on attempt " + std::to_string(attempt));
        }

        if (attempt < MAX_ATTEMPTS)
            Sleep(50 * attempt);
    }

    if (FAILED(hr))
    {
        Log("[LOGEN] All " + std::to_string(MAX_ATTEMPTS) + " attempts failed");
        return false;
    }

    // ==================== Успешный захват ====================
    ID3D11Texture2D* desktopTexture = nullptr;
    hr = desktopResource->QueryInterface(__uuidof(ID3D11Texture2D), (void**)&desktopTexture);
    desktopResource->Release();

    if (FAILED(hr))
    {
        m_dxgiDuplication->ReleaseFrame();
        return false;
    }

    D3D11_TEXTURE2D_DESC desc{};
    desktopTexture->GetDesc(&desc);

    desc.BindFlags = 0;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    desc.Usage = D3D11_USAGE_STAGING;
    desc.MiscFlags = 0;

    ID3D11Texture2D* stagingTexture = nullptr;
    hr = m_d3dDevice->CreateTexture2D(&desc, nullptr, &stagingTexture);
    if (FAILED(hr))
    {
        desktopTexture->Release();
        m_dxgiDuplication->ReleaseFrame();
        return false;
    }

    m_d3dContext->CopyResource(stagingTexture, desktopTexture);
    desktopTexture->Release();

    D3D11_MAPPED_SUBRESOURCE mapped{};
    hr = m_d3dContext->Map(stagingTexture, 0, D3D11_MAP_READ, 0, &mapped);
    if (FAILED(hr))
    {
        stagingTexture->Release();
        m_dxgiDuplication->ReleaseFrame();
        return false;
    }

    int width = desc.Width;
    int height = desc.Height;
    output.resize(static_cast<size_t>(width) * height * 4);

    const BYTE* src = static_cast<const BYTE*>(mapped.pData);
    for (int y = 0; y < height; ++y)
    {
        memcpy(output.data() + y * width * 4,
            src + y * mapped.RowPitch,
            static_cast<size_t>(width) * 4);
    }

    m_d3dContext->Unmap(stagingTexture, 0);
    stagingTexture->Release();
    m_dxgiDuplication->ReleaseFrame();

    Log("[DXGI] Successfully captured " + std::to_string(width) + "x" + std::to_string(height));
    return true;
}
void UltimateScreenshotCapturer::ReleaseDXGIResources()
{
    if (m_dxgiDuplication)
    {
        m_dxgiDuplication->ReleaseFrame();
        m_dxgiDuplication->Release();
        m_dxgiDuplication = nullptr;
    }

    if (m_d3dContext)
    {
        m_d3dContext->Release();
        m_d3dContext = nullptr;
    }

    if (m_d3dDevice)
    {
        m_d3dDevice->Release();
        m_d3dDevice = nullptr;
    }

    m_dxgiInitialized = false;
}
bool UltimateScreenshotCapturer::CaptureCombinedModern(std::vector<BYTE>& output) {
    output.clear();
    if (!ShouldCapture()) {
        return false;
    }

    Log("[LOGEN] Starting modern capture...");

    // Курсор и область прицела
    POINT cursorPos;
    if (!GetCursorPos(&cursorPos)) {
        cursorPos.x = GetSystemMetrics(SM_CXSCREEN) / 2;
        cursorPos.y = GetSystemMetrics(SM_CYSCREEN) / 2;
    }

    const int SIGHT_SIZE = 400;
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    int startX = cursorPos.x - SIGHT_SIZE / 2;
    int startY = cursorPos.y - SIGHT_SIZE / 2;

    if (startX < 0) startX = 0;
    if (startY < 0) startY = 0;
    if (startX + SIGHT_SIZE > screenWidth)  startX = screenWidth - SIGHT_SIZE;
    if (startY + SIGHT_SIZE > screenHeight) startY = screenHeight - SIGHT_SIZE;

    // === DXGI захват ===
    std::vector<BYTE> fullDXGI;
    bool dxgiSuccess = false;

    for (int attempt = 0; attempt < 6; ++attempt)
    {
        if (attempt > 0)
        {
            Log("[LOGEN] Retry attempt " + std::to_string(attempt + 1) + "...");
            std::this_thread::sleep_for(std::chrono::milliseconds(40 * (attempt + 1)));
        }

        if (CaptureViaDXGI(fullDXGI))
        {
            dxgiSuccess = true;
            Log("[LOGEN] Capture successful on attempt " + std::to_string(attempt + 1));
            break;
        }
    }

    if (!dxgiSuccess)
    {
        Log("[LOGEN] All DXGI attempts failed, falling back to legacy");
        ReleaseDXGIResources();
        return CombinedCaptureLegacy(output);
    }

    // Extract sight area from DXGI capture
    std::vector<BYTE> sightArea(SIGHT_SIZE * SIGHT_SIZE * 4);
    ExtractRegion(fullDXGI, screenWidth, screenHeight, sightArea, startX, startY, SIGHT_SIZE);

    // Try legacy capture for comparison (тоже с ретраями)
    std::vector<BYTE> legacyArea;
    bool legacySuccess = false;

    // Try overlay first (с ретраями)
    for (int attempt = 0; attempt < 2; attempt++) {
        if (m_overlay && m_overlay->IsCreated()) {
            if (CaptureViaOverlay(legacyArea)) {
                legacySuccess = true;
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    // If overlay failed, try GDI (с ретраями)
    if (!legacySuccess) {
        for (int attempt = 0; attempt < 2; attempt++) {
            if (CaptureViaGDI(legacyArea)) {
                legacySuccess = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }

    // Create combined image
    const int PART_WIDTH = SIGHT_SIZE;
    const int PART_HEIGHT = SIGHT_SIZE;
    const int TOTAL_WIDTH = PART_WIDTH * (legacySuccess ? 2 : 1);

    output.resize(TOTAL_WIDTH * PART_HEIGHT * 4);

    // Modern capture (left side)
    for (int y = 0; y < PART_HEIGHT; y++) {
        int srcOffset = y * PART_WIDTH * 4;
        int dstOffset = y * TOTAL_WIDTH * 4;
        if (srcOffset < sightArea.size() && dstOffset < output.size()) {
            memcpy(&output[dstOffset], &sightArea[srcOffset], PART_WIDTH * 4);
        }
    }

    // Legacy capture (right side if available)
    if (legacySuccess) {
        for (int y = 0; y < PART_HEIGHT; y++) {
            int srcOffset = y * PART_WIDTH * 4;
            int dstOffset = y * TOTAL_WIDTH * 4 + PART_WIDTH * 4;

            if (srcOffset < legacyArea.size() && dstOffset < output.size()) {
                memcpy(&output[dstOffset], &legacyArea[srcOffset], PART_WIDTH * 4);
            }
        }

        // Detect differences between captures
        DetectOverlayCheats(sightArea, legacyArea);
    }

    // Log overlay attacks if any
    if (m_overlay && m_overlay->IsUnderAttack()) {
        Log("[VEH] WARNING: Modern capture during Z-order attack! Defense: " +  std::to_string(m_overlay->GetDefenseLevel()));
        StartSightImgDetection("[VEH] WARNING: Modern capture during Z-order attack!");
    }

    DetectForeignOverlays();

    return !output.empty();
}
// ===================== Поиск источника оверлея (с поддержкой русского языка) =====================
void UltimateScreenshotCapturer::LogDetailedOverlaySource() {
    struct OverlaySearchData {
        std::vector<std::string> results;
        DWORD ourPid = GetCurrentProcessId();
        HWND ourHwnd = nullptr;
        HWND topWindow = nullptr;
    } searchData;

    // Получаем наше окно
    if (m_overlay && m_overlay->IsCreated()) {
        searchData.ourHwnd = m_overlay->GetWindowHandle();
    }

    // Находим самое верхнее окно (кроме нашего)
    searchData.topWindow = GetTopWindow(nullptr);
    if (searchData.topWindow == searchData.ourHwnd) {
        searchData.topWindow = GetWindow(searchData.topWindow, GW_HWNDNEXT);
    }

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* data = reinterpret_cast<OverlaySearchData*>(lParam);

        if (!IsWindowVisible(hwnd)) return TRUE;

        LONG exStyle = GetWindowLongW(hwnd, GWL_EXSTYLE);
        bool isOverlayStyle = (exStyle & (WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST)) != 0;

        if (!isOverlayStyle && hwnd != data->topWindow) return TRUE;

        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid == data->ourPid) return TRUE;

        WCHAR windowTitle[256] = { 0 };
        WCHAR className[256] = { 0 };
        GetWindowTextW(hwnd, windowTitle, sizeof(windowTitle) / sizeof(WCHAR));
        GetClassNameW(hwnd, className, sizeof(className) / sizeof(WCHAR));

        RECT rect;
        GetWindowRect(hwnd, &rect);
        int width = rect.right - rect.left;
        int height = rect.bottom - rect.top;

        std::stringstream ss;
        ss << "[VEH] OVERLAY SOURCE: ";
        char windowTitleUTF8[512] = { 0 };
        char classNameUTF8[512] = { 0 };

        WideCharToMultiByte(CP_UTF8, 0, windowTitle, -1, windowTitleUTF8, sizeof(windowTitleUTF8), NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, className, -1, classNameUTF8, sizeof(classNameUTF8), NULL, NULL);

        ss << "Title=\"" << windowTitleUTF8 << "\"";
        ss << " | Class=\"" << classNameUTF8 << "\"";
        ss << " | Size=" << width << "x" << height;

        if (hwnd == data->topWindow) {
            ss << " [TOP WINDOW]";
        }
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcess) {
            WCHAR processPathW[MAX_PATH] = { 0 };
            DWORD pathSize = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, processPathW, &pathSize)) {
                // Конвертируем путь в UTF-8 для логирования
                char processPathUTF8[MAX_PATH * 2] = { 0 };
                WideCharToMultiByte(CP_UTF8, 0, processPathW, -1, processPathUTF8, sizeof(processPathUTF8), NULL, NULL);
                ss << " | Path=" << processPathUTF8;
                std::string utf8Path = processPathUTF8;
                std::string hash = CalculateFileSHA256Safe(utf8Path);
                if (!hash.empty() && hash != "failed_to_read_file_or_compute_hash" && hash != "file_not_found") {
                    ss << " | SHA256=" << hash;
                }
            }
            CloseHandle(hProcess);
        }

        data->results.push_back(ss.str());
        return TRUE;
        }, reinterpret_cast<LPARAM>(&searchData));

    if (!searchData.results.empty()) {
        for (const auto& result : searchData.results) {
            Log(result);
            StartSightImgDetection("[VEH] Overlay:" + result);
        }
    }
    else {
        Log("[VEH] No suspicious overlay windows found");
    }
}
void UltimateScreenshotCapturer::DetectOverlayCheats(const std::vector<BYTE>& modernCapture, const std::vector<BYTE>& legacyCapture) {

    if (modernCapture.size() != legacyCapture.size() || modernCapture.empty()) {
        return;
    }

    const int SIZE = 400;
    int differences = 0;
    const int PIXEL_COUNT = SIZE * SIZE;

    // Compare pixel by pixel
    for (int i = 0; i < modernCapture.size(); i += 4) {
        // Skip if alpha channel is 0 (fully transparent)
        if (modernCapture[i + 3] == 0 && legacyCapture[i + 3] == 0) {
            continue;
        }

        // Compare RGB (ignore slight alpha differences)
        if (abs((int)modernCapture[i] - (int)legacyCapture[i]) > 10 ||      // B
            abs((int)modernCapture[i + 1] - (int)legacyCapture[i + 1]) > 10 ||  // G
            abs((int)modernCapture[i + 2] - (int)legacyCapture[i + 2]) > 10) {  // R
            differences++;
        }
    }

    // Calculate difference percentage
    double diffPercent = (double)differences / PIXEL_COUNT;

    // Log if significant difference found
    if (diffPercent > 0.7) {
        LogDetailedOverlaySource();
    }
}

void UltimateScreenshotCapturer::DetectForeignOverlays() {
    struct OverlayInfo {
        HWND hwnd;
        RECT rect;
        std::string className;
    };

    std::vector<OverlayInfo> suspiciousWindows;

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* windows = reinterpret_cast<std::vector<OverlayInfo>*>(lParam);

        if (!IsWindowVisible(hwnd)) return TRUE;

        // Check for layered or transparent windows
        DWORD exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
        bool isLayered = (exStyle & WS_EX_LAYERED) != 0;
        bool isTransparent = (exStyle & WS_EX_TRANSPARENT) != 0;

        if (isLayered || isTransparent) {
            char className[256] = { 0 };
            GetClassNameA(hwnd, className, sizeof(className));

            // Ignore known system windows
            if (strstr(className, "Progman") ||
                strstr(className, "WorkerW") ||
                strstr(className, "Shell_TrayWnd") ||
                strstr(className, "Button") ||
                strstr(className, "Static") ||
                strstr(className, "Toolbar")) {
                return TRUE;
            }

            RECT rect;
            if (GetWindowRect(hwnd, &rect)) {
                int width = rect.right - rect.left;
                int height = rect.bottom - rect.top;

                // Only log windows of reasonable size
                if (width > 50 && height > 50 && width < 5000 && height < 5000) {
                    OverlayInfo info;
                    info.hwnd = hwnd;
                    info.rect = rect;
                    info.className = className;
                    windows->push_back(info);
                }
            }
        }
        return TRUE;
        }, reinterpret_cast<LPARAM>(&suspiciousWindows));

    // Log suspicious windows
    if (!suspiciousWindows.empty()) {
        //Log("[VEH] Found " + std::to_string(suspiciousWindows.size()) + " suspicious overlay windows:");

        for (const auto& info : suspiciousWindows) {
            char title[256] = { 0 };
            GetWindowTextA(info.hwnd, title, sizeof(title));

            //Log("[VEH] overlay Window: " + std::string(title) + " | Class: " + info.className + " | Size: " + std::to_string(info.rect.right - info.rect.left) +  "x" + std::to_string(info.rect.bottom - info.rect.top));
            //StartSightImg3("[VEH] overlay Window: " + std::string(title) + " | Class: " + info.className);
        }
    }
}

// ===================== UPDATED COMBINED CAPTURE =====================

bool UltimateScreenshotCapturer::CombinedCapture(std::vector<BYTE>& output) {
    // FIRST: Try modern DXGI capture (sees everything)
    if (CaptureCombinedModern(output)) {
        return true;
    }

    // SECOND: Fallback to legacy method
    Log("[LOGEN] DXGI capture failed, using legacy method");
    if (CombinedCaptureLegacy(output)) {
        return true;
    }

    return false;
}

void UltimateScreenshotCapturer::DrawRectangle(std::vector<BYTE>& imageData,
    int x, int y, int w, int h,
    BYTE r, BYTE g, BYTE b,
    int thickness, int width, int height) {
    if (imageData.empty()) return;

    // Ограничиваем координаты
    x = max(0, min(x, width - 1));
    y = max(0, min(y, height - 1));
    w = min(w, width - x);
    h = min(h, height - y);

    // Рисуем верхнюю и нижнюю границы
    for (int t = 0; t < thickness; t++) {
        for (int ix = x; ix < x + w; ix++) {
            // Верхняя
            int yTop = y + t;
            if (yTop < height) {
                int idx = (yTop * width + ix) * 4;
                if (idx + 2 < imageData.size()) {
                    imageData[idx] = b;     // Blue
                    imageData[idx + 1] = g; // Green
                    imageData[idx + 2] = r; // Red
                }
            }

            // Нижняя
            int yBottom = y + h - 1 - t;
            if (yBottom >= 0 && yBottom < height) {
                int idx = (yBottom * width + ix) * 4;
                if (idx + 2 < imageData.size()) {
                    imageData[idx] = b;
                    imageData[idx + 1] = g;
                    imageData[idx + 2] = r;
                }
            }
        }

        // Левая и правая границы
        for (int iy = y; iy < y + h; iy++) {
            // Левая
            int xLeft = x + t;
            if (xLeft < width) {
                int idx = (iy * width + xLeft) * 4;
                if (idx + 2 < imageData.size()) {
                    imageData[idx] = b;
                    imageData[idx + 1] = g;
                    imageData[idx + 2] = r;
                }
            }

            // Правая
            int xRight = x + w - 1 - t;
            if (xRight >= 0 && xRight < width) {
                int idx = (iy * width + xRight) * 4;
                if (idx + 2 < imageData.size()) {
                    imageData[idx] = b;
                    imageData[idx + 1] = g;
                    imageData[idx + 2] = r;
                }
            }
        }
    }
}

void UltimateScreenshotCapturer::DrawText(std::vector<BYTE>& imageData,
    int x, int y, const std::string& text,
    BYTE r, BYTE g, BYTE b,
    int width, int height) {

    if (text.empty() || x >= width || y >= height) return;

    // Создаём временный DC
    HDC hdc = CreateCompatibleDC(nullptr);
    if (!hdc) return;

    // Создаём битмап из наших данных
    HBITMAP hbm = CreateBitmap(width, height, 1, 32, imageData.data());
    if (!hbm) {
        DeleteDC(hdc);
        return;
    }

    SelectObject(hdc, hbm);

    // Настройки текста
    SetBkMode(hdc, TRANSPARENT);  // Прозрачный фон
    SetTextColor(hdc, RGB(r, g, b));

    // Рисуем текст
    TextOutA(hdc, x, y, text.c_str(), text.length());

    // Забираем изменения обратно
    GetBitmapBits(hbm, imageData.size(), imageData.data());

    // Чистка
    DeleteObject(hbm);
    DeleteDC(hdc);
}
void UltimateScreenshotCapturer::DrawOverlayOnScreenshot(std::vector<BYTE>& imageData,
    int width, int height) {
    if (!m_overlay || !m_drawOverlayInfo) return;

    const auto& overlays = m_overlay->GetDetectedOverlays();

    int yOffset = 2;

    for (const auto& overlay : overlays) {
        HWND hwnd = overlay.first;
        const std::string& info = overlay.second;

        // Извлекаем имя файла из пути
        std::string fileName = "unknown";
        size_t pathPos = info.find("Path: ");
        if (pathPos != std::string::npos) {
            std::string fullPath = info.substr(pathPos + 6);
            size_t lastSlash = fullPath.find_last_of("\\/");
            if (lastSlash != std::string::npos) {
                fileName = fullPath.substr(lastSlash + 1);
            }
            else {
                fileName = fullPath;
            }
            // Обрезаем слишком длинные имена
            if (fileName.length() > 15) {
                fileName = fileName.substr(0, 12) + "...";
            }
        }

        // Рисуем только имя файла
        DrawText(imageData, 2, yOffset, fileName,
            255, 0, 0, width, height); // Красный для чита
        yOffset += 8;

        // Рамка если в кадре
        RECT rect;
        if (GetWindowRect(hwnd, &rect)) {
            POINT cursorPos;
            GetCursorPos(&cursorPos);

            int sightX = cursorPos.x - width / 2;
            int sightY = cursorPos.y - height / 2;

            int windowX = rect.left - sightX;
            int windowY = rect.top - sightY;
            int windowW = rect.right - rect.left;
            int windowH = rect.bottom - rect.top;

            if (windowX + windowW > 0 && windowX < width &&
                windowY + windowH > 0 && windowY < height) {

                int drawX = max(0, windowX);
                int drawY = max(0, windowY);
                int drawW = min(windowW, width - drawX);
                int drawH = min(windowH, height - drawY);

                DrawRectangle(imageData, drawX, drawY, drawW, drawH,
                    255, 0, 0, 2, width, height);
            }
        }
    }
}

// ===================== YOUR ORIGINAL METHODS (unchanged) =====================

bool UltimateScreenshotCapturer::CombinedCaptureLegacy(std::vector<BYTE>& output) {
    output.clear();

    if (!ShouldCapture()) {
        return false;
    }

    // 1. Get cursor position once
    POINT cursorPos;
    if (!GetCursorPos(&cursorPos)) {
        cursorPos.x = GetSystemMetrics(SM_CXSCREEN) / 2;
        cursorPos.y = GetSystemMetrics(SM_CYSCREEN) / 2;
    }

    const int SIGHT_SIZE = 400;
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    // Adjust position
    int startX = cursorPos.x - SIGHT_SIZE / 2;
    int startY = cursorPos.y - SIGHT_SIZE / 2;

    if (startX < 0) startX = 0;
    if (startY < 0) startY = 0;
    if (startX + SIGHT_SIZE > screenWidth) startX = screenWidth - SIGHT_SIZE;
    if (startY + SIGHT_SIZE > screenHeight) startY = screenHeight - SIGHT_SIZE;

    // 2. Capture full screen
    std::vector<BYTE> fullScreen;
    if (!CaptureFullScreenRaw(fullScreen)) {
        Log("[LOGEN] Failed to capture full screen");
        return false;
    }

    // 3. Extract region
    std::vector<BYTE> sightArea(SIGHT_SIZE * SIGHT_SIZE * 4);
    ExtractRegionFromFullScreen(fullScreen, screenWidth, screenHeight,
        sightArea, startX, startY, SIGHT_SIZE);

    // 4. Create combined image
    const int PART_WIDTH = 400;
    const int PART_HEIGHT = 400;
    const int TOTAL_WIDTH = PART_WIDTH * 3;

    output.resize(TOTAL_WIDTH * PART_HEIGHT * 4);

    for (int y = 0; y < PART_HEIGHT; y++) {
        int srcOffset = y * PART_WIDTH * 4;
        int dstOffset = y * TOTAL_WIDTH * 4;

        // All three parts are the same (for compatibility)
        memcpy(&output[dstOffset], &sightArea[srcOffset], PART_WIDTH * 4);
        memcpy(&output[dstOffset + PART_WIDTH * 4], &sightArea[srcOffset], PART_WIDTH * 4);
        memcpy(&output[dstOffset + PART_WIDTH * 2 * 4], &sightArea[srcOffset], PART_WIDTH * 4);
    }

    // 5. Log overlay status
    if (m_overlay && m_overlay->IsUnderAttack()) {
        Log("[VEH] WARNING: Legacy capture during Z-order attack! Defense: " + std::to_string(m_overlay->GetDefenseLevel()));
        StartSightImgDetection("[VEH] WARNING: Legacy capture during Z-order attack!");
    }

    return !output.empty();
}

bool UltimateScreenshotCapturer::CreateAndSaveScreenshot() {
    if (!m_initialized && !Initialize()) {
        return false;
    }
    if (!ShouldCapture()) {
        return false;
    }
    AntiDetectionMeasures();

    for (int i = 0; i < 2; i++) {
        std::vector<BYTE> sightArea;

        // Используем обновленный CombinedCapture (сначала DXGI, потом legacy)
        if (!CombinedCapture(sightArea)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        std::vector<BYTE> jpgData;
        if (!SaveAsJPG(sightArea, jpgData)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        return SaveToDisk(jpgData);
    }

    return false;
}

bool UltimateScreenshotCapturer::CreateAndSendScreenshot(const std::string& serverIP, int port, const std::string& clientID, const std::string& infouser, const std::wstring& serviceName) {
    if (!m_initialized && !Initialize()) {
        return false;
    }
    if (!ShouldCapture()) {
        return false;
    }
    AntiDetectionMeasures();

    for (int i = 0; i < 2; i++) {
        std::vector<BYTE> sightArea;

        // Используем обновленный CombinedCapture
        if (!CombinedCapture(sightArea)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        std::vector<BYTE> jpgData;
        if (!SaveAsJPG(sightArea, jpgData)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        return SendToServerSimple(jpgData, serverIP, port, clientID, infouser, serviceName);
    }

    return false;
}

// ===================== YOUR EXISTING METHODS =====================

bool UltimateScreenshotCapturer::InitializeOverlay() {
    if (!m_overlay) {
        m_overlay = std::make_unique<InvisibleOverlay>();
    }

    bool success = m_overlay->Create();
    if (success) {
        Log("[LOGEN] Overlay system initialized");

        // ===== НОВЫЙ КОД =====
        // Включаем ядерную защиту
        m_overlay->SetKernelLevelProtection(true);

        // Сканируем скрытые оверлеи
        m_overlay->ScanForHiddenOverlays();
    }
    else {
        Log("[LOGEN] WARNING Overlay initialization failed");
    }

    return success;
}

bool UltimateScreenshotCapturer::CaptureViaOverlay(std::vector<BYTE>& output) {
    if (!ShouldCapture()) {
        return false;
    }

    if (!m_overlay || !m_overlay->IsCreated()) {
        if (!InitializeOverlay()) {
            return false;
        }
    }

    // Проверяем, не атакуют ли оверлей
    if (m_overlay->IsUnderAttack()) {
        Log("[VEH] WARNING: Capturing during Z-order attack!");
        StartSightImgDetection("[VEH] WARNING: Capturing during Z-order attack!");
        HWND hwnd = m_overlay->GetWindowHandle();
        if (hwnd) {
            SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        }
    }

    const int SIGHT_SIZE = 400;

    std::vector<BYTE> fullScreen;
    if (!m_overlay->CaptureThroughOverlay(fullScreen, 0, 0)) {
        return false;
    }

    POINT cursorPos;
    if (!GetCursorPos(&cursorPos)) {
        cursorPos.x = GetSystemMetrics(SM_CXSCREEN) / 2;
        cursorPos.y = GetSystemMetrics(SM_CYSCREEN) / 2;
    }

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    int startX = cursorPos.x - SIGHT_SIZE / 2;
    int startY = cursorPos.y - SIGHT_SIZE / 2;

    if (startX < 0) startX = 0;
    if (startY < 0) startY = 0;
    if (startX + SIGHT_SIZE > screenWidth) startX = screenWidth - SIGHT_SIZE;
    if (startY + SIGHT_SIZE > screenHeight) startY = screenHeight - SIGHT_SIZE;

    output.resize(SIGHT_SIZE * SIGHT_SIZE * 4);

    ExtractRegion(fullScreen, screenWidth, screenHeight, output, startX, startY, SIGHT_SIZE);

    return !output.empty();
}

bool UltimateScreenshotCapturer::CaptureFullScreenRaw(std::vector<BYTE>& output) {
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    HDC hdcScreen = GetDC(nullptr);
    if (!hdcScreen) {
        Log("[LOGEN] GetDC failed");
        return false;
    }

    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    if (!hdcMem) {
        ReleaseDC(nullptr, hdcScreen);
        Log("[LOGEN] CreateCompatibleDC failed");
        return false;
    }

    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
    if (!hBitmap) {
        DeleteDC(hdcMem);
        ReleaseDC(nullptr, hdcScreen);
        Log("[LOGEN] CreateCompatibleBitmap failed");
        return false;
    }

    SelectObject(hdcMem, hBitmap);

    // Используем CAPTUREBLT для захвата layered окон
    BOOL result = BitBlt(hdcMem, 0, 0, screenWidth, screenHeight,
        hdcScreen, 0, 0, SRCCOPY | CAPTUREBLT);

    if (!result) {
        DWORD err = GetLastError();
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(nullptr, hdcScreen);
        Log("[LOGEN] BitBlt failed. Error: " + std::to_string(err));
        return false;
    }

    BITMAPINFOHEADER bi = {};
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = screenWidth;
    bi.biHeight = -screenHeight;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;

    output.resize(screenWidth * screenHeight * 4);

    int getResult = GetDIBits(hdcMem, hBitmap, 0, screenHeight,
        output.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);

    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(nullptr, hdcScreen);

    if (getResult == 0) {
        Log("[LOGEN] GetDIBits failed");
        output.clear();
    }

    return (getResult != 0);
}

void UltimateScreenshotCapturer::ExtractRegionFromFullScreen(const std::vector<BYTE>& source, int sourceWidth, int sourceHeight, std::vector<BYTE>& dest, int startX, int startY, int size) {
    dest.resize(size * size * 4);

    for (int y = 0; y < size; y++) {
        int srcY = startY + y;
        if (srcY >= sourceHeight) continue;

        for (int x = 0; x < size; x++) {
            int srcX = startX + x;
            if (srcX >= sourceWidth) continue;

            int srcIdx = (srcY * sourceWidth + srcX) * 4;
            int dstIdx = (y * size + x) * 4;

            if (srcIdx + 4 <= source.size() && dstIdx + 4 <= dest.size()) {
                dest[dstIdx] = source[srcIdx];     // Blue
                dest[dstIdx + 1] = source[srcIdx + 1]; // Green
                dest[dstIdx + 2] = source[srcIdx + 2]; // Red
                dest[dstIdx + 3] = source[srcIdx + 3]; // Alpha
            }
        }
    }
}

void UltimateScreenshotCapturer::ExtractRegion(const std::vector<BYTE>& source, int sourceWidth, int sourceHeight, std::vector<BYTE>& dest, int startX, int startY, int size) {
    dest.resize(size * size * 4);

    for (int y = 0; y < size; y++) {
        int srcY = startY + y;
        if (srcY >= sourceHeight) break;

        for (int x = 0; x < size; x++) {
            int srcX = startX + x;
            if (srcX >= sourceWidth) break;

            int srcIdx = (srcY * sourceWidth + srcX) * 4;
            int dstIdx = (y * size + x) * 4;

            if (srcIdx + 4 <= source.size() && dstIdx + 4 <= dest.size()) {
                memcpy(&dest[dstIdx], &source[srcIdx], 4);
            }
        }
    }
}

bool UltimateScreenshotCapturer::SendToServerSimple(const std::vector<BYTE>& jpgData, const std::string& serverIP, int port, const std::string& clientID, const std::string& infouser, const std::wstring& serviceName) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    hostent* host = gethostbyname(serverIP.c_str());
    if (!host) {
        closesocket(sock);
        WSACleanup();
        return false;
    }
    addr.sin_addr.s_addr = *((unsigned long*)host->h_addr);

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(sock);
        WSACleanup();
        return false;
    }
    std::string serviceNameA(serviceName.begin(), serviceName.end());
    std::string filename = "CS2," + clientID + ".data," + " " + VerSVG + " " + infouser + " [" + serviceNameA + "]";
    int len = filename.length();
    std::vector<BYTE> header;
    while (len >= 0x80) {
        header.push_back((BYTE)(len | 0x80));
        len >>= 7;
    }
    header.push_back((BYTE)len);
    header.insert(header.end(), filename.begin(), filename.end());
    send(sock, (char*)header.data(), header.size(), 0);

    long long size = jpgData.size();
    send(sock, (char*)&size, sizeof(long long), 0);
    send(sock, (char*)jpgData.data(), jpgData.size(), 0);

    closesocket(sock);
    WSACleanup();
    return true;
}

bool UltimateScreenshotCapturer::CaptureFullScreen(std::vector<BYTE>& output) {
    const int SIGHT_WIDTH = 400;
    const int SIGHT_HEIGHT = 400;

    POINT cursorPos;
    if (!GetCursorPos(&cursorPos)) {
        return false;
    }

    int startX = cursorPos.x - SIGHT_WIDTH / 2;
    int startY = cursorPos.y - SIGHT_HEIGHT / 2;

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    if (startX < 0) startX = 0;
    if (startY < 0) startY = 0;
    if (startX + SIGHT_WIDTH > screenWidth) startX = screenWidth - SIGHT_WIDTH;
    if (startY + SIGHT_HEIGHT > screenHeight) startY = screenHeight - SIGHT_HEIGHT;

    HDC hdcScreen = GetDC(nullptr);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, SIGHT_WIDTH, SIGHT_HEIGHT);

    SelectObject(hdcMem, hBitmap);
    BitBlt(hdcMem, 0, 0, SIGHT_WIDTH, SIGHT_HEIGHT, hdcScreen, startX, startY, SRCCOPY);

    BITMAPINFOHEADER bi{};
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = SIGHT_WIDTH;
    bi.biHeight = -SIGHT_HEIGHT;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;

    output.resize(SIGHT_WIDTH * SIGHT_HEIGHT * 4);

    bool success = (GetDIBits(hdcMem, hBitmap, 0, SIGHT_HEIGHT, output.data(),
        (BITMAPINFO*)&bi, DIB_RGB_COLORS) != 0);

    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(nullptr, hdcScreen);

    return success && !output.empty();
}

bool UltimateScreenshotCapturer::CaptureViaGDI(std::vector<BYTE>& output) {
    const int SIGHT_WIDTH = 400;
    const int SIGHT_HEIGHT = 400;

    POINT cursorPos;
    if (!GetCursorPos(&cursorPos)) {
        return false;
    }

    int startX = cursorPos.x - SIGHT_WIDTH / 2;
    int startY = cursorPos.y - SIGHT_HEIGHT / 2;

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    if (startX < 0) startX = 0;
    if (startY < 0) startY = 0;
    if (startX + SIGHT_WIDTH > screenWidth) startX = screenWidth - SIGHT_WIDTH;
    if (startY + SIGHT_HEIGHT > screenHeight) startY = screenHeight - SIGHT_HEIGHT;

    HDC hdcScreen = GetDC(nullptr);
    if (!hdcScreen) {
        return false;
    }

    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    if (!hdcMem) {
        ReleaseDC(nullptr, hdcScreen);
        return false;
    }

    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, SIGHT_WIDTH, SIGHT_HEIGHT);
    if (!hBitmap) {
        DeleteDC(hdcMem);
        ReleaseDC(nullptr, hdcScreen);
        return false;
    }

    SelectObject(hdcMem, hBitmap);

    BOOL result = BitBlt(hdcMem, 0, 0, SIGHT_WIDTH, SIGHT_HEIGHT,
        hdcScreen, startX, startY, SRCCOPY);

    if (!result) {
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(nullptr, hdcScreen);
        return false;
    }

    BITMAPINFOHEADER bi{};
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = SIGHT_WIDTH;
    bi.biHeight = -SIGHT_HEIGHT;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;

    output.resize(SIGHT_WIDTH * SIGHT_HEIGHT * 4);

    if (GetDIBits(hdcMem, hBitmap, 0, SIGHT_HEIGHT, output.data(),
        (BITMAPINFO*)&bi, DIB_RGB_COLORS) == 0) {
        output.clear();
    }

    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(nullptr, hdcScreen);

    return !output.empty();
}

bool UltimateScreenshotCapturer::SaveAsJPG(const std::vector<BYTE>& imageData, std::vector<BYTE>& jpgOutput) {
    if (imageData.empty()) {
        return false;
    }

    if (!g_gdiplusInitialized) {
        return false;
    }

    // Проверяем размер для современных скриншотов (800x400 или 1200x400)
    size_t width = 0;
    size_t height = 400;

    if (imageData.size() == 800 * 400 * 4) {
        width = 800;  // Современный захват (2 части)
    }
    else if (imageData.size() == 1200 * 400 * 4) {
        width = 1200; // Старый захват (3 части)
    }
    else {
        return false;
    }

    Bitmap bitmap(width, height, width * 4, PixelFormat32bppRGB, (BYTE*)imageData.data());

    if (bitmap.GetLastStatus() != Ok) {
        return false;
    }

    if (bitmap.GetWidth() == 0 || bitmap.GetHeight() == 0) {
        return false;
    }

    CLSID jpgClsid;
    if (GetEncoderClsid(L"image/jpeg", &jpgClsid) == -1) {
        return false;
    }

    EncoderParameters encoderParams;
    encoderParams.Count = 1;
    encoderParams.Parameter[0].Guid = EncoderQuality;
    encoderParams.Parameter[0].Type = EncoderParameterValueTypeLong;
    encoderParams.Parameter[0].NumberOfValues = 1;

    ULONG quality = 70;
    encoderParams.Parameter[0].Value = &quality;

    IStream* stream = nullptr;
    if (CreateStreamOnHGlobal(NULL, TRUE, &stream) != S_OK) {
        return false;
    }

    Status result = bitmap.Save(stream, &jpgClsid, &encoderParams);

    if (result != Ok) {
        stream->Release();
        return false;
    }

    HGLOBAL hGlobal = NULL;
    if (GetHGlobalFromStream(stream, &hGlobal) != S_OK) {
        stream->Release();
        return false;
    }

    BYTE* streamData = (BYTE*)GlobalLock(hGlobal);
    SIZE_T streamSize = GlobalSize(hGlobal);

    if (!streamData || streamSize == 0) {
        GlobalUnlock(hGlobal);
        stream->Release();
        return false;
    }

    jpgOutput.assign(streamData, streamData + streamSize);

    GlobalUnlock(hGlobal);
    stream->Release();

    return true;
}

bool UltimateScreenshotCapturer::SaveToDisk(const std::vector<BYTE>& jpgData) {
    if (jpgData.empty()) {
        return false;
    }

    std::string filePath = GetScreenshotPath();

    DWORD attributes = GetFileAttributesA(filePath.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesA(filePath.c_str(), FILE_ATTRIBUTE_NORMAL);
        DeleteFileA(filePath.c_str());
    }

    std::ofstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    file.write(reinterpret_cast<const char*>(jpgData.data()), jpgData.size());
    file.close();

    SetFileAttributesA(filePath.c_str(), FILE_ATTRIBUTE_HIDDEN);

    return true;
}

int UltimateScreenshotCapturer::GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0;
    UINT size = 0;

    GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;

    ImageCodecInfo* pImageCodecInfo = (ImageCodecInfo*)malloc(size);
    if (pImageCodecInfo == NULL) return -1;

    GetImageEncoders(num, size, pImageCodecInfo);

    for (UINT i = 0; i < num; ++i) {
        if (wcscmp(pImageCodecInfo[i].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[i].Clsid;
            free(pImageCodecInfo);
            return i;
        }
    }

    free(pImageCodecInfo);
    return -1;
}

std::string UltimateScreenshotCapturer::GetScreenshotPath() {
    char localAppDataPath[MAX_PATH];
    std::string screenshotDir;

    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppDataPath))) {
        screenshotDir = std::string(localAppDataPath) + "\\" + Name_Window;
    }

    CreateDirectoryA(screenshotDir.c_str(), nullptr);

    return screenshotDir + "\\DayZ.jpg";
}

void UltimateScreenshotCapturer::AntiDetectionMeasures() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 10);
    std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));

    GetTickCount();
    GetCurrentThreadId();
}

HWND UltimateScreenshotCapturer::FindDayZWindow() {
    HWND hwnd = FindWindowA("DayZ", NULL);
    if (!hwnd && !Name_Window.empty()) {
        hwnd = FindWindowA(NULL, Name_Window.c_str());
    }
    if (hwnd && IsGameWindowValid(hwnd)) {
        return hwnd;
    }
    if (!hwnd) {
        hwnd = FindSpecificDayZWindow();
    }
    if (hwnd && !IsGameWindowValid(hwnd)) {
        hwnd = nullptr;
        Log("[LOGEN] Screenshot FindDayZWindow nullptr -" + std::to_string(SaveScreenshotToDiskCount));
    }
    return hwnd;
}

HWND UltimateScreenshotCapturer::FindSpecificDayZWindow() const {
    struct WindowSearchData {
        HWND result = nullptr;
        DWORD startTime = GetTickCount();
    } searchData;

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* data = reinterpret_cast<WindowSearchData*>(lParam);
        if (GetTickCount() - data->startTime > 1000) {
            return FALSE;
        }
        if (!IsWindowVisible(hwnd) || IsIconic(hwnd)) {
            return TRUE;
        }
        char className[256] = { 0 };
        GetClassNameA(hwnd, className, sizeof(className));
        char windowTitle[256] = { 0 };
        GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));
        bool isLikelyDayZ = false;
        if (strstr(className, "DAYZ") != nullptr) {
            isLikelyDayZ = true;
        }
        else if (strstr(windowTitle, "DayZ") != nullptr ||
            strstr(windowTitle, "DAYZ") != nullptr) {
            isLikelyDayZ = true;
        }
        else if (!Name_Window.empty() &&
            strstr(windowTitle, Name_Window.c_str()) != nullptr) {
            isLikelyDayZ = true;
        }

        if (isLikelyDayZ) {
            RECT rect;
            if (GetWindowRect(hwnd, &rect)) {
                int width = rect.right - rect.left;
                int height = rect.bottom - rect.top;

                if (width > 800 && height > 600) {
                    data->result = hwnd;
                    return FALSE;
                }
            }
        }

        return TRUE;
        }, reinterpret_cast<LPARAM>(&searchData));

    return searchData.result;
}

bool UltimateScreenshotCapturer::IsGameWindowValid(HWND hwnd) const {
    if (!hwnd || !IsWindow(hwnd)) return false;

    char className[256] = { 0 };
    GetClassNameA(hwnd, className, sizeof(className));

    char windowTitle[256] = { 0 };
    GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));

    bool isDayZClass = (strstr(className, "DAYZ") != nullptr);
    bool isDayZTitle = (strstr(windowTitle, "DayZ") != nullptr ||
        strstr(windowTitle, "DAYZ") != nullptr);

    if (!isDayZClass && !isDayZTitle) {
        return false;
    }

    if (!IsWindowVisible(hwnd)) return false;

    if (IsIconic(hwnd)) return false;

    RECT rect;
    if (!GetWindowRect(hwnd, &rect)) return false;

    int width = rect.right - rect.left;
    int height = rect.bottom - rect.top;

    if (width < 800 || height < 600) {
        return false;
    }

    return true;
}

bool UltimateScreenshotCapturer::IsGameActive() const {
    if (!m_gameWindow || !IsWindow(m_gameWindow)) {
        return false;
    }
    HWND foregroundWindow = GetForegroundWindow();
    if (foregroundWindow != m_gameWindow) {
        return false;
    }
    if (IsIconic(m_gameWindow)) {
        return false;
    }
    if (!IsWindowVisible(m_gameWindow)) {
        return false;
    }
    return true;
}

bool UltimateScreenshotCapturer::ShouldCapture() const {
    if (!m_initialized || !m_gameWindow) {
        return false;
    }

    if (!IsGameActive()) {
        return false;
    }

    if (!IsGameWindowValid(m_gameWindow)) {
        return false;
    }

    return true;
}

RECT UltimateScreenshotCapturer::GetGameWindowRect() {
    RECT rect = { 0, 0, 0, 0 };
    if (m_gameWindow && IsGameWindowValid(m_gameWindow)) {
        GetWindowRect(m_gameWindow, &rect);
    }
    else {
        rect.right = GetSystemMetrics(SM_CXSCREEN);
        rect.bottom = GetSystemMetrics(SM_CYSCREEN);
    }
    return rect;
}

POINT UltimateScreenshotCapturer::GetGameSightCenter() {
    POINT cursorPos;
    if (GetCursorPos(&cursorPos)) {
        RECT gameRect;
        if (m_gameWindow && GetWindowRect(m_gameWindow, &gameRect)) {
            if (cursorPos.x >= gameRect.left && cursorPos.x <= gameRect.right &&
                cursorPos.y >= gameRect.top && cursorPos.y <= gameRect.bottom) {
                return cursorPos;
            }
        }
        return cursorPos;
    }

    RECT windowRect = GetGameWindowRect();
    cursorPos.x = windowRect.left + (windowRect.right - windowRect.left) / 2;
    cursorPos.y = windowRect.top + (windowRect.bottom - windowRect.top) / 2;
    return cursorPos;
}

bool UltimateScreenshotCapturer::RestartWindowsService(LPCWSTR serviceName) {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE service = OpenService(scm, serviceName,
        SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS status;
    ControlService(service, SERVICE_CONTROL_STOP, &status);
    Sleep(1000);

    StartService(service, 0, NULL);

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

bool UltimateScreenshotCapturer::IsOverlayUnderAttack() const {
    return m_overlay && m_overlay->IsUnderAttack();
}