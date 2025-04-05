#define NOMINMAX
#include "UI.h"
#include "font.h"
#include "../BAM/BAM.h"
#include "../yara/yara.h"
#include <time.h>
#include <thread>
#include <shellapi.h>
#include <string>
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <algorithm>
#include <d3d9.h>
#include <windows.h>
#include <tchar.h>
#include <ImGui/imgui_internal.h>

struct IconData {
    LPDIRECT3DTEXTURE9 Texture = nullptr;
    int Width = 0;
    int Height = 0;
    bool IsLoaded = false;
};

std::string ExtractBasePathFromADS(const std::string& fullPath) {
    size_t adsPos = fullPath.find(':');
    if (adsPos != std::string::npos && adsPos < 3) {
        adsPos = fullPath.find(':', adsPos + 1);
    }
    if (adsPos != std::string::npos) {
        return fullPath.substr(0, adsPos);
    }
    return fullPath;
}

bool LoadFileIcon(const std::string& filePath, IconData* outIconData, LPDIRECT3DDEVICE9 device) {
    if (filePath.empty() || device == nullptr)
        return false;
    std::string basePath = ExtractBasePathFromADS(filePath);
    DWORD fileAttributes = GetFileAttributesA(basePath.c_str());
    bool fileExists = (fileAttributes != INVALID_FILE_ATTRIBUTES);
    SHFILEINFO shfi = { 0 };
    DWORD dwFlags = SHGFI_ICON | SHGFI_LARGEICON;
    if (!fileExists) {
        dwFlags |= SHGFI_USEFILEATTRIBUTES;
    }
    DWORD_PTR result = SHGetFileInfoA(basePath.c_str(), fileExists ? 0 : FILE_ATTRIBUTE_NORMAL, &shfi, sizeof(SHFILEINFO), dwFlags);
    if (result == 0 || shfi.hIcon == NULL)
        return false;
    ICONINFO iconInfo;
    if (!GetIconInfo(shfi.hIcon, &iconInfo)) {
        DestroyIcon(shfi.hIcon);
        return false;
    }
    BITMAP bm;
    if (!GetObject(iconInfo.hbmColor, sizeof(BITMAP), &bm)) {
        DeleteObject(iconInfo.hbmMask);
        DeleteObject(iconInfo.hbmColor);
        DestroyIcon(shfi.hIcon);
        return false;
    }
    HDC hDC = CreateCompatibleDC(NULL);
    HBITMAP oldBitmap = (HBITMAP)SelectObject(hDC, iconInfo.hbmColor);
    int width = bm.bmWidth;
    int height = bm.bmHeight;
    LPDIRECT3DTEXTURE9 texture = nullptr;
    HRESULT hr = device->CreateTexture(width, height, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED, &texture, NULL);
    if (FAILED(hr)) {
        SelectObject(hDC, oldBitmap);
        DeleteDC(hDC);
        DeleteObject(iconInfo.hbmMask);
        DeleteObject(iconInfo.hbmColor);
        DestroyIcon(shfi.hIcon);
        return false;
    }
    D3DLOCKED_RECT lockedRect;
    texture->LockRect(0, &lockedRect, NULL, 0);
    BITMAPINFO bmi;
    ZeroMemory(&bmi, sizeof(BITMAPINFO));
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -height;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    GetDIBits(hDC, iconInfo.hbmColor, 0, height, lockedRect.pBits, &bmi, DIB_RGB_COLORS);
    texture->UnlockRect(0);
    texture->SetAutoGenFilterType(D3DTEXF_LINEAR);
    outIconData->Texture = texture;
    outIconData->Width = width;
    outIconData->Height = height;
    outIconData->IsLoaded = true;
    SelectObject(hDC, oldBitmap);
    DeleteDC(hDC);
    DeleteObject(iconInfo.hbmMask);
    DeleteObject(iconInfo.hbmColor);
    DestroyIcon(shfi.hIcon);
    return true;
}

void ProcessEntries(std::atomic<bool>& isProcessing, std::vector<BAMEntry>& entries) {
    BAMParser parser;
    entries = parser.GetEntries();
    isProcessing = false;
}

LPDIRECT3D9 UI::g_pD3D = nullptr;
LPDIRECT3DDEVICE9 UI::g_pd3dDevice = nullptr;
D3DPRESENT_PARAMETERS UI::g_d3dpp = {};
HWND UI::hwnd = nullptr;
WNDCLASSEX UI::wc = {};

bool UI::CreateDeviceD3D() {
    g_pD3D = Direct3DCreate9(D3D_SDK_VERSION);
    if (g_pD3D == nullptr)
        return false;
    ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
    g_d3dpp.Windowed = TRUE;
    g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
    g_d3dpp.EnableAutoDepthStencil = TRUE;
    g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;
    if (g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &g_d3dpp, &g_pd3dDevice) < 0)
        return false;
    return true;
}

void UI::CleanupDeviceD3D() {
    if (g_pd3dDevice) {
        g_pd3dDevice->Release();
        g_pd3dDevice = nullptr;
    }
    if (g_pD3D) {
        g_pD3D->Release();
        g_pD3D = nullptr;
    }
}

void UI::ResetDevice() {
    ImGui_ImplDX9_InvalidateDeviceObjects();
    HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
    if (hr == D3DERR_INVALIDCALL)
        IM_ASSERT(0);
    ImGui_ImplDX9_CreateDeviceObjects();
}

LRESULT WINAPI UI::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;
    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED) {
            g_d3dpp.BackBufferWidth = LOWORD(lParam);
            g_d3dpp.BackBufferHeight = HIWORD(lParam);
            ResetDevice();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
            return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

bool UI::Initialize() {
    wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, _T("Process Parser"), nullptr };
    RegisterClassEx(&wc);
    hwnd = CreateWindow(wc.lpszClassName, _T("BAM parser"), WS_OVERLAPPEDWINDOW, 100, 100, 800, 600, nullptr, nullptr, wc.hInstance, nullptr);
    if (!CreateDeviceD3D()) {
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return false;
    }
    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    ImGui::StyleColorsDark();
    ImFontConfig CustomFont;
    CustomFont.FontDataOwnedByAtlas = false;
    io.Fonts->AddFontFromMemoryTTF((void*)Custom.data(), (int)Custom.size(), 17.5f, &CustomFont);
    io.Fonts->AddFontDefault();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);
    return true;
}

bool UI::ShouldClose() {
    MSG msg;
    while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
        if (msg.message == WM_QUIT)
            return true;
    }
    return false;
}

void UI::BeginFrame() {
    ImGui_ImplDX9_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
    ImGui::Begin("##MainWindow", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);
    ImGui::GetIO().IniFilename = nullptr;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(5, 5));
}

void UI::Render() {
    static std::vector<BAMEntry> entries;
    static std::atomic<bool> isProcessing(false);
    static std::thread processingThread;
    static bool showNotSignedOnly = false;
    static bool showFlaggedOnly = false;
    static bool showOnlyInstance = false;
    static bool showDetailsPopup = false;
    static BAMEntry selectedEntry;
    static std::unordered_map<std::string, IconData> iconCache;
    static char searchBuffer[256] = "";

    auto parseTime = [](const std::wstring& timeStr) -> std::chrono::system_clock::time_point {
        std::tm tm = {};
        std::string narrowTimeStr(timeStr.begin(), timeStr.end());
        std::istringstream ss(narrowTimeStr);
        ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
        return std::chrono::system_clock::from_time_t(std::mktime(&tm));
        };

    auto sortEntries = [&parseTime](std::vector<BAMEntry>& entriesToSort) {
        std::sort(entriesToSort.begin(), entriesToSort.end(), [&parseTime](const BAMEntry& a, const BAMEntry& b) {
            return parseTime(a.executionTime) > parseTime(b.executionTime);
            });
        };

    if (!isProcessing && entries.empty()) {
        isProcessing = true;
        if (processingThread.joinable()) {
            processingThread.join();
        }
        processingThread = std::thread([sortEntries, isProcessing_ptr = &isProcessing, entries_ptr = &entries]() {
            std::vector<BAMEntry> localEntries;
            ProcessEntries(*isProcessing_ptr, localEntries);
            sortEntries(localEntries);
            *entries_ptr = std::move(localEntries);
            *isProcessing_ptr = false;
            });
    }

    if (isProcessing) {
        const float windowCenterX = (ImGui::GetWindowSize().x - ImGui::CalcTextSize("Processing BAM entries...").x) * 0.5f;
        const float windowCenterY = (ImGui::GetWindowSize().y - ImGui::CalcTextSize("Processing BAM entries...").y) * 0.5f;
        ImGui::SetCursorPos(ImVec2(windowCenterX, windowCenterY));
        ImGui::Text("Processing BAM entries...");
        return;
    }

    if (showDetailsPopup) {
        ImGui::PushStyleColor(ImGuiCol_ModalWindowDimBg, ImVec4(0.0f, 0.0f, 0.0f, 0.6f));
        ImGui::OpenPopup("Replace Details Modal");
        ImVec2 center = ImGui::GetMainViewport()->GetCenter();
        ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
        ImGui::SetNextWindowSize(ImVec2(800, 600));
        if (ImGui::BeginPopupModal("Replace Details Modal", &showDetailsPopup, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings)) {
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 20));
            ImGui::Text("Replace Information:");
            ImGui::Spacing();
            ImGui::Spacing();
            for (auto it = selectedEntry.replace_results.rbegin(); it != selectedEntry.replace_results.rend(); ++it) {
                const auto& replace = *it;
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));
                ImGui::Text("Type:");
                ImGui::SameLine();
                ImGui::TextWrapped("%s", replace.replaceType.c_str());
                ImGui::Spacing();
                ImGui::Text("Details:");
                ImGui::SameLine();
                ImGui::TextWrapped("%s", replace.details.c_str());
                ImGui::PopStyleColor();
                ImGui::Separator();
                ImGui::Spacing();
            }
            ImGui::PopStyleVar();
            ImGui::EndPopup();
        }
        ImGui::PopStyleColor();
    }

    if (ImGui::Button("Parse again", ImVec2(100, 30))) {
        entries.clear();
        isProcessing = true;
        if (processingThread.joinable()) {
            processingThread.join();
        }
        processingThread = std::thread([sortEntries, isProcessing_ptr = &isProcessing, entries_ptr = &entries]() {
            std::vector<BAMEntry> localEntries;
            ProcessEntries(*isProcessing_ptr, localEntries);
            sortEntries(localEntries);
            *entries_ptr = std::move(localEntries);
            *isProcessing_ptr = false;
            });
        return;
    }
    ImGui::Checkbox("Not Signed Only", &showNotSignedOnly);
    ImGui::SameLine();
    ImGui::Checkbox("Flagged Only", &showFlaggedOnly);
    ImGui::SameLine();
    ImGui::Checkbox("In Instance Only", &showOnlyInstance);

    float searchWidth = 450.0f;
    float padding = 25.0f;       
    ImGui::SameLine(ImGui::GetWindowWidth() - searchWidth - padding - ImGui::CalcTextSize("Search").x);
    ImGui::InputTextEx("Search", NULL, searchBuffer, (int)IM_ARRAYSIZE(searchBuffer), ImVec2(searchWidth, 0), 0, NULL, NULL);

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();


    if (entries.empty()) {
        ImGui::Text("No BAM entries found.");
        return;
    }

    float pathMaxWidth = ImGui::CalcTextSize("Filepath").x;
    float timeMaxWidth = ImGui::CalcTextSize("Last Execution").x;
    float signatureMaxWidth = ImGui::CalcTextSize("Signature").x;
    float rulesMaxWidth = ImGui::CalcTextSize("Rules").x;
    for (const auto& entry : entries) {
        std::string path(entry.path.begin(), entry.path.end());
        std::string time(entry.executionTime.begin(), entry.executionTime.end());
        std::string signature(entry.signatureStatus.begin(), entry.signatureStatus.end());
        timeMaxWidth = std::max(timeMaxWidth, ImGui::CalcTextSize(time.c_str()).x);
        pathMaxWidth = std::max(pathMaxWidth, ImGui::CalcTextSize(path.c_str()).x);
        signatureMaxWidth = std::max(signatureMaxWidth, ImGui::CalcTextSize(signature.c_str()).x);
        std::string rules;
        for (const auto& rule : entry.matched_rules) {
            rules += rule + ", ";
        }
        if (!rules.empty()) {
            rules = rules.substr(0, rules.length() - 2);
            rulesMaxWidth = std::max(rulesMaxWidth, ImGui::CalcTextSize(rules.c_str()).x);
        }
    }
    timeMaxWidth += 30;
    pathMaxWidth += 30;
    signatureMaxWidth += 30;
    rulesMaxWidth += 30;

    auto SelectableText = [&](const char* label, const char* text_to_copy, bool& clicked) {
        ImGui::PushID(label);
        bool selected = false;
        ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0.2f, 0.2f, 0.2f, 0.5f));
        ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(0.3f, 0.3f, 0.3f, 0.5f));
        ImGui::PushStyleColor(ImGuiCol_HeaderActive, ImVec4(0.4f, 0.4f, 0.4f, 0.5f));
        if (ImGui::Selectable(label, &selected, ImGuiSelectableFlags_None)) {
            if (ImGui::GetIO().KeyCtrl) {
                ImGui::SetClipboardText(text_to_copy);
                clicked = true;
            }
            else {
                clicked = true;
            }
        }
        ImGui::PopStyleColor(3);
        ImGui::PopID();
        };

    auto toLower = [](const std::string& s) -> std::string {
        std::string lower = s;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });
        return lower;
        };

    if (ImGui::BeginTable("BAMTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable)) {
        ImGui::TableSetupColumn("Last Execution", ImGuiTableColumnFlags_None, timeMaxWidth);
        ImGui::TableSetupColumn("Filepath", ImGuiTableColumnFlags_None, pathMaxWidth);
        ImGui::TableSetupColumn("Signature", ImGuiTableColumnFlags_None, signatureMaxWidth);
        ImGui::TableSetupColumn("Rules", ImGuiTableColumnFlags_None, rulesMaxWidth);
        ImGui::TableHeadersRow();
        for (const auto& entry : entries) {
            bool shouldShow = true;
            std::string signatureStr(entry.signatureStatus.begin(), entry.signatureStatus.end());
            if (showNotSignedOnly && signatureStr == "Signed") {
                shouldShow = false;
            }
            if (showFlaggedOnly && entry.matched_rules.empty()) {
                shouldShow = false;
            }
            if (showOnlyInstance && !entry.isInCurrentInstance) {
                shouldShow = false;
            }
            if (!shouldShow)
                continue;

            std::string searchQuery(searchBuffer);
            if (!searchQuery.empty()) {
                std::string lowerSearch = toLower(searchQuery);
                std::string timeStr(entry.executionTime.begin(), entry.executionTime.end());
                std::string pathStr(entry.path.begin(), entry.path.end());
                std::string lowerTime = toLower(timeStr);
                std::string lowerPath = toLower(pathStr);
                std::string lowerSignature = toLower(signatureStr);
                std::string rules;
                for (const auto& rule : entry.matched_rules) {
                    rules += rule + ", ";
                }
                if (!rules.empty()) {
                    rules = rules.substr(0, rules.length() - 2);
                }
                std::string lowerRules = toLower(rules);
                if (lowerTime.find(lowerSearch) == std::string::npos &&
                    lowerPath.find(lowerSearch) == std::string::npos &&
                    lowerSignature.find(lowerSearch) == std::string::npos &&
                    lowerRules.find(lowerSearch) == std::string::npos) {
                    continue;
                }
            }

            std::string timeStr(entry.executionTime.begin(), entry.executionTime.end());
            std::string pathStr(entry.path.begin(), entry.path.end());
            ImGui::TableNextRow();
            bool clicked = false;
            ImGui::TableNextColumn();
            SelectableText(timeStr.c_str(), timeStr.c_str(), clicked);
            ImGui::TableNextColumn();

            IconData icon;
            bool hasIcon = false;
            auto it = iconCache.find(pathStr);
            if (it == iconCache.end()) {
                IconData loadedIcon;
                if (LoadFileIcon(pathStr, &loadedIcon, g_pd3dDevice)) {
                    iconCache[pathStr] = loadedIcon;
                    icon = loadedIcon;
                    hasIcon = true;
                }
            }
            else {
                icon = it->second;
                hasIcon = icon.IsLoaded;
            }
            if (hasIcon) {
                ImGui::Image((void*)icon.Texture, ImVec2((float)icon.Width * 0.5f, (float)icon.Height * 0.5f));
                ImGui::SameLine();
            }
            if (!entry.replace_results.empty()) {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));
            }
            SelectableText(pathStr.c_str(), pathStr.c_str(), clicked);
            if (!entry.replace_results.empty()) {
                ImGui::PopStyleColor();
            }
            if (clicked && !ImGui::GetIO().KeyCtrl && !entry.replace_results.empty()) {
                selectedEntry = entry;
                showDetailsPopup = true;
            }
            ImGui::TableNextColumn();
            if (signatureStr == "Signed") {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 1.0f, 0.0f, 1.0f));
            }
            else {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.9f, 0.2f, 0.2f, 1.0f));
            }
            SelectableText(signatureStr.c_str(), signatureStr.c_str(), clicked);
            ImGui::PopStyleColor();
            ImGui::TableNextColumn();
            if (!entry.matched_rules.empty()) {
                std::string rules;
                for (size_t i = 0; i < entry.matched_rules.size(); i++) {
                    rules += entry.matched_rules[i];
                    if (i < entry.matched_rules.size() - 1) {
                        rules += ", ";
                    }
                }
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));
                SelectableText(rules.c_str(), rules.c_str(), clicked);
                ImGui::PopStyleColor();
            }
            else {
                SelectableText("-", "-", clicked);
            }
        }
        ImGui::EndTable();
    }
}


void UI::EndFrame() {
    ImGui::EndFrame();
    g_pd3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
    g_pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
    g_pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);
    D3DCOLOR clear_col_dx = D3DCOLOR_RGBA(0, 0, 0, 255);
    g_pd3dDevice->Clear(0, nullptr, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, clear_col_dx, 1.0f, 0);
    if (g_pd3dDevice->BeginScene() >= 0) {
        ImGui::Render();
        ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
        g_pd3dDevice->EndScene();
    }
    HRESULT result = g_pd3dDevice->Present(nullptr, nullptr, nullptr, nullptr);
    if (result == D3DERR_DEVICELOST && g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET)
        ResetDevice();
}

void UI::Shutdown() {
    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);
}
