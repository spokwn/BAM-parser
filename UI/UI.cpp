#define NOMINMAX
#include "UI.h"
#include "font.h"
#include "../BAM/BAM.h"
#include <time.h>
#include <thread>
#include "../yara/yara.h"

LPDIRECT3D9 UI::g_pD3D = nullptr;
LPDIRECT3DDEVICE9 UI::g_pd3dDevice = nullptr;
D3DPRESENT_PARAMETERS UI::g_d3dpp = {};
HWND UI::hwnd = nullptr;
WNDCLASSEX UI::wc = {};

bool UI::CreateDeviceD3D() {
    g_pD3D = Direct3DCreate9(D3D_SDK_VERSION);
    if (g_pD3D == nullptr) return false;

    ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
    g_d3dpp.Windowed = TRUE;
    g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
    g_d3dpp.EnableAutoDepthStencil = TRUE;
    g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;

    if (g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd,
        D3DCREATE_HARDWARE_VERTEXPROCESSING, &g_d3dpp, &g_pd3dDevice) < 0)
        return false;

    return true;
}

void UI::CleanupDeviceD3D() {
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
    if (g_pD3D) { g_pD3D->Release(); g_pD3D = nullptr; }
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
    ImGuiIO& io = ImGui::GetIO(); (void)io;
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
    ImGui::Begin("##MainWindow", nullptr,
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoCollapse);

    ImGui::GetIO().IniFilename = nullptr;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(5, 5));
}

void ProcessEntries(std::atomic<bool>& isProcessing, std::vector<BAMEntry>& entries) {
    BAMParser parser;
    entries = parser.GetEntries();
    isProcessing = false;
}

void UI::Render() {
    static std::vector<BAMEntry> entries;
    static std::atomic<bool> isProcessing(false);
    static std::thread processingThread;
    static bool showNotSignedOnly = false;
    static bool showFlaggedOnly = false;
    static bool showOnlyInstance = false;

    auto parseTime = [](const std::wstring& timeStr) -> std::chrono::system_clock::time_point {
        std::tm tm = {};
        std::string narrowTimeStr(timeStr.begin(), timeStr.end());
        std::istringstream ss(narrowTimeStr);
        ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
        return std::chrono::system_clock::from_time_t(std::mktime(&tm));
        };

    auto sortEntries = [&parseTime](std::vector<BAMEntry>& entriesToSort) {
        std::sort(entriesToSort.begin(), entriesToSort.end(),
            [&parseTime](const BAMEntry& a, const BAMEntry& b) {
                return parseTime(a.executionTime) > parseTime(b.executionTime);
            });
        };

    if (!isProcessing && entries.empty()) {
        isProcessing = true;
        if (processingThread.joinable()) {
            processingThread.join();
        }
        processingThread = std::thread([sortEntries] {
            std::vector<BAMEntry> localEntries;
            ProcessEntries(isProcessing, localEntries);
            sortEntries(localEntries);
            entries = std::move(localEntries);
            isProcessing = false;
            });
    }

    if (isProcessing) {
        const float windowCenterX = (ImGui::GetWindowSize().x - ImGui::CalcTextSize("Processing BAM entries...").x) * 0.5f;
        const float windowCenterY = (ImGui::GetWindowSize().y - ImGui::CalcTextSize("Processing BAM entries...").y) * 0.5f;
        ImGui::SetCursorPos(ImVec2(windowCenterX, windowCenterY));
        ImGui::Text("Processing BAM entries...");
        return;
    }

    if (ImGui::Button("Parse again", ImVec2(100, 30))) {
        entries.clear();
        isProcessing = true;
        if (processingThread.joinable()) {
            processingThread.join();
        }
        processingThread = std::thread([sortEntries] {
            std::vector<BAMEntry> localEntries;
            ProcessEntries(isProcessing, localEntries);
            sortEntries(localEntries);
            entries = std::move(localEntries);
            isProcessing = false;
            });
        return;
    }

    ImGui::SameLine();
    ImGui::Checkbox("Not Signed Only", &showNotSignedOnly);
    ImGui::SameLine();
    ImGui::Checkbox("Flagged Only", &showFlaggedOnly);
    ImGui::SameLine();
    ImGui::Checkbox("In Instance Only", &showOnlyInstance);

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

    ImGui::Columns(4, "BAMColumns", true);
    ImGui::SetColumnWidth(0, timeMaxWidth);
    ImGui::SetColumnWidth(1, pathMaxWidth);
    ImGui::SetColumnWidth(2, signatureMaxWidth);
    ImGui::SetColumnWidth(3, rulesMaxWidth);

    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetColorU32(ImVec4(1.0f, 1.0f, 1.0f, 1.0f)));
    ImGui::Text("Last Execution"); ImGui::NextColumn();
    ImGui::Text("Filepath"); ImGui::NextColumn();
    ImGui::Text("Signature"); ImGui::NextColumn();
    ImGui::Text("Rules"); ImGui::NextColumn();
    ImGui::PopStyleColor();

    ImGui::Separator();

    for (const auto& entry : entries) {
        bool shouldShow = true;

        std::string signature(entry.signatureStatus.begin(), entry.signatureStatus.end());
        if (showNotSignedOnly && signature == "Signed") {
            shouldShow = false;
        }

        if (showFlaggedOnly && entry.matched_rules.empty()) {
            shouldShow = false;
        }
        if (showOnlyInstance && !entry.isInCurrentInstance) {
            shouldShow = false;
        }
            
        if (shouldShow) {
            std::string time(entry.executionTime.begin(), entry.executionTime.end());
            std::string path(entry.path.begin(), entry.path.end());

            ImGui::Text("%s", time.c_str());
            ImGui::NextColumn();

            ImGui::Text("%s", path.c_str());
            ImGui::NextColumn();

            if (signature == "Signed") {
                ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetColorU32(ImVec4(0.0f, 1.0f, 0.0f, 1.0f)));
            }
            else {
                ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetColorU32(ImVec4(0.9f, 0.2f, 0.2f, 1.0f)));
            }
            ImGui::Text("%s", signature.c_str());
            ImGui::PopStyleColor();
            ImGui::NextColumn();

            if (!entry.matched_rules.empty()) {
                std::string rules;
                for (size_t i = 0; i < entry.matched_rules.size(); i++) {
                    rules += entry.matched_rules[i];
                    if (i < entry.matched_rules.size() - 1) {
                        rules += ", ";
                    }
                }
                ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetColorU32(ImVec4(1.0f, 0.0f, 0.0f, 1.0f)));
                ImGui::Text("%s", rules.c_str());
                ImGui::PopStyleColor();
            }
            else {
                ImGui::Text("-");
            }
            ImGui::NextColumn();
        }
    }

    ImGui::Columns(1);
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