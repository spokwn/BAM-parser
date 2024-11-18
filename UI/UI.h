#pragma once
#include "../include.h"

class UI {
private:
    static LPDIRECT3D9 g_pD3D;
    static LPDIRECT3DDEVICE9 g_pd3dDevice;
    static D3DPRESENT_PARAMETERS g_d3dpp;
    static HWND hwnd;
    static WNDCLASSEX wc;

    static bool CreateDeviceD3D();
    static void CleanupDeviceD3D();
    static void ResetDevice();
    static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

public:
    static bool Initialize();
    static void Render();
    static void Shutdown();
    static bool ShouldClose();
    static void BeginFrame();
    static void EndFrame();
};

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);