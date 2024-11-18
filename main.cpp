#include "UI/UI.h"
#include "yara/yara.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if (!UI::Initialize())
        return 1;

    initializeGenericRules();

    while (!UI::ShouldClose()) {
        UI::BeginFrame();
        UI::Render();
        UI::EndFrame();
    }

    UI::Shutdown();
    return 0;
}