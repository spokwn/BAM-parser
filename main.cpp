#include <iostream>
#include <thread>
#include <exception>
#include <atomic>
#include <windows.h>
#include <tchar.h>
#include "UI/UI.h"
#include "yara/yara.h"

#define DEBUG_MODE 0 // this is corresponding to the BAMParserDebug.exe or normal BAMParser.exe, some people's crash when opening the programm so this most likely will help me figure out why

#if DEBUG_MODE

static FILE* ConsoleFilePointer = nullptr;
static std::atomic<bool> uiRunning{ true };

void AllocateConsole()
{

    if (GetConsoleWindow()) {
        return;
    }
    if (!AllocConsole()) {
        return;
    }

    const HWND ConsoleHandle = GetConsoleWindow();
    constexpr RECT ConsoleBounds{ 800, 650 };
    RECT WindowRect{};
    SetConsoleTitle(_T("debug"));
    GetWindowRect(ConsoleHandle, &WindowRect);
    MoveWindow(
        ConsoleHandle,
        WindowRect.left, WindowRect.top,
        ConsoleBounds.left, ConsoleBounds.top,
        TRUE
    );
    SetWindowLong(ConsoleHandle, GWL_STYLE, GetWindowLong(ConsoleHandle, GWL_STYLE) | WS_BORDER);
    SetWindowLong(ConsoleHandle, GWL_EXSTYLE, GetWindowLong(ConsoleHandle, GWL_EXSTYLE) | WS_EX_LAYERED);
    SetLayeredWindowAttributes(ConsoleHandle, 0, 230, 2);

    try {
        freopen_s(&ConsoleFilePointer, "CONOUT$", "w", stdout);
    }
    catch (const std::exception& ex) {
        std::cerr << "Caught exception while freopen stdout: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Caught unknown exception while freopen stdout." << std::endl;
    }

    try {
        freopen_s(&ConsoleFilePointer, "CONOUT$", "w", stderr);
    }
    catch (const std::exception& ex) {
        std::cerr << "Caught exception while freopen stderr: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Caught unknown exception while freopen stderr." << std::endl;
    }

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

    std::cout << "Debug console initialized.\n";
}

void ConsoleThread()
{
    AllocateConsole();

    while (uiRunning.load())
    {
        Sleep(100);
    }

    std::cout << "UI has stopped. Press Enter to exit application..." << std::endl;
    std::cin.get();
}

void RunUI()
{
    try {
        if (!UI::Initialize()) {
            std::cerr << "UI::Initialize() returned false. Aborting UI.\n";
            return;
        }

        initializeGenericRules();

        while (!UI::ShouldClose()) {
            try {
                UI::BeginFrame();
                UI::Render();
                UI::EndFrame();
            }
            catch (const std::exception& e) {
                std::cerr << "UI Render Error: " << e.what() << std::endl;
                break;
            }
            catch (...) {
                std::cerr << "Unknown UI Render Error occurred." << std::endl;
                break;
            }
        }

        UI::Shutdown();
        std::cout << "UI shut down successfully.\n";
    }
    catch (const std::exception& e) {
        std::cerr << "UI Critical Error (uncaught exception): " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "UI Critical Unknown Error occurred.\n";
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{

    std::jthread consoleThread(ConsoleThread);

    Sleep(500);

    std::jthread uiThread(RunUI);

    uiThread.join();

    uiRunning.store(false);
    consoleThread.join();

    return 0;
}

#else  

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{

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

#endif 
