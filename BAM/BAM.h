#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <wintrust.h>
#include <softpub.h>
#include <ntsecapi.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <Shlwapi.h>
#include <ntstatus.h>
#include <wincrypt.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Crypt32.lib") 

struct BAMEntry {
    std::wstring path;
    std::wstring executionTime;
    std::wstring signatureStatus;
    bool isInCurrentInstance;
    std::vector<std::string> matched_rules;
};

class BAMParser {
private:
    std::vector<BAMEntry> entries;
    std::string wstringToString(const std::wstring& wstr);
    std::wstring ConvertHardDiskVolumeToLetter(const std::wstring& path);
    FILETIME ConvertToLocalFileTime(const FILETIME& ft);
    std::wstring FileTimeToString(const FILETIME& ft);
    std::wstring CheckDigitalSignature(const std::wstring& filePath);
    bool IsInCurrentInstance(const std::wstring& execTime);
    void Parse();
    std::vector<FILETIME> GetInteractiveLogonSessions();
    bool IsValidTimeFormat(const std::wstring& timeStr);
    FILETIME StringToFileTime(const std::wstring& timeStr);

public:
    BAMParser() { Parse(); }
    const std::vector<BAMEntry>& GetEntries() const { return entries; }
};