#include "BAM.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include "../yara/yara.h"

std::vector<GenericRule> genericRules;

std::string BAMParser::wstringToString(const std::wstring& wstr) {
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &str[0], size_needed, nullptr, nullptr);
    return str;
}

std::wstring BAMParser::CheckDigitalSignature(const std::wstring& filePath) {
    if (!PathFileExistsW(filePath.c_str())) {
        return L"Deleted";
    }

    WINTRUST_FILE_INFO fileInfo;
    ZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();

    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA winTrustData;
    ZeroMemory(&winTrustData, sizeof(winTrustData));
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.pFile = &fileInfo;

    LONG lStatus = WinVerifyTrust(NULL, &guidAction, &winTrustData);
    std::wstring result = L"Not signed";

    if (lStatus == ERROR_SUCCESS) {
        result = L"Signed";
        CRYPT_PROVIDER_DATA const* psProvData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
        if (psProvData) {
            CRYPT_PROVIDER_DATA* nonConstProvData = const_cast<CRYPT_PROVIDER_DATA*>(psProvData);
            CRYPT_PROVIDER_SGNR* pProvSigner = WTHelperGetProvSignerFromChain(nonConstProvData, 0, FALSE, 0);
            if (pProvSigner) {
                CRYPT_PROVIDER_CERT* pProvCert = WTHelperGetProvCertFromChain(pProvSigner, 0);
                if (pProvCert && pProvCert->pCert) {
                    char subjectName[256];
                    CertNameToStrA(pProvCert->pCert->dwCertEncodingType,
                        &pProvCert->pCert->pCertInfo->Subject,
                        CERT_X500_NAME_STR,
                        subjectName,
                        sizeof(subjectName));
                    std::string subject(subjectName);
                    std::transform(subject.begin(), subject.end(), subject.begin(), ::tolower);

                    if (subject.find("manthe industries, llc") != std::string::npos ||
                        subject.find("slinkware") != std::string::npos) {
                        result = L"Not signed";
                    }
                }
            }
        }
    }

    // Cleanup
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &guidAction, &winTrustData);

    return result;
}
std::vector<FILETIME> BAMParser::GetInteractiveLogonSessions() {
    std::vector<FILETIME> sessions;
    ULONG logonSessionCount = 0;
    PLUID logonSessionList = NULL;

    NTSTATUS status = LsaEnumerateLogonSessions(&logonSessionCount, &logonSessionList);
    if (status != STATUS_SUCCESS) {
        return sessions;
    }

    for (ULONG i = 0; i < logonSessionCount; i++) {
        PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
        status = LsaGetLogonSessionData(&logonSessionList[i], &sessionData);
        if (status == STATUS_SUCCESS && sessionData != NULL) {
            if (sessionData->LogonType == Interactive ||
                sessionData->LogonType == RemoteInteractive) {
                FILETIME logonTime;
                logonTime.dwLowDateTime = sessionData->LogonTime.LowPart;
                logonTime.dwHighDateTime = sessionData->LogonTime.HighPart;

                FILETIME localLogonTime;
                FileTimeToLocalFileTime(&logonTime, &localLogonTime);
                sessions.push_back(localLogonTime);
            }
            LsaFreeReturnBuffer(sessionData);
        }
    }

    LsaFreeReturnBuffer(logonSessionList);
    return sessions;
}

bool BAMParser::IsInCurrentInstance(const std::wstring& execTime) {
    if (!IsValidTimeFormat(execTime)) {
        return false;
    }

    auto sessions = GetInteractiveLogonSessions();
    if (sessions.empty()) {
        return false;
    }

    FILETIME oldestSession = *std::min_element(sessions.begin(), sessions.end(),
        [](const FILETIME& a, const FILETIME& b) {
            return CompareFileTime(&a, &b) < 0;
        });

    SYSTEMTIME currentSysTime;
    GetLocalTime(&currentSysTime);
    FILETIME currentTime;
    SystemTimeToFileTime(&currentSysTime, &currentTime);

    FILETIME execFt = StringToFileTime(execTime);

    return (CompareFileTime(&execFt, &oldestSession) >= 0 &&
        CompareFileTime(&execFt, &currentTime) <= 0);
}

bool BAMParser::IsValidTimeFormat(const std::wstring& timeStr) {
    if (timeStr.length() != 19) return false;
    std::wistringstream ss(timeStr);
    std::tm tm = {};
    ss >> std::get_time(&tm, L"%Y-%m-%d %H:%M:%S");
    return !ss.fail();
}

FILETIME BAMParser::StringToFileTime(const std::wstring& timeStr) {
    std::wistringstream ss(timeStr);
    std::tm tm = {};
    ss >> std::get_time(&tm, L"%Y-%m-%d %H:%M:%S");

    SYSTEMTIME st = {
        (WORD)(tm.tm_year + 1900),
        (WORD)(tm.tm_mon + 1),
        (WORD)tm.tm_wday,
        (WORD)tm.tm_mday,
        (WORD)tm.tm_hour,
        (WORD)tm.tm_min,
        (WORD)tm.tm_sec,
        0
    };

    FILETIME ft;
    SystemTimeToFileTime(&st, &ft);
    FILETIME localFt;
    FileTimeToLocalFileTime(&ft, &localFt);
    return localFt;
}

std::wstring BAMParser::ConvertHardDiskVolumeToLetter(const std::wstring& path) {
    wchar_t drives[MAX_PATH];
    if (GetLogicalDriveStringsW(MAX_PATH, drives)) {
        wchar_t volumeName[MAX_PATH];
        wchar_t driveLetter[] = L" :";

        for (wchar_t* drive = drives; *drive; drive += 4) {
            driveLetter[0] = drive[0];
            if (QueryDosDeviceW(driveLetter, volumeName, MAX_PATH)) {
                std::wstring volPath = path;
                std::wstring volName = volumeName;

                if (volPath.find(volName) == 0) {
                    return std::wstring(1, drive[0]) + L":";
                }

                std::wstring globalRootPrefix = L"\\\\?\\GLOBALROOT";
                if (volPath.find(globalRootPrefix) == 0) {
                    volPath = volPath.substr(globalRootPrefix.length());
                    if (volPath.find(volName) == 0) {
                        return std::wstring(1, drive[0]) + L":";
                    }
                }
            }
        }
    }
    return L"?:";
}

FILETIME BAMParser::ConvertToLocalFileTime(const FILETIME& ft) {
    FILETIME localFt;
    ::FileTimeToLocalFileTime(&ft, &localFt);
    return localFt;
}

std::wstring BAMParser::FileTimeToString(const FILETIME& ft) {
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);

    std::wostringstream oss;
    oss << std::setfill(L'0')
        << st.wYear << L"-"
        << std::setw(2) << st.wMonth << L"-"
        << std::setw(2) << st.wDay << L" "
        << std::setw(2) << st.wHour << L":"
        << std::setw(2) << st.wMinute << L":"
        << std::setw(2) << st.wSecond;
    return oss.str();
}

void BAMParser::Parse() {
    HKEY hKey;
    const wchar_t* keyPath = L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";

    entries.clear();

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        std::wcout << L"Failed to open BAM key\n";
        return;
    }

    DWORD subKeyCount = 0;
    if (RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, &subKeyCount, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        std::wcout << L"Failed to query BAM key info\n";
        return;
    }

    for (DWORD i = 0; i < subKeyCount; i++) {
        wchar_t subKeyName[256];
        DWORD subKeyNameSize = 256;

        if (RegEnumKeyExW(hKey, i, subKeyName, &subKeyNameSize, nullptr, nullptr,
            nullptr, nullptr) == ERROR_SUCCESS) {
            HKEY hSubKey;
            std::wstring fullSubKeyPath = std::wstring(keyPath) + L"\\" + subKeyName;

            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, fullSubKeyPath.c_str(), 0,
                KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                DWORD valueCount = 0;
                if (RegQueryInfoKeyW(hSubKey, nullptr, nullptr, nullptr, nullptr, nullptr,
                    nullptr, &valueCount, nullptr, nullptr, nullptr,
                    nullptr) == ERROR_SUCCESS) {

                    for (DWORD j = 0; j < valueCount; j++) {
                        wchar_t valueName[32768];
                        DWORD valueNameSize = 32768;
                        BYTE valueData[1024];
                        DWORD valueDataSize = 1024;
                        DWORD valueType;

                        if (RegEnumValueW(hSubKey, j, valueName, &valueNameSize, nullptr,
                            &valueType, valueData, &valueDataSize) == ERROR_SUCCESS) {
                            if (valueType == REG_BINARY && valueDataSize >= sizeof(FILETIME)) {
                                std::wstring path = valueName;
                                if (path.find(L'\\') != std::wstring::npos) {
                                    size_t hdvPos = path.find(L"HarddiskVolume");
                                    if (hdvPos != std::wstring::npos) {
                                        std::wstring driveLetter = ConvertHardDiskVolumeToLetter(path);
                                        size_t pathStart = path.find(L'\\', hdvPos);
                                        if (pathStart != std::wstring::npos) {
                                            path = driveLetter + path.substr(pathStart);
                                        }
                                    }

                                    FILETIME* ft = reinterpret_cast<FILETIME*>(valueData);
                                    FILETIME localFt = ConvertToLocalFileTime(*ft);

                                    BAMEntry entry;
                                    entry.path = path;
                                    entry.executionTime = FileTimeToString(localFt);
                                    entry.signatureStatus = CheckDigitalSignature(path);
                                    entry.isInCurrentInstance = IsInCurrentInstance(entry.executionTime);
                                    if (entry.signatureStatus != L"Signed" && entry.signatureStatus != L"Deleted") {
                                        std::vector<std::string> matched_rules;
                                        if (scan_with_yara(wstringToString(path), matched_rules)) {
                                            entry.matched_rules = matched_rules;
                                        }
                                    }
                                    entries.push_back(entry);
                                }
                            }
                        }
                    }
                }
                RegCloseKey(hSubKey);
            }
        }
    }
    RegCloseKey(hKey);
}