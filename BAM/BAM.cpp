#include "bam.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <locale>
#include <codecvt>
#include <fstream>
#include "../yara/yara.h"

std::vector<GenericRule> genericRules;

std::string wstringToString(const std::wstring& wstr) {
    if (wstr.empty()) {
        return std::string();
    }

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(),
        nullptr, 0, nullptr, nullptr);

    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(),
        &str[0], size_needed, nullptr, nullptr);

    return str;
}

bool BAMParser::VerifyFileViaCatalog(LPCWSTR filePath)
{
    HANDLE hCatAdmin = NULL;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
        return false;

    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    DWORD dwHashSize = 0;
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, NULL, 0))
    {
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    BYTE* pbHash = new BYTE[dwHashSize];
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, pbHash, 0))
    {
        delete[] pbHash;
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    CloseHandle(hFile);

    CATALOG_INFO catInfo = { 0 };
    catInfo.cbStruct = sizeof(catInfo);

    HANDLE hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, NULL);
    bool isCatalogSigned = false;

    while (hCatInfo && CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0))
    {
        WINTRUST_CATALOG_INFO wtc = {};
        wtc.cbStruct = sizeof(wtc);
        wtc.pcwszCatalogFilePath = catInfo.wszCatalogFile;
        wtc.pbCalculatedFileHash = pbHash;
        wtc.cbCalculatedFileHash = dwHashSize;
        wtc.pcwszMemberFilePath = filePath;

        WINTRUST_DATA wtd = {};
        wtd.cbStruct = sizeof(wtd);
        wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
        wtd.pCatalog = &wtc;
        wtd.dwUIChoice = WTD_UI_NONE;
        wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wtd.dwProvFlags = 0;
        wtd.dwStateAction = WTD_STATEACTION_VERIFY;

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG res = WinVerifyTrust(NULL, &action, &wtd);

        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &action, &wtd);

        if (res == ERROR_SUCCESS)
        {
            isCatalogSigned = true;
            break;
        }
        hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, &hCatInfo);
    }

    if (hCatInfo)
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);

    CryptCATAdminReleaseContext(hCatAdmin, 0);
    delete[] pbHash;

    return isCatalogSigned;
}

std::wstring BAMParser::CheckDigitalSignature(const std::wstring& filePath) {
    if (!PathFileExistsW(filePath.c_str())) {
        return L"Deleted";
    }
    WINTRUST_FILE_INFO fileInfo;
    ZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(fileInfo);
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

    LONG status = WinVerifyTrust(NULL, &guidAction, &winTrustData);
    std::wstring result = L"Not signed";
    PCCERT_CONTEXT signingCert = nullptr;

    if (status == ERROR_SUCCESS) {
        result = L"Signed";
        CRYPT_PROVIDER_DATA const* provData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
        if (provData) {
            CRYPT_PROVIDER_DATA* nonConstData = const_cast<CRYPT_PROVIDER_DATA*>(provData);
            CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(nonConstData, 0, FALSE, 0);
            if (signer) {
                CRYPT_PROVIDER_CERT* provCert = WTHelperGetProvCertFromChain(signer, 0);
                if (provCert && provCert->pCert) {
                    signingCert = provCert->pCert;

                    char subjectName[256];
                    CertNameToStrA(signingCert->dwCertEncodingType, &signingCert->pCertInfo->Subject, CERT_X500_NAME_STR, subjectName, sizeof(subjectName));
                    std::string subject(subjectName);
                    std::transform(subject.begin(), subject.end(), subject.begin(), ::tolower);
                    static const char* cheats[] = { "manthe industries, llc", "slinkware", "amstion limited", "newfakeco", "faked signatures inc" };
                    for (auto c : cheats) {
                        if (subject.find(c) != std::string::npos) {
                            result = L"Cheat Signature";
                            break;
                        }
                    }

                    DWORD hashLen = 0;
                    if (CertGetCertificateContextProperty(signingCert, CERT_SHA1_HASH_PROP_ID, nullptr, &hashLen)) {
                        std::vector<BYTE> hash(hashLen);
                        if (CertGetCertificateContextProperty(signingCert, CERT_SHA1_HASH_PROP_ID, hash.data(), &hashLen)) {
                            CRYPT_HASH_BLOB blob{ hashLen, hash.data() };
                            static const LPCWSTR storeNames[] = { L"MY", L"Root", L"Trust", L"CA", L"UserDS", L"TrustedPublisher", L"Disallowed", L"AuthRoot", L"TrustedPeople", L"ClientAuthIssuer", L"CertificateEnrollment", L"SmartCardRoot" };
                            const DWORD contexts[] = { CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG, CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG };
                            bool found = false;
                            for (auto ctx : contexts) {
                                for (auto name : storeNames) {
                                    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, ctx, name);
                                    if (!store) continue;
                                    PCCERT_CONTEXT foundCert = CertFindCertificateInStore(store, signingCert->dwCertEncodingType, 0, CERT_FIND_SHA1_HASH, &blob, NULL);
                                    if (foundCert) {
                                        found = true;
                                        CertFreeCertificateContext(foundCert);
                                    }
                                    CertCloseStore(store, 0);
                                    if (found) break;
                                }
                                if (found) break;
                            }
                            if (found) {
                                result = L"Fake Signature";
                            }
                        }
                    }
                }
            }
        }
    } else {
        if (VerifyFileViaCatalog(filePath.c_str())) {
            result = L"Signed";
        }
    }

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &guidAction, &winTrustData);

    return result;
}


bool BAMParser::IsValidTimeFormat(const std::wstring& timeStr) {
    if (timeStr.length() != 19) return false;
    std::wistringstream ss(timeStr);
    std::tm tm = {};
    ss >> std::get_time(&tm, L"%Y-%m-%d %H:%M:%S");
    return !ss.fail();
}

FILETIME BAMParser::StringToFileTimeUTC(const std::wstring& timeStr) {
    std::wistringstream ss(timeStr);
    std::tm tm = {};
    ss >> std::get_time(&tm, L"%Y-%m-%d %H:%M:%S");

    SYSTEMTIME localSt = {
        (WORD)(tm.tm_year + 1900),
        (WORD)(tm.tm_mon + 1),
        (WORD)tm.tm_wday,
        (WORD)tm.tm_mday,
        (WORD)tm.tm_hour,
        (WORD)tm.tm_min,
        (WORD)tm.tm_sec,
        0
    };

    SYSTEMTIME utcSt;
    TzSpecificLocalTimeToSystemTime(NULL, &localSt, &utcSt);

    FILETIME ftUTC;
    SystemTimeToFileTime(&utcSt, &ftUTC);
    return ftUTC;
}

std::wstring BAMParser::FileTimeToStringLocal(const FILETIME& ft) {
    FILETIME localFt;
    FileTimeToLocalFileTime(&ft, &localFt);
    SYSTEMTIME st;
    FileTimeToSystemTime(&localFt, &st);

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

bool BAMParser::IsInCurrentInstance(const std::wstring& execTime) {
    if (!IsValidTimeFormat(execTime)) {
        return false;
    }

    auto sessions = GetInteractiveLogonSessions();
    if (sessions.empty()) {
        return false;
    }

    const LogonSessionInfo& firstSession = sessions.front();

    SYSTEMTIME utcCurrentSysTime;
    GetSystemTime(&utcCurrentSysTime);
    FILETIME currentTime;
    SystemTimeToFileTime(&utcCurrentSysTime, &currentTime);

    FILETIME execFt = StringToFileTimeUTC(execTime);

    return (CompareFileTime(&execFt, &firstSession.logonTime) >= 0 &&
        CompareFileTime(&execFt, &currentTime) <= 0);
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

void BAMParser::Parse() {
    if (!ReplaceScanner::init()) {
        std::cerr << "Failed to initialize ReplaceParser." << std::endl;
        return;
    }

    HKEY hKey;
    const wchar_t* keyPath = L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";

    entries.clear();

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        std::wcout << L"Failed to open BAM key\n";
        ReplaceScanner::destroy();
        return;
    }

    DWORD subKeyCount = 0;
    if (RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, &subKeyCount, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        std::wcout << L"Failed to query BAM key info\n";
        ReplaceScanner::destroy();
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
                                    std::wstring execLocalStr = FileTimeToStringLocal(*ft);

                                    BAMEntry entry;
                                    entry.path = path;
                                    entry.executionTime = execLocalStr;
                                    entry.signatureStatus = CheckDigitalSignature(path);
                                    entry.isInCurrentInstance = IsInCurrentInstance(entry.executionTime);

                                    if (entry.signatureStatus != L"Signed" && entry.signatureStatus != L"Deleted") {
                                        if (scan_with_yara(wstringToString(path), entry.matched_rules)) {
                                            // be happy (idk why its a if!)
                                        }
                                    }

                                    auto result = ReplaceScanner::scan(wstringToString(path));
                                    if (!result.empty()) {
                                        entry.replace_results = result;
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
    ReplaceScanner::destroy();
}
