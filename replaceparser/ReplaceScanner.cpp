#include "ReplaceScanner.hh"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <windows.h>
#include "Replaceparser.h"

std::string ReplaceScanner::replaceParserDir;
std::unordered_map<std::string, std::vector<ReplaceFileStruct>> ReplaceScanner::replaceCache;
std::mutex ReplaceScanner::cacheMutex;

bool ReplaceScanner::init() {
    char tempPathBuffer[MAX_PATH];
    DWORD tempPathLen = GetTempPathA(MAX_PATH, tempPathBuffer);
    if (tempPathLen == 0 || tempPathLen > MAX_PATH) {
        std::cerr << "Failed to get temporary path." << std::endl;
        return false;
    }

    std::string tempPath = std::string(tempPathBuffer);
    if (tempPath.back() == '\\' || tempPath.back() == '/') {
        tempPath.pop_back();
    }

    replaceParserDir = tempPath + "\\replaceparser";

    if (!CreateDirectoryA(replaceParserDir.c_str(), NULL)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            std::cerr << "Failed to create replaceParserDir: " << replaceParserDir << std::endl;
            return false;
        }
    }

    if (!WriteExeToTemp()) {
        std::cerr << "Failed to write replaceparser.exe to temp." << std::endl;
        return false;
    }

    if (!ExecuteReplaceParser()) {
        std::cerr << "Failed to execute replaceparser.exe." << std::endl;
        return false;
    }

    if (!loadCache()) {
        std::cerr << "Failed to load cache from replaces.txt." << std::endl;
        return false;
    }

    return true;
}

bool ReplaceScanner::destroy() {
    std::lock_guard<std::mutex> lock(cacheMutex);
    replaceCache.clear();

    try {
        return std::filesystem::remove_all(replaceParserDir) > 0;
    }
    catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Filesystem error during destroy: " << e.what() << std::endl;
        return false;
    }
}

std::vector<ReplaceFileStruct> ReplaceScanner::scan(const std::string& filePathOrName) {
    std::vector<ReplaceFileStruct> results;
    std::string fileName = extractFileName(filePathOrName);
    std::string fileNameLower = ToLower(fileName);

    std::lock_guard<std::mutex> lock(cacheMutex);
    auto it = replaceCache.find(fileNameLower);
    if (it != replaceCache.end()) {
        results = it->second;
    }

    return results;
}

std::string ReplaceScanner::getReplaceParserDir() {
    return replaceParserDir;
}

std::string ReplaceScanner::ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) { return std::tolower(c); });
    return result;
}

bool ReplaceScanner::WriteExeToTemp() {
    std::string exePath = replaceParserDir + "\\replaceparser.exe";
    std::ofstream exeFile(exePath, std::ios::binary);
    if (!exeFile) {
        std::cerr << "Failed to create replaceparser.exe at: " << exePath << std::endl;
        return false;
    }
    exeFile.write(reinterpret_cast<const char*>(ReplaceParserHex), sizeof(ReplaceParserHex));
    exeFile.close();
    return true;
}

bool ReplaceScanner::ExecuteReplaceParser() {
    std::string exePath = replaceParserDir + "\\replaceparser.exe";
    std::string replacesTxtPath = replaceParserDir + "\\replaces.txt";
    std::string commandLine = "\"" + exePath + "\" \"" + replacesTxtPath + "\"";

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL, const_cast<char*>(commandLine.c_str()), NULL, NULL, FALSE, 0, NULL,
        replaceParserDir.c_str(), &si, &pi)) {
        std::cerr << "CreateProcess failed with error: " << GetLastError() << std::endl;
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

std::string ReplaceScanner::extractFileName(const std::string& filePath) {
    size_t lastSlash = filePath.find_last_of("/\\");
    if (lastSlash != std::string::npos) {
        return filePath.substr(lastSlash + 1);
    }
    return filePath;
}

bool ReplaceScanner::loadCache() {
    std::string logPath = replaceParserDir + "\\replaces.txt";
    std::ifstream file(logPath);
    if (!file.is_open()) {
        std::cerr << "Failed to open replaces.txt at: " << logPath << std::endl;
        return false;
    }

    std::lock_guard<std::mutex> lock(cacheMutex);
    replaceCache.clear();

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;

        std::string replaceType, pattern;
        if (line.rfind("Explorer replacement found in file: ", 0) == 0) {
            replaceType = "Explorer";
            pattern = "Explorer replacement found in file: ";
        }
        else if (line.rfind("Copy replacement found in file: ", 0) == 0) {
            replaceType = "Copy";
            pattern = "Copy replacement found in file: ";
        }
        else if (line.rfind("Type pattern found in file: ", 0) == 0) {
            replaceType = "Type";
            pattern = "Type pattern found in file: ";
        }
        else if (line.rfind("Delete pattern found in file: ", 0) == 0) {
            replaceType = "Delete";
            pattern = "Delete pattern found in file: ";
        }
        else {
            continue;
        }

        size_t pos = line.find(pattern);
        if (pos == std::string::npos) continue;

        std::string foundFileName = line.substr(pos + pattern.size());
        std::string foundFileNameLower = ToLower(foundFileName);

        std::string detailsLine;
        bool openBraceFound = false;
        std::string detailsCollected;

        while (std::getline(file, detailsLine)) {
            if (!openBraceFound) {
                size_t bracePos = detailsLine.find('{');
                if (bracePos != std::string::npos) {
                    openBraceFound = true;
                    if (bracePos + 1 < detailsLine.size()) {
                        detailsCollected += detailsLine.substr(bracePos + 1) + "\n";
                    }
                }
            }
            else {
                size_t closePos = detailsLine.find('}');
                if (closePos != std::string::npos) {
                    if (closePos > 0) {
                        detailsCollected += detailsLine.substr(0, closePos);
                    }
                    break;
                }
                else {
                    detailsCollected += detailsLine + "\n";
                }
            }
        }

        ReplaceFileStruct result;
        result.filename = foundFileName;
        result.replaceType = replaceType;
        result.details = detailsCollected;

        replaceCache[foundFileNameLower].emplace_back(std::move(result));
    }

    file.close();
    return true;
}
