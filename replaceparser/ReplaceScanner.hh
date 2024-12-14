#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

struct ReplaceFileStruct {
    std::string filename;
    std::string replaceType;
    std::string details;
};

class ReplaceScanner {
public:
    static bool init();
    static bool destroy();
    static std::vector<ReplaceFileStruct> scan(const std::string& filePathOrName);
    static std::string getReplaceParserDir();

private:
    static std::string replaceParserDir;
    static std::unordered_map<std::string, std::vector<ReplaceFileStruct>> replaceCache;
    static std::mutex cacheMutex;

    static std::string ToLower(const std::string& str);
    static bool WriteExeToTemp();
    static bool ExecuteReplaceParser();
    static std::string extractFileName(const std::string& filePath);
    static bool loadCache();
};
