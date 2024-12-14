#include "yara.h"
#include <yara/yara.h>

void addGenericRule(const std::string& name, const std::string& rule) {
    genericRules.push_back({ name, rule });
}

void initializeGenericRules() {
  addGenericRule("Generic A", R"(
import "pe"
rule A
{
    strings:
        $a = /clicker/i ascii wide
        $b = /autoclick/i ascii wide
        $c = /clicking/i ascii wide
        $d = /String Cleaner/i ascii wide
        $e = /double_click/i ascii wide
        $f = /Jitter Click/i ascii wide
        $g = /Butterfly Click/i ascii wide

    condition:
        pe.is_pe and
        any of them
}
)");

    addGenericRule("Specifics A", R"(
rule sA
{
    strings:
        $a = /Exodus\.codes/i ascii wide
        $b = /slinky\.gg/i ascii wide
        $c = /slinkyhook\.dll/i ascii wide
        $d = /slinky_library\.dll/i ascii wide
        $e = /\[!\] Failed to find Vape jar/i ascii wide
        $f = /Vape Launcher/i ascii wide
        $g = /vape\.gg/i ascii wide
        $h = /C:\\Users\\PC\\Desktop\\Cleaner-main\\obj\\x64\\Release\\WindowsFormsApp3\.pdb/i ascii wide
        $i = /discord\.gg\/advantages/i ascii wide
        $j = /String cleaner/i ascii wide
        $k = /Open Minecraft, then try again\./i ascii wide
        $l = /The clicker code was done by Nightbot\. I skidded it :\)/i ascii wide
        $m = /PE injector/i ascii wide
        $n = /name="SparkCrack\.exe"/i ascii wide
        $o = /starlight v1\.0/i ascii wide
        $p = /Sapphire LITE Clicker/i ascii wide
        $q = /Striker\.exe/i ascii wide
        $r = /Cracked by Kangaroo/i ascii wide
        $s = /Monolith Lite/i ascii wide
        $t = /B\.fagg0t0/i ascii wide
        $u = /B\.fag0/i ascii wide
        $v = /\.\fag1/i ascii wide
        $w = /dream-injector/i ascii wide
        $x = /C:\\Users\\Daniel\\Desktop\\client-top\\x64\\Release\\top-external\.pdb/i ascii wide
        $y = /C:\\Users\\Daniel\\Desktop\\client-top\\x64\\Release\\top-internal\.pdb/i ascii wide
        $z = /UNICORN CLIENT/i ascii wide
        $aa = /Adding delay to Minecraft/i ascii wide
        $ab = /rightClickChk\.BackgroundImage/i ascii wide
        $ac = /UwU Client/i ascii wide
        $ad = /lithiumclient\.wtf/i ascii wide
    condition:
        pe.is_pe and
        any of them
}
)");

    // MAS
}



int yara_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        std::vector<std::string>* matched_rules = (std::vector<std::string>*)user_data;
        matched_rules->push_back(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

void compiler_error_callback(int error_level, const char* file_name, int line_number, const YR_RULE* rule, const char* message, void* user_data) {
    fprintf(stderr, "Error: %s at line %d: %s\n", file_name ? file_name : "N/A", line_number, message);
}

bool scan_with_yara(const std::string& path, std::vector<std::string>& matched_rules) {
    YR_COMPILER* compiler = NULL;
    YR_RULES* rules = NULL;
    int result = yr_initialize();
    if (result != ERROR_SUCCESS) return false;

    result = yr_compiler_create(&compiler);
    if (result != ERROR_SUCCESS) {
        yr_finalize();
        return false;
    }

    yr_compiler_set_callback(compiler, compiler_error_callback, NULL);

    for (const auto& rule : genericRules) {
        result = yr_compiler_add_string(compiler, rule.rule.c_str(), NULL);
        if (result != 0) {
            yr_compiler_destroy(compiler);
            yr_finalize();
            return false;
        }
    }

    result = yr_compiler_get_rules(compiler, &rules);
    if (result != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        yr_finalize();
        return false;
    }

    result = yr_rules_scan_file(rules, path.c_str(), 0, yara_callback, &matched_rules, 0);

    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);
    yr_finalize();

    return !matched_rules.empty();
}
