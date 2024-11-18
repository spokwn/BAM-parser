#pragma once
#include <yara/yara.h>
#include <string>
#include <vector>

struct GenericRule {
	std::string name;
	std::string rule;
};

extern std::vector<GenericRule> genericRules;

void addGenericRule(const std::string& name, const std::string& rule);

void initializeGenericRules();

bool scan_with_yara(const std::string& path, std::vector<std::string>& matched_rules);