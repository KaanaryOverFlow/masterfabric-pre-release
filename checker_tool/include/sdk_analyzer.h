#ifndef SDK_ANALYZER_H
#define SDK_ANALYZER_H

#include "yaml_parser.h"

#define MAX_FINDINGS 1000
#define MAX_FINDING_DESC 512

typedef struct {
    char description[MAX_FINDING_DESC];
    severity_level_t severity;
    char file_path[MAX_STRING_LEN];
    int line_number;
    char recommendation[MAX_FINDING_DESC];
} security_finding_t;

typedef struct {
    security_finding_t findings[MAX_FINDINGS];
    int finding_count;
    int critical_count;
    int high_count;
    int medium_count;
    int low_count;
} scan_results_t;

// Function prototypes
int analyze_dependencies(const char* target_path, const security_policy_t* policy, scan_results_t* results);
int parse_package_json(const char* file_path, scan_results_t* results);
int parse_requirements_txt(const char* file_path, scan_results_t* results);
int parse_cargo_toml(const char* file_path, scan_results_t* results);
int parse_go_mod(const char* file_path, scan_results_t* results);
int check_blacklisted_versions(const char* package_name, const char* version, 
                              const security_policy_t* policy, scan_results_t* results);
int check_approved_sdks(const char* package_name, const char* version,
                       const security_policy_t* policy, scan_results_t* results);
void add_finding(scan_results_t* results, severity_level_t severity, const char* description,
                const char* file_path, int line_number, const char* recommendation);
void cleanup_scan_results(scan_results_t* results);

#endif // SDK_ANALYZER_H
