#ifndef YAML_PARSER_H
#define YAML_PARSER_H

#include <stddef.h>

#define MAX_STRING_LEN 1024
#define MAX_LIST_SIZE 100
#define MAX_SDK_ENTRIES 50

typedef enum {
    SEVERITY_LOW = 0,
    SEVERITY_MEDIUM = 1,
    SEVERITY_HIGH = 2,
    SEVERITY_CRITICAL = 3
} severity_level_t;

typedef struct {
    char name[MAX_STRING_LEN];
    char versions[MAX_STRING_LEN];
} approved_sdk_t;

typedef struct {
    char version[MAX_STRING_LEN];
} blacklisted_version_t;

typedef struct {
    char symmetric_encryption[MAX_STRING_LEN];
    char hashing[MAX_STRING_LEN];
    char tls_version[MAX_STRING_LEN];
} minimum_standards_t;

typedef struct {
    int enabled;
    double entropy_threshold;
} hardcoded_secret_config_t;

typedef struct {
    int strip_symbols;
    int pie_enabled;
    int stack_canary;
} binary_checks_t;

typedef struct {
    severity_level_t failure_threshold;
    
    approved_sdk_t approved_sdks[MAX_SDK_ENTRIES];
    int approved_sdk_count;
    
    blacklisted_version_t blacklisted_versions[MAX_LIST_SIZE];
    int blacklisted_version_count;
    
    minimum_standards_t minimum_standards;
    
    hardcoded_secret_config_t hardcoded_secret_scan;
    
    char required_hardening_flags[MAX_LIST_SIZE][MAX_STRING_LEN];
    int hardening_flags_count;
    
    binary_checks_t binary_checks;
    
    int memory_safety_checks;
    int concurrency_checks;
} security_policy_t;

// Function prototypes
int parse_security_yaml(const char* filename, security_policy_t* policy);
void cleanup_security_policy(security_policy_t* policy);
severity_level_t parse_severity(const char* severity_str);
const char* severity_to_string(severity_level_t severity);

#endif // YAML_PARSER_H
