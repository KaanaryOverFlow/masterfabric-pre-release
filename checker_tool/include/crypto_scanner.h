#ifndef CRYPTO_SCANNER_H
#define CRYPTO_SCANNER_H

#include "yaml_parser.h"
#include "sdk_analyzer.h"

// Function prototypes
int scan_cryptographic_issues(const char* target_path, const security_policy_t* policy, scan_results_t* results);
int scan_file_for_crypto_issues(const char* file_path, const security_policy_t* policy, scan_results_t* results);
int detect_weak_ciphers(const char* content, const char* file_path, int line_number, scan_results_t* results);
int detect_hardcoded_secrets(const char* content, const char* file_path, int line_number, 
                           const security_policy_t* policy, scan_results_t* results);
int detect_weak_random_sources(const char* content, const char* file_path, int line_number, scan_results_t* results);
int detect_flutter_security_issues(const char* content, const char* file_path, int line_number, scan_results_t* results);
double calculate_entropy(const char* str);
int is_high_entropy_string(const char* str, double threshold);

#endif // CRYPTO_SCANNER_H
