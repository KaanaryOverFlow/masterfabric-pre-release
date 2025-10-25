#ifndef STATIC_ANALYZER_H
#define STATIC_ANALYZER_H

#include "yaml_parser.h"
#include "sdk_analyzer.h"

// Function prototypes
int run_static_analysis(const char* target_path, const security_policy_t* policy, scan_results_t* results);
int run_clang_tidy(const char* target_path, const security_policy_t* policy, scan_results_t* results);
int run_cppcheck(const char* target_path, const security_policy_t* policy, scan_results_t* results);
int parse_clang_tidy_output(const char* output, scan_results_t* results);
int parse_cppcheck_output(const char* output, scan_results_t* results);
int find_source_files(const char* target_path, char** source_files, int max_files);
int execute_command(const char* command, char* output, size_t output_size);

#endif // STATIC_ANALYZER_H
