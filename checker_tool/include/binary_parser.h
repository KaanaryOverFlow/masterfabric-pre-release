#ifndef BINARY_PARSER_H
#define BINARY_PARSER_H

#include "yaml_parser.h"
#include "sdk_analyzer.h"

// Function prototypes
int check_binary_hardening(const char* target_path, const security_policy_t* policy, scan_results_t* results);
int check_compiler_flags(const char* target_path, const security_policy_t* policy, scan_results_t* results);
int check_binary_security_features(const char* binary_path, const security_policy_t* policy, scan_results_t* results);
int find_binaries(const char* target_path, scan_results_t* results);
int check_makefile_flags(const char* makefile_path, const security_policy_t* policy, scan_results_t* results);
int check_cmake_flags(const char* cmake_path, const security_policy_t* policy, scan_results_t* results);
int is_elf_binary(const char* file_path);
int check_elf_security_features(const char* binary_path, const security_policy_t* policy, scan_results_t* results);

#endif // BINARY_PARSER_H
