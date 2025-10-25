#include "binary_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

static int is_binary_file(const char* filename) {
    const char* ext = strrchr(filename, '.');
    if (!ext) return 0;
    
    // Common binary extensions
    return (strcmp(ext, ".exe") == 0 || strcmp(ext, ".bin") == 0 || 
            strcmp(ext, ".so") == 0 || strcmp(ext, ".dll") == 0 ||
            strcmp(ext, ".dylib") == 0 || strcmp(ext, ".a") == 0 ||
            strcmp(ext, ".o") == 0);
}

static int is_executable(const char* file_path) {
    struct stat st;
    if (stat(file_path, &st) != 0) return 0;
    
    return (st.st_mode & S_IXUSR) || (st.st_mode & S_IXGRP) || (st.st_mode & S_IXOTH);
}

int is_elf_binary(const char* file_path) {
    FILE* file = fopen(file_path, "rb");
    if (!file) return 0;
    
    unsigned char magic[4];
    if (fread(magic, 1, 4, file) != 4) {
        fclose(file);
        return 0;
    }
    
    fclose(file);
    
    // Check ELF magic number: 0x7F 'E' 'L' 'F'
    return (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F');
}

int check_elf_security_features(const char* binary_path, const security_policy_t* policy, scan_results_t* results) {
    // This is a simplified check - in a real implementation, you would use libelf
    // or similar to parse ELF headers and check for security features
    
    FILE* file = fopen(binary_path, "rb");
    if (!file) return 1;
    
    // Read ELF header
    unsigned char header[64];
    if (fread(header, 1, 64, file) != 64) {
        fclose(file);
        return 1;
    }
    
    fclose(file);
    
    // Check for PIE (Position Independent Executable)
    // This is a simplified check - real implementation would parse ELF properly
    if (policy->binary_checks.pie_enabled) {
        // In a real implementation, you would check the ELF header for PIE flags
        // For now, we'll add a placeholder finding
        add_finding(results, SEVERITY_MEDIUM,
                   "PIE (Position Independent Executable) check not fully implemented",
                   binary_path, 0,
                   "Verify PIE is enabled in compiler flags (-fPIE -pie)");
    }
    
    // Check for stack canary
    if (policy->binary_checks.stack_canary) {
        // In a real implementation, you would check for stack canary symbols
        add_finding(results, SEVERITY_MEDIUM,
                   "Stack canary check not fully implemented",
                   binary_path, 0,
                   "Verify stack canary is enabled (-fstack-protector-strong)");
    }
    
    return 0;
}

int find_binaries(const char* target_path, scan_results_t* results) {
    DIR* dir = opendir(target_path);
    if (!dir) return 1;
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        // Skip hidden files and directories
        if (entry->d_name[0] == '.') continue;
        
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", target_path, entry->d_name);
        
        struct stat st;
        if (stat(full_path, &st) != 0) continue;
        
        if (S_ISDIR(st.st_mode)) {
            // Recursively search subdirectories
            find_binaries(full_path, results);
        } else if (S_ISREG(st.st_mode) && (is_binary_file(entry->d_name) || is_executable(full_path))) {
            // Found a binary file
            if (is_elf_binary(full_path)) {
                // This is a placeholder - in a real implementation, you would
                // add the binary to a list for later analysis
                printf("Found ELF binary: %s\n", full_path);
            }
        }
    }
    
    closedir(dir);
    return 0;
}

int check_makefile_flags(const char* makefile_path, const security_policy_t* policy, scan_results_t* results) {
    FILE* file = fopen(makefile_path, "r");
    if (!file) return 1;
    
    char line[1024];
    int line_number = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_number++;
        
        // Look for CFLAGS, CXXFLAGS, LDFLAGS
        if (strstr(line, "CFLAGS") != NULL || strstr(line, "CXXFLAGS") != NULL || strstr(line, "LDFLAGS") != NULL) {
            // Check if required hardening flags are present
            for (int i = 0; i < policy->hardening_flags_count; i++) {
                const char* required_flag = policy->required_hardening_flags[i];
                
                if (strstr(line, required_flag) == NULL) {
                    char description[MAX_FINDING_DESC];
                    snprintf(description, sizeof(description),
                            "Missing required hardening flag: %s", required_flag);
                    
                    char recommendation[MAX_FINDING_DESC];
                    snprintf(recommendation, sizeof(recommendation),
                            "Add %s to CFLAGS/CXXFLAGS/LDFLAGS in Makefile", required_flag);
                    
                    add_finding(results, SEVERITY_HIGH, description, makefile_path, line_number, recommendation);
                }
            }
        }
    }
    
    fclose(file);
    return 0;
}

int check_cmake_flags(const char* cmake_path, const security_policy_t* policy, scan_results_t* results) {
    FILE* file = fopen(cmake_path, "r");
    if (!file) return 1;
    
    char line[1024];
    int line_number = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_number++;
        
        // Look for add_compile_options, target_compile_options, etc.
        if (strstr(line, "add_compile_options") != NULL || 
            strstr(line, "target_compile_options") != NULL ||
            strstr(line, "set(CMAKE_C_FLAGS") != NULL ||
            strstr(line, "set(CMAKE_CXX_FLAGS") != NULL) {
            
            // Check if required hardening flags are present
            for (int i = 0; i < policy->hardening_flags_count; i++) {
                const char* required_flag = policy->required_hardening_flags[i];
                
                if (strstr(line, required_flag) == NULL) {
                    char description[MAX_FINDING_DESC];
                    snprintf(description, sizeof(description),
                            "Missing required hardening flag: %s", required_flag);
                    
                    char recommendation[MAX_FINDING_DESC];
                    snprintf(recommendation, sizeof(recommendation),
                            "Add %s to CMake compile options", required_flag);
                    
                    add_finding(results, SEVERITY_HIGH, description, cmake_path, line_number, recommendation);
                }
            }
        }
    }
    
    fclose(file);
    return 0;
}

int check_compiler_flags(const char* target_path, const security_policy_t* policy, scan_results_t* results) {
    // Look for Makefile
    char makefile_path[1024];
    snprintf(makefile_path, sizeof(makefile_path), "%s/Makefile", target_path);
    
    struct stat st;
    if (stat(makefile_path, &st) == 0) {
        if (check_makefile_flags(makefile_path, policy, results) != 0) {
            fprintf(stderr, "Warning: Failed to check Makefile flags\n");
        }
    }
    
    // Look for CMakeLists.txt
    char cmake_path[1024];
    snprintf(cmake_path, sizeof(cmake_path), "%s/CMakeLists.txt", target_path);
    
    if (stat(cmake_path, &st) == 0) {
        if (check_cmake_flags(cmake_path, policy, results) != 0) {
            fprintf(stderr, "Warning: Failed to check CMake flags\n");
        }
    }
    
    return 0;
}

int check_binary_security_features(const char* binary_path, const security_policy_t* policy, scan_results_t* results) {
    if (is_elf_binary(binary_path)) {
        return check_elf_security_features(binary_path, policy, results);
    }
    
    // For non-ELF binaries, we can't perform detailed analysis
    add_finding(results, SEVERITY_LOW,
               "Binary format not supported for detailed security analysis",
               binary_path, 0,
               "Consider using ELF format for better security analysis");
    
    return 0;
}

int check_binary_hardening(const char* target_path, const security_policy_t* policy, scan_results_t* results) {
    // Check compiler flags in build files
    if (check_compiler_flags(target_path, policy, results) != 0) {
        fprintf(stderr, "Warning: Failed to check compiler flags\n");
    }
    
    // Find and analyze binary files
    if (find_binaries(target_path, results) != 0) {
        fprintf(stderr, "Warning: Failed to find binary files\n");
    }
    
    return 0;
}
