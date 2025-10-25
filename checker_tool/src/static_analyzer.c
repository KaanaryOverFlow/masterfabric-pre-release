#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include "static_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

static int is_c_cpp_file(const char* filename) {
    const char* ext = strrchr(filename, '.');
    if (!ext) return 0;
    
    return (strcmp(ext, ".c") == 0 || strcmp(ext, ".cpp") == 0 || 
            strcmp(ext, ".cc") == 0 || strcmp(ext, ".cxx") == 0 ||
            strcmp(ext, ".h") == 0 || strcmp(ext, ".hpp") == 0);
}

int find_source_files(const char* target_path, char** source_files, int max_files) {
    DIR* dir = opendir(target_path);
    if (!dir) return 0;
    
    int count = 0;
    struct dirent* entry;
    
    while ((entry = readdir(dir)) != NULL && count < max_files) {
        // Skip hidden files and directories
        if (entry->d_name[0] == '.') continue;
        
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", target_path, entry->d_name);
        
        struct stat st;
        if (stat(full_path, &st) != 0) continue;
        
        if (S_ISDIR(st.st_mode)) {
            // Recursively search subdirectories
            int sub_count = find_source_files(full_path, &source_files[count], max_files - count);
            count += sub_count;
        } else if (S_ISREG(st.st_mode) && is_c_cpp_file(entry->d_name)) {
            // Found a C/C++ source file
            source_files[count] = malloc(strlen(full_path) + 1);
            if (source_files[count]) {
                strcpy(source_files[count], full_path);
                count++;
            }
        }
    }
    
    closedir(dir);
    return count;
}

int execute_command(const char* command, char* output, size_t output_size) {
    FILE* pipe = popen(command, "r");
    if (!pipe) return 1;
    
    size_t total_read = 0;
    char buffer[1024];
    
    while (fgets(buffer, sizeof(buffer), pipe) && total_read < output_size - 1) {
        size_t len = strlen(buffer);
        if (total_read + len < output_size) {
            strcpy(output + total_read, buffer);
            total_read += len;
        }
    }
    
    output[total_read] = '\0';
    
    int exit_code = pclose(pipe);
    return (exit_code == 0) ? 0 : 1;
}

int parse_clang_tidy_output(const char* output, scan_results_t* results) {
    const char* line_start = output;
    const char* line_end;
    
    while ((line_end = strchr(line_start, '\n')) != NULL) {
        size_t line_len = line_end - line_start;
        char line[1024];
        
        if (line_len >= sizeof(line)) line_len = sizeof(line) - 1;
        strncpy(line, line_start, line_len);
        line[line_len] = '\0';
        
        // Parse clang-tidy output format
        // Example: "file.cpp:10:5: warning: potential memory leak [clang-analyzer-unix.Malloc]"
        if (strstr(line, ": warning:") != NULL || strstr(line, ": error:") != NULL) {
            char file_path[256];
            int line_number = 0;
            char severity_str[32];
            char message[512];
            
            // Extract file path
            const char* colon1 = strchr(line, ':');
            if (colon1) {
                size_t path_len = colon1 - line;
                if (path_len < sizeof(file_path)) {
                    strncpy(file_path, line, path_len);
                    file_path[path_len] = '\0';
                }
                
                // Extract line number
                const char* colon2 = strchr(colon1 + 1, ':');
                if (colon2) {
                    line_number = atoi(colon1 + 1);
                    
                    // Extract severity
                    const char* colon3 = strchr(colon2 + 1, ':');
                    if (colon3) {
                        const char* severity_start = colon3 + 1;
                        while (*severity_start && isspace(*severity_start)) severity_start++;
                        
                        const char* severity_end = strchr(severity_start, ':');
                        if (severity_end) {
                            size_t severity_len = severity_end - severity_start;
                            if (severity_len < sizeof(severity_str)) {
                                strncpy(severity_str, severity_start, severity_len);
                                severity_str[severity_len] = '\0';
                            }
                            
                            // Extract message
                            const char* message_start = severity_end + 1;
                            while (*message_start && isspace(*message_start)) message_start++;
                            
                            strncpy(message, message_start, sizeof(message) - 1);
                            message[sizeof(message) - 1] = '\0';
                            
                            // Determine severity level
                            severity_level_t severity = SEVERITY_MEDIUM;
                            if (strstr(severity_str, "error") != NULL) {
                                severity = SEVERITY_HIGH;
                            } else if (strstr(severity_str, "warning") != NULL) {
                                severity = SEVERITY_MEDIUM;
                            }
                            
                            // Add finding
                            add_finding(results, severity, message, file_path, line_number,
                                       "Review and fix the static analysis finding");
                        }
                    }
                }
            }
        }
        
        line_start = line_end + 1;
    }
    
    return 0;
}

int parse_cppcheck_output(const char* output, scan_results_t* results) {
    const char* line_start = output;
    const char* line_end;
    
    while ((line_end = strchr(line_start, '\n')) != NULL) {
        size_t line_len = line_end - line_start;
        char line[1024];
        
        if (line_len >= sizeof(line)) line_len = sizeof(line) - 1;
        strncpy(line, line_start, line_len);
        line[line_len] = '\0';
        
        // Parse cppcheck output format
        // Example: "[file.cpp:10]: (error) Memory leak: variable"
        if (strstr(line, "]: (") != NULL) {
            char file_path[256];
            int line_number = 0;
            char severity_str[32];
            char message[512];
            
            // Extract file path and line number
            const char* bracket_start = strchr(line, '[');
            if (bracket_start) {
                const char* colon = strchr(bracket_start, ':');
                if (colon) {
                    size_t path_len = colon - bracket_start - 1;
                    if (path_len < sizeof(file_path)) {
                        strncpy(file_path, bracket_start + 1, path_len);
                        file_path[path_len] = '\0';
                    }
                    
                    line_number = atoi(colon + 1);
                    
                    // Extract severity
                    const char* severity_start = strchr(colon, '(');
                    if (severity_start) {
                        severity_start++;
                        const char* severity_end = strchr(severity_start, ')');
                        if (severity_end) {
                            size_t severity_len = severity_end - severity_start;
                            if (severity_len < sizeof(severity_str)) {
                                strncpy(severity_str, severity_start, severity_len);
                                severity_str[severity_len] = '\0';
                            }
                            
                            // Extract message
                            const char* message_start = severity_end + 1;
                            while (*message_start && isspace(*message_start)) message_start++;
                            
                            strncpy(message, message_start, sizeof(message) - 1);
                            message[sizeof(message) - 1] = '\0';
                            
                            // Determine severity level
                            severity_level_t severity = SEVERITY_MEDIUM;
                            if (strstr(severity_str, "error") != NULL) {
                                severity = SEVERITY_HIGH;
                            } else if (strstr(severity_str, "warning") != NULL) {
                                severity = SEVERITY_MEDIUM;
                            } else if (strstr(severity_str, "style") != NULL) {
                                severity = SEVERITY_LOW;
                            }
                            
                            // Add finding
                            add_finding(results, severity, message, file_path, line_number,
                                       "Review and fix the static analysis finding");
                        }
                    }
                }
            }
        }
        
        line_start = line_end + 1;
    }
    
    return 0;
}

int run_clang_tidy(const char* target_path, const security_policy_t* policy, scan_results_t* results) {
    if (!policy->memory_safety_checks && !policy->concurrency_checks) {
        return 0; // Skip if checks are disabled
    }
    
    // Find C/C++ source files
    char* source_files[100];
    int file_count = find_source_files(target_path, source_files, 100);
    
    if (file_count == 0) {
        return 0; // No C/C++ files found
    }
    
    // Build clang-tidy command
    char command[2048];
    strcpy(command, "clang-tidy --checks=* ");
    
    // Add security-focused checks
    if (policy->memory_safety_checks) {
        strcat(command, "--checks=clang-analyzer-security*,clang-analyzer-unix.Malloc,clang-analyzer-cplusplus.NewDelete ");
    }
    
    if (policy->concurrency_checks) {
        strcat(command, "--checks=clang-analyzer-concurrency* ");
    }
    
    // Add source files
    for (int i = 0; i < file_count; i++) {
        strcat(command, source_files[i]);
        strcat(command, " ");
    }
    
    // Execute command
    char output[8192];
    if (execute_command(command, output, sizeof(output)) == 0) {
        parse_clang_tidy_output(output, results);
    } else {
        // clang-tidy not available or failed
        add_finding(results, SEVERITY_LOW,
                   "clang-tidy not available or failed to run",
                   target_path, 0,
                   "Install clang-tidy for enhanced static analysis");
    }
    
    // Cleanup
    for (int i = 0; i < file_count; i++) {
        free(source_files[i]);
    }
    
    return 0;
}

int run_cppcheck(const char* target_path, const security_policy_t* policy, scan_results_t* results) {
    if (!policy->memory_safety_checks && !policy->concurrency_checks) {
        return 0; // Skip if checks are disabled
    }
    
    // Build cppcheck command
    char command[1024];
    strcpy(command, "cppcheck --enable=all --inconclusive ");
    
    if (policy->memory_safety_checks) {
        strcat(command, "--enable=memory,leak ");
    }
    
    if (policy->concurrency_checks) {
        strcat(command, "--enable=threadSafety ");
    }
    
    strcat(command, target_path);
    
    // Execute command
    char output[8192];
    if (execute_command(command, output, sizeof(output)) == 0) {
        parse_cppcheck_output(output, results);
    } else {
        // cppcheck not available or failed
        add_finding(results, SEVERITY_LOW,
                   "cppcheck not available or failed to run",
                   target_path, 0,
                   "Install cppcheck for enhanced static analysis");
    }
    
    return 0;
}

int run_static_analysis(const char* target_path, const security_policy_t* policy, scan_results_t* results) {
    // Run clang-tidy
    if (run_clang_tidy(target_path, policy, results) != 0) {
        fprintf(stderr, "Warning: clang-tidy analysis failed\n");
    }
    
    // Run cppcheck
    if (run_cppcheck(target_path, policy, results) != 0) {
        fprintf(stderr, "Warning: cppcheck analysis failed\n");
    }
    
    return 0;
}
