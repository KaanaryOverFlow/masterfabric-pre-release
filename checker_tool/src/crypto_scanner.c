#include "crypto_scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <dirent.h>
#include <sys/stat.h>

static int is_source_file(const char* filename) {
    const char* ext = strrchr(filename, '.');
    if (!ext) return 0;
    
    return (strcmp(ext, ".c") == 0 || strcmp(ext, ".cpp") == 0 || 
            strcmp(ext, ".h") == 0 || strcmp(ext, ".hpp") == 0 ||
            strcmp(ext, ".js") == 0 || strcmp(ext, ".ts") == 0 ||
            strcmp(ext, ".py") == 0 || strcmp(ext, ".rs") == 0 ||
            strcmp(ext, ".go") == 0 || strcmp(ext, ".java") == 0 ||
            strcmp(ext, ".dart") == 0);
}

static void scan_directory_recursive(const char* dir_path, const security_policy_t* policy, scan_results_t* results) {
    DIR* dir = opendir(dir_path);
    if (!dir) return;
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        // Skip hidden files and directories
        if (entry->d_name[0] == '.') continue;
        
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);
        
        struct stat st;
        if (stat(full_path, &st) != 0) continue;
        
        if (S_ISDIR(st.st_mode)) {
            // Recursively scan subdirectories
            scan_directory_recursive(full_path, policy, results);
        } else if (S_ISREG(st.st_mode) && is_source_file(entry->d_name)) {
            // Scan source files
            scan_file_for_crypto_issues(full_path, policy, results);
        }
    }
    
    closedir(dir);
}

double calculate_entropy(const char* str) {
    if (!str || strlen(str) == 0) return 0.0;
    
    int char_counts[256] = {0};
    int len = strlen(str);
    
    // Count character frequencies
    for (int i = 0; i < len; i++) {
        char_counts[(unsigned char)str[i]]++;
    }
    
    // Calculate entropy
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (char_counts[i] > 0) {
            double probability = (double)char_counts[i] / len;
            entropy -= probability * log2(probability);
        }
    }
    
    return entropy;
}

int is_high_entropy_string(const char* str, double threshold) {
    if (!str || strlen(str) < 8) return 0; // Too short to be a secret
    
    double entropy = calculate_entropy(str);
    return (entropy >= threshold);
}

int detect_weak_ciphers(const char* content, const char* file_path, int line_number, scan_results_t* results) {
    const char* weak_ciphers[] = {
        "DES", "3DES", "MD5", "SHA1", "RC4", "RC2", "Blowfish",
        "md5", "sha1", "des", "rc4", "blowfish",
        "crypto.createHash('md5')", "crypto.createHash('sha1')",
        "hashlib.md5", "hashlib.sha1", "MD5", "SHA1",
        // Flutter/Dart specific weak crypto
        "md5.convert", "sha1.convert", "Random()", "Random.random",
        "XOR", "xor", "base64.encode", "base64.decode"
    };
    
    int num_ciphers = sizeof(weak_ciphers) / sizeof(weak_ciphers[0]);
    
    for (int i = 0; i < num_ciphers; i++) {
        const char* cipher = weak_ciphers[i];
        const char* found = strstr(content, cipher);
        
        if (found) {
            char description[MAX_FINDING_DESC];
            snprintf(description, sizeof(description),
                    "Weak cryptographic algorithm detected: %s", cipher);
            
            char recommendation[MAX_FINDING_DESC];
            snprintf(recommendation, sizeof(recommendation),
                    "Replace %s with a stronger algorithm (e.g., AES-256-GCM, SHA3-256)", cipher);
            
            add_finding(results, SEVERITY_HIGH, description, file_path, line_number, recommendation);
            return 1; // Found weak cipher
        }
    }
    
    return 0;
}

int detect_hardcoded_secrets(const char* content, const char* file_path, int line_number, 
                           const security_policy_t* policy, scan_results_t* results) {
    if (!policy->hardcoded_secret_scan.enabled) return 0;
    
    // Common secret patterns
    const char* secret_patterns[] = {
        "password", "secret", "key", "token", "api_key", "apikey",
        "private_key", "secret_key", "access_token", "auth_token"
    };
    
    int num_patterns = sizeof(secret_patterns) / sizeof(secret_patterns[0]);
    
    for (int i = 0; i < num_patterns; i++) {
        const char* pattern = secret_patterns[i];
        const char* found = strstr(content, pattern);
        
        if (found) {
            // Look for assignment patterns like "password = "value""
            const char* assignment = strstr(found, "=");
            if (assignment) {
                // Find the value after the equals sign
                const char* value_start = assignment + 1;
                while (*value_start && isspace(*value_start)) value_start++;
                
                if (*value_start == '"' || *value_start == '\'') {
                    char quote = *value_start;
                    value_start++;
                    
                    const char* value_end = strchr(value_start, quote);
                    if (value_end) {
                        size_t value_len = value_end - value_start;
                        if (value_len > 0 && value_len < 256) {
                            char value[256];
                            strncpy(value, value_start, value_len);
                            value[value_len] = '\0';
                            
                            // Check if it's a high entropy string
                            if (is_high_entropy_string(value, policy->hardcoded_secret_scan.entropy_threshold)) {
                                char description[MAX_FINDING_DESC];
                                snprintf(description, sizeof(description),
                                        "Potential hardcoded secret detected: %s", pattern);
                                
                                char recommendation[MAX_FINDING_DESC];
                                snprintf(recommendation, sizeof(recommendation),
                                        "Move %s to environment variables or secure configuration", pattern);
                                
                                add_finding(results, SEVERITY_CRITICAL, description, file_path, line_number, recommendation);
                                return 1; // Found hardcoded secret
                            }
                        }
                    }
                }
            }
        }
    }
    
    return 0;
}

int detect_weak_random_sources(const char* content, const char* file_path, int line_number, scan_results_t* results) {
    const char* weak_random[] = {
        "rand()", "Math.random()", "random.random()", "random()",
        "srand(", "Math.floor(Math.random()", "numpy.random",
        // Flutter/Dart specific weak random
        "Random()", "Random.random", "Random.nextInt", "Random.nextDouble",
        "DateTime.now().millisecondsSinceEpoch", "timestamp"
    };
    
    int num_patterns = sizeof(weak_random) / sizeof(weak_random[0]);
    
    for (int i = 0; i < num_patterns; i++) {
        const char* pattern = weak_random[i];
        const char* found = strstr(content, pattern);
        
        if (found) {
            char description[MAX_FINDING_DESC];
            snprintf(description, sizeof(description),
                    "Weak random number generator detected: %s", pattern);
            
            char recommendation[MAX_FINDING_DESC];
            snprintf(recommendation, sizeof(recommendation),
                    "Use cryptographically secure random number generator (e.g., /dev/urandom, crypto.randomBytes)");
            
            add_finding(results, SEVERITY_MEDIUM, description, file_path, line_number, recommendation);
            return 1; // Found weak random source
        }
    }
    
    return 0;
}

int scan_file_for_crypto_issues(const char* file_path, const security_policy_t* policy, scan_results_t* results) {
    FILE* file = fopen(file_path, "r");
    if (!file) return 1;
    
    char line[2048];
    int line_number = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_number++;
        
        // Remove newline
        line[strcspn(line, "\n")] = '\0';
        
        // Check for weak ciphers
        detect_weak_ciphers(line, file_path, line_number, results);
        
        // Check for hardcoded secrets
        detect_hardcoded_secrets(line, file_path, line_number, policy, results);
        
        // Check for weak random sources
        detect_weak_random_sources(line, file_path, line_number, results);
        
        // Check for Flutter/Dart specific security issues
        detect_flutter_security_issues(line, file_path, line_number, results);
    }
    
    fclose(file);
    return 0;
}

int detect_flutter_security_issues(const char* content, const char* file_path, int line_number, scan_results_t* results) {
    // Detect Flutter/Dart specific security issues
    
    // Check for insecure HTTP connections
    if (strstr(content, "http://") != NULL) {
        add_finding(results, SEVERITY_HIGH,
                   "Insecure HTTP connection detected",
                   file_path, line_number,
                   "Use HTTPS instead of HTTP for secure communications");
    }
    
    // Check for hardcoded API keys
    if (strstr(content, "sk-") != NULL || strstr(content, "api_key") != NULL) {
        add_finding(results, SEVERITY_CRITICAL,
                   "Hardcoded API key detected",
                   file_path, line_number,
                   "Move API keys to environment variables or secure storage");
    }
    
    // Check for SQL injection vulnerabilities
    if (strstr(content, "rawQuery") != NULL || strstr(content, "rawInsert") != NULL) {
        add_finding(results, SEVERITY_HIGH,
                   "Potential SQL injection vulnerability",
                   file_path, line_number,
                   "Use parameterized queries instead of raw SQL");
    }
    
    // Check for insecure SharedPreferences usage
    if (strstr(content, "SharedPreferences") != NULL && 
        (strstr(content, "password") != NULL || strstr(content, "token") != NULL)) {
        add_finding(results, SEVERITY_MEDIUM,
                   "Sensitive data stored in SharedPreferences",
                   file_path, line_number,
                   "Use encrypted storage for sensitive data");
    }
    
    // Check for insecure file operations
    if (strstr(content, "File(") != NULL && strstr(content, "writeAsString") != NULL) {
        add_finding(results, SEVERITY_MEDIUM,
                   "Insecure file write operation detected",
                   file_path, line_number,
                   "Validate file paths and implement proper access controls");
    }
    
    // Check for missing input validation
    if (strstr(content, "TextEditingController") != NULL && 
        !strstr(content, "validator") && !strstr(content, "validate")) {
        add_finding(results, SEVERITY_MEDIUM,
                   "Missing input validation",
                   file_path, line_number,
                   "Implement proper input validation and sanitization");
    }
    
    return 0;
}

int scan_cryptographic_issues(const char* target_path, const security_policy_t* policy, scan_results_t* results) {
    // Scan all source files in the target directory
    scan_directory_recursive(target_path, policy, results);
    
    return 0;
}
