#include "cve_database.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Known CVE database for demonstration purposes
// In a real implementation, this would be loaded from a comprehensive CVE database
static cve_entry_t known_cves[] = {
    // Flutter/Dart CVEs
    {
        .cve_id = "CVE-2023-1234",
        .package_name = "http",
        .version_constraint = "<0.13.0",
        .severity = SEVERITY_HIGH,
        .description = "HTTP package vulnerability allows request smuggling",
        .published_date = "2023-01-15",
        .last_modified = "2023-01-20"
    },
    {
        .cve_id = "CVE-2023-1235",
        .package_name = "crypto",
        .version_constraint = "<3.0.0",
        .severity = SEVERITY_CRITICAL,
        .description = "Crypto package uses weak encryption algorithms",
        .published_date = "2023-02-01",
        .last_modified = "2023-02-05"
    },
    {
        .cve_id = "CVE-2023-1236",
        .package_name = "shared_preferences",
        .version_constraint = "<2.0.0",
        .severity = SEVERITY_HIGH,
        .description = "SharedPreferences stores data in plain text",
        .published_date = "2023-02-10",
        .last_modified = "2023-02-15"
    },
    {
        .cve_id = "CVE-2023-1237",
        .package_name = "sqflite",
        .version_constraint = "<2.0.0",
        .severity = SEVERITY_HIGH,
        .description = "SQLite database vulnerable to injection attacks",
        .published_date = "2023-02-20",
        .last_modified = "2023-02-25"
    },
    {
        .cve_id = "CVE-2023-1238",
        .package_name = "dio",
        .version_constraint = "<4.0.0",
        .severity = SEVERITY_MEDIUM,
        .description = "Dio HTTP client has certificate validation issues",
        .published_date = "2023-03-01",
        .last_modified = "2023-03-05"
    },
    {
        .cve_id = "CVE-2023-1239",
        .package_name = "uuid",
        .version_constraint = "<3.0.0",
        .severity = SEVERITY_MEDIUM,
        .description = "UUID generation uses predictable random numbers",
        .published_date = "2023-03-10",
        .last_modified = "2023-03-15"
    },
    
    // Node.js/JavaScript CVEs
    {
        .cve_id = "CVE-2021-23337",
        .package_name = "lodash",
        .version_constraint = "<4.17.21",
        .severity = SEVERITY_HIGH,
        .description = "Command injection vulnerability in lodash",
        .published_date = "2021-03-15",
        .last_modified = "2021-03-20"
    },
    {
        .cve_id = "CVE-2022-0155",
        .package_name = "node-fetch",
        .version_constraint = "<2.6.7",
        .severity = SEVERITY_HIGH,
        .description = "node-fetch vulnerable to request smuggling",
        .published_date = "2022-01-10",
        .last_modified = "2022-01-15"
    },
    {
        .cve_id = "CVE-2022-23529",
        .package_name = "jsonwebtoken",
        .version_constraint = "<9.0.0",
        .severity = SEVERITY_CRITICAL,
        .description = "jsonwebtoken vulnerable to algorithm confusion",
        .published_date = "2022-12-21",
        .last_modified = "2022-12-25"
    },
    {
        .cve_id = "CVE-2022-23530",
        .package_name = "bcrypt",
        .version_constraint = "<5.0.0",
        .severity = SEVERITY_HIGH,
        .description = "bcrypt vulnerable to timing attacks",
        .published_date = "2022-12-21",
        .last_modified = "2022-12-25"
    },
    
    // Python CVEs
    {
        .cve_id = "CVE-2023-32681",
        .package_name = "requests",
        .version_constraint = "<2.31.0",
        .severity = SEVERITY_MEDIUM,
        .description = "requests library vulnerable to proxy header injection",
        .published_date = "2023-06-01",
        .last_modified = "2023-06-05"
    },
    
    // Rust CVEs
    {
        .cve_id = "CVE-2023-25663",
        .package_name = "serde",
        .version_constraint = "<1.0.160",
        .severity = SEVERITY_MEDIUM,
        .description = "serde deserialization vulnerability",
        .published_date = "2023-03-15",
        .last_modified = "2023-03-20"
    }
};

static const int known_cve_count = sizeof(known_cves) / sizeof(known_cves[0]);

int load_cve_database(const char* database_path, cve_database_t* database) {
    // For demonstration, we'll use the static CVE database
    // In a real implementation, this would load from a JSON/CSV file or API
    memset(database, 0, sizeof(cve_database_t));
    
    for (int i = 0; i < known_cve_count && i < MAX_CVE_ENTRIES; i++) {
        database->entries[i] = known_cves[i];
        database->entry_count++;
    }
    
    return 0;
}

int version_matches_constraint(const char* version, const char* constraint) {
    if (!version || !constraint) return 0;
    
    // Simple version comparison for demonstration
    // In a real implementation, use proper semantic versioning
    
    if (constraint[0] == '<') {
        // Less than constraint
        const char* constraint_version = constraint + 1;
        if (constraint_version[0] == '=') {
            constraint_version++; // Handle <=
        }
        return strcmp(version, constraint_version) < 0;
    } else if (constraint[0] == '>') {
        // Greater than constraint
        const char* constraint_version = constraint + 1;
        if (constraint_version[0] == '=') {
            constraint_version++; // Handle >=
        }
        return strcmp(version, constraint_version) > 0;
    } else if (constraint[0] == '=') {
        // Exact match
        const char* constraint_version = constraint + 1;
        return strcmp(version, constraint_version) == 0;
    }
    
    return 0;
}

int check_package_cves(const char* package_name, const char* version, 
                      const cve_database_t* database, scan_results_t* results) {
    int found_vulnerabilities = 0;
    
    for (int i = 0; i < database->entry_count; i++) {
        const cve_entry_t* cve = &database->entries[i];
        
        if (strcmp(cve->package_name, package_name) == 0) {
            if (version_matches_constraint(version, cve->version_constraint)) {
                char description[MAX_FINDING_DESC];
                snprintf(description, sizeof(description),
                        "CVE %s: %s (Version: %s, Constraint: %s)",
                        cve->cve_id, cve->description, version, cve->version_constraint);
                
                char recommendation[MAX_FINDING_DESC];
                snprintf(recommendation, sizeof(recommendation),
                        "Update %s to a version that does not match constraint: %s",
                        package_name, cve->version_constraint);
                
                add_finding(results, cve->severity, description, "dependencies", 0, recommendation);
                found_vulnerabilities++;
            }
        }
    }
    
    return found_vulnerabilities;
}

int check_flutter_cves(const char* pubspec_path, const cve_database_t* database, scan_results_t* results) {
    FILE* file = fopen(pubspec_path, "r");
    if (!file) return 1;
    
    char line[2048];
    int line_number = 0;
    int in_dependencies = 0;
    int found_vulnerabilities = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_number++;
        
        // Remove whitespace
        char* trimmed = line;
        while (*trimmed && isspace(*trimmed)) trimmed++;
        
        // Check for dependencies section
        if (strstr(trimmed, "dependencies:") != NULL) {
            in_dependencies = 1;
            continue;
        } else if (trimmed[0] != ' ' && trimmed[0] != '\t' && in_dependencies) {
            in_dependencies = 0;
            continue;
        }
        
        // Parse dependency entries
        if (in_dependencies && strchr(trimmed, ':') != NULL) {
            char* colon = strchr(trimmed, ':');
            if (!colon) continue;
            
            char package_name[256];
            size_t name_len = colon - trimmed;
            if (name_len >= sizeof(package_name)) continue;
            
            strncpy(package_name, trimmed, name_len);
            package_name[name_len] = '\0';
            
            // Remove whitespace
            char* trimmed_name = package_name;
            while (*trimmed_name && isspace(*trimmed_name)) trimmed_name++;
            strcpy(package_name, trimmed_name);
            
            // Extract version
            const char* version_start = colon + 1;
            while (*version_start && isspace(*version_start)) version_start++;
            
            char version[256];
            strncpy(version, version_start, sizeof(version) - 1);
            version[sizeof(version) - 1] = '\0';
            
            // Remove newline and clean version
            char* newline = strchr(version, '\n');
            if (newline) *newline = '\0';
            
            // Remove version prefix (^, ~, etc.)
            if (version[0] == '^' || version[0] == '~' || version[0] == '>') {
                memmove(version, version + 1, strlen(version));
            }
            
            // Check for CVEs
            found_vulnerabilities += check_package_cves(package_name, version, database, results);
        }
    }
    
    fclose(file);
    return found_vulnerabilities;
}

int check_nodejs_cves(const char* package_json_path, const cve_database_t* database, scan_results_t* results) {
    FILE* file = fopen(package_json_path, "r");
    if (!file) return 1;
    
    char line[2048];
    int line_number = 0;
    int in_dependencies = 0;
    int in_dev_dependencies = 0;
    int found_vulnerabilities = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_number++;
        
        // Remove whitespace
        char* trimmed = line;
        while (*trimmed && isspace(*trimmed)) trimmed++;
        
        // Check for dependencies sections
        if (strstr(trimmed, "\"dependencies\"") != NULL) {
            in_dependencies = 1;
            in_dev_dependencies = 0;
            continue;
        } else if (strstr(trimmed, "\"devDependencies\"") != NULL) {
            in_dependencies = 0;
            in_dev_dependencies = 1;
            continue;
        } else if (trimmed[0] == '}' && (in_dependencies || in_dev_dependencies)) {
            in_dependencies = 0;
            in_dev_dependencies = 0;
            continue;
        }
        
        // Parse dependency entries
        if ((in_dependencies || in_dev_dependencies) && strstr(trimmed, "\"") != NULL) {
            // Extract package name and version
            char* name_start = strchr(trimmed, '"');
            if (!name_start) continue;
            name_start++;
            
            char* name_end = strchr(name_start, '"');
            if (!name_end) continue;
            
            char package_name[256];
            size_t name_len = name_end - name_start;
            if (name_len >= sizeof(package_name)) continue;
            
            strncpy(package_name, name_start, name_len);
            package_name[name_len] = '\0';
            
            // Find version
            char* version_start = strchr(name_end, '"');
            if (!version_start) continue;
            version_start++;
            
            char* version_end = strchr(version_start, '"');
            if (!version_end) continue;
            
            char version[256];
            size_t version_len = version_end - version_start;
            if (version_len >= sizeof(version)) continue;
            
            strncpy(version, version_start, version_len);
            version[version_len] = '\0';
            
            // Check for CVEs
            found_vulnerabilities += check_package_cves(package_name, version, database, results);
        }
    }
    
    fclose(file);
    return found_vulnerabilities;
}

int check_python_cves(const char* requirements_path, const cve_database_t* database, scan_results_t* results) {
    FILE* file = fopen(requirements_path, "r");
    if (!file) return 1;
    
    char line[512];
    int line_number = 0;
    int found_vulnerabilities = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_number++;
        
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') continue;
        
        // Parse package==version format
        char* equals = strchr(line, '=');
        if (!equals) continue;
        
        char package_name[256];
        size_t name_len = equals - line;
        if (name_len >= sizeof(package_name)) continue;
        
        strncpy(package_name, line, name_len);
        package_name[name_len] = '\0';
        
        // Remove whitespace
        char* trimmed = package_name;
        while (*trimmed && isspace(*trimmed)) trimmed++;
        strcpy(package_name, trimmed);
        
        // Extract version
        const char* version_start = equals + 1;
        while (*version_start && isspace(*version_start)) version_start++;
        
        char version[256];
        strncpy(version, version_start, sizeof(version) - 1);
        version[sizeof(version) - 1] = '\0';
        
        // Remove newline
        char* newline = strchr(version, '\n');
        if (newline) *newline = '\0';
        
        // Check for CVEs
        found_vulnerabilities += check_package_cves(package_name, version, database, results);
    }
    
    fclose(file);
    return found_vulnerabilities;
}

int check_rust_cves(const char* cargo_path, const cve_database_t* database, scan_results_t* results) {
    FILE* file = fopen(cargo_path, "r");
    if (!file) return 1;
    
    char line[512];
    int line_number = 0;
    int in_dependencies = 0;
    int found_vulnerabilities = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_number++;
        
        // Remove whitespace
        char* trimmed = line;
        while (*trimmed && isspace(*trimmed)) trimmed++;
        
        // Check for dependencies section
        if (strstr(trimmed, "[dependencies]") != NULL) {
            in_dependencies = 1;
            continue;
        } else if (trimmed[0] == '[' && in_dependencies) {
            in_dependencies = 0;
            continue;
        }
        
        // Parse dependency entries
        if (in_dependencies && strchr(trimmed, '=') != NULL) {
            char* equals = strchr(trimmed, '=');
            if (!equals) continue;
            
            char package_name[256];
            size_t name_len = equals - trimmed;
            if (name_len >= sizeof(package_name)) continue;
            
            strncpy(package_name, trimmed, name_len);
            package_name[name_len] = '\0';
            
            // Extract version
            const char* version_start = equals + 1;
            while (*version_start && isspace(*version_start)) version_start++;
            
            char version[256];
            strncpy(version, version_start, sizeof(version) - 1);
            version[sizeof(version) - 1] = '\0';
            
            // Remove quotes and newline
            if (version[0] == '"') {
                memmove(version, version + 1, strlen(version));
                char* end_quote = strrchr(version, '"');
                if (end_quote) *end_quote = '\0';
            }
            
            char* newline = strchr(version, '\n');
            if (newline) *newline = '\0';
            
            // Check for CVEs
            found_vulnerabilities += check_package_cves(package_name, version, database, results);
        }
    }
    
    fclose(file);
    return found_vulnerabilities;
}

int check_go_cves(const char* go_mod_path, const cve_database_t* database, scan_results_t* results) {
    FILE* file = fopen(go_mod_path, "r");
    if (!file) return 1;
    
    char line[512];
    int line_number = 0;
    int found_vulnerabilities = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_number++;
        
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') continue;
        
        // Parse require statements
        if (strstr(line, "require") != NULL) {
            // Extract package name and version
            char* space1 = strchr(line, ' ');
            if (!space1) continue;
            space1++;
            
            char* space2 = strchr(space1, ' ');
            if (!space2) continue;
            
            char package_name[256];
            size_t name_len = space2 - space1;
            if (name_len >= sizeof(package_name)) continue;
            
            strncpy(package_name, space1, name_len);
            package_name[name_len] = '\0';
            
            // Extract version
            const char* version_start = space2 + 1;
            while (*version_start && isspace(*version_start)) version_start++;
            
            char version[256];
            strncpy(version, version_start, sizeof(version) - 1);
            version[sizeof(version) - 1] = '\0';
            
            // Remove newline
            char* newline = strchr(version, '\n');
            if (newline) *newline = '\0';
            
            // Check for CVEs
            found_vulnerabilities += check_package_cves(package_name, version, database, results);
        }
    }
    
    fclose(file);
    return found_vulnerabilities;
}

void cleanup_cve_database(cve_database_t* database) {
    // Nothing to cleanup for this simple structure
    (void)database;
}
