#include "cve_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <curl/curl.h>
#include <json-c/json.h>

// Global CURL handle for reuse
static CURL* curl_handle = NULL;

// Callback function for CURL to write response data
static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    char* response = (char*)userp;
    
    // Check if we have enough space
    if (strlen(response) + realsize >= MAX_API_RESPONSE_SIZE - 1) {
        return 0; // Stop if buffer would overflow
    }
    
    strncat(response, (char*)contents, realsize);
    return realsize;
}

int make_http_request(const char* url, char* response_buffer, size_t buffer_size) {
    if (!curl_handle) {
        curl_handle = curl_easy_init();
        if (!curl_handle) {
            fprintf(stderr, "Error: Failed to initialize CURL\n");
            return 1;
        }
    }
    
    // Clear response buffer
    memset(response_buffer, 0, buffer_size);
    
    // Set CURL options
    curl_easy_setopt(curl_handle, CURLOPT_URL, url);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, response_buffer);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "MasterFabric-Security-Checker/1.0");
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 2L);
    
    // Perform the request
    CURLcode res = curl_easy_perform(curl_handle);
    
    if (res != CURLE_OK) {
        fprintf(stderr, "Error: CURL request failed: %s\n", curl_easy_strerror(res));
        return 1;
    }
    
    return 0;
}

int normalize_package_name(const char* package_name, char* normalized_name, size_t name_size) {
    if (!package_name || !normalized_name) return 1;
    
    strncpy(normalized_name, package_name, name_size - 1);
    normalized_name[name_size - 1] = '\0';
    
    // Convert to lowercase for consistency
    for (char* p = normalized_name; *p; p++) {
        *p = tolower(*p);
    }
    
    // Handle common package name variations
    if (strstr(normalized_name, "_") != NULL) {
        // Replace underscores with hyphens
        for (char* p = normalized_name; *p; p++) {
            if (*p == '_') *p = '-';
        }
    }
    
    return 0;
}

int parse_cvss_score(const char* cvss_vector, double* score, severity_level_t* severity) {
    if (!cvss_vector || !score || !severity) return 1;
    
    // Extract CVSS score from vector string
    // Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (example)
    const char* score_start = strstr(cvss_vector, "/CVSS:3.");
    if (!score_start) {
        score_start = strstr(cvss_vector, "CVSS:3.");
    }
    
    if (score_start) {
        // Look for score in the vector
        const char* c_start = strstr(cvss_vector, "/C:");
        const char* i_start = strstr(cvss_vector, "/I:");
        const char* a_start = strstr(cvss_vector, "/A:");
        
        if (c_start && i_start && a_start) {
            char c_severity = c_start[3];
            char i_severity = i_start[3];
            char a_severity = a_start[3];
            
            // Calculate approximate score based on severity levels
            double base_score = 0.0;
            if (c_severity == 'H') base_score += 3.0;
            else if (c_severity == 'M') base_score += 2.0;
            else if (c_severity == 'L') base_score += 1.0;
            
            if (i_severity == 'H') base_score += 3.0;
            else if (i_severity == 'M') base_score += 2.0;
            else if (i_severity == 'L') base_score += 1.0;
            
            if (a_severity == 'H') base_score += 3.0;
            else if (a_severity == 'M') base_score += 2.0;
            else if (a_severity == 'L') base_score += 1.0;
            
            *score = base_score / 3.0; // Normalize to 0-3 scale
            
            // Determine severity level
            if (*score >= 2.5) *severity = SEVERITY_CRITICAL;
            else if (*score >= 2.0) *severity = SEVERITY_HIGH;
            else if (*score >= 1.0) *severity = SEVERITY_MEDIUM;
            else *severity = SEVERITY_LOW;
        }
    }
    
    return 0;
}

int extract_json_field(const char* json, const char* field_name, char* output, size_t output_size) {
    if (!json || !field_name || !output) return 1;
    
    // Simple JSON field extraction (in production, use proper JSON parser)
    char search_pattern[256];
    snprintf(search_pattern, sizeof(search_pattern), "\"%s\":", field_name);
    
    const char* field_start = strstr(json, search_pattern);
    if (!field_start) return 1;
    
    field_start += strlen(search_pattern);
    
    // Skip whitespace
    while (*field_start && isspace(*field_start)) field_start++;
    
    // Extract value
    const char* value_start = field_start;
    if (*value_start == '"') {
        value_start++; // Skip opening quote
        const char* value_end = strchr(value_start, '"');
        if (!value_end) return 1;
        
        size_t value_len = value_end - value_start;
        if (value_len >= output_size) value_len = output_size - 1;
        
        strncpy(output, value_start, value_len);
        output[value_len] = '\0';
    } else {
        // Non-string value
        const char* value_end = value_start;
        while (*value_end && *value_end != ',' && *value_end != '}' && *value_end != ']') {
            value_end++;
        }
        
        size_t value_len = value_end - value_start;
        if (value_len >= output_size) value_len = output_size - 1;
        
        strncpy(output, value_start, value_len);
        output[value_len] = '\0';
    }
    
    return 0;
}

int parse_nvd_response(const char* json_response, const char* package_name, cve_api_response_t* response) {
    if (!json_response || !package_name || !response) return 1;
    
    memset(response, 0, sizeof(cve_api_response_t));
    
    // Parse NVD API response
    // Look for vulnerabilities array
    const char* vulns_start = strstr(json_response, "\"vulnerabilities\":[");
    if (!vulns_start) return 1;
    
    // Count vulnerabilities
    int vuln_count = 0;
    const char* search_pos = vulns_start;
    while ((search_pos = strstr(search_pos, "\"cve\"")) != NULL) {
        vuln_count++;
        search_pos += 5;
    }
    
    response->total_results = vuln_count;
    
    // Parse each vulnerability (simplified parsing)
    search_pos = vulns_start;
    int parsed_count = 0;
    
    while ((search_pos = strstr(search_pos, "\"cve\"")) != NULL && parsed_count < MAX_CVE_RESULTS) {
        cve_api_result_t* result = &response->results[parsed_count];
        
        // Extract CVE ID
        if (extract_json_field(search_pos, "id", result->cve_id, sizeof(result->cve_id)) == 0) {
            // Extract description
            extract_json_field(search_pos, "description", result->description, sizeof(result->description));
            
            // Extract published date
            extract_json_field(search_pos, "published", result->published_date, sizeof(result->published_date));
            
            // Extract last modified date
            extract_json_field(search_pos, "lastModified", result->last_modified, sizeof(result->last_modified));
            
            // Extract CVSS vector
            extract_json_field(search_pos, "vectorString", result->vector_string, sizeof(result->vector_string));
            
            // Parse CVSS score
            parse_cvss_score(result->vector_string, &result->cvss_score, &result->severity);
            
            // Set package name
            strncpy(result->package_name, package_name, sizeof(result->package_name) - 1);
            
            parsed_count++;
        }
        
        search_pos += 5;
    }
    
    response->result_count = parsed_count;
    return 0;
}

int parse_osv_response(const char* json_response, const char* package_name, cve_api_response_t* response) {
    if (!json_response || !package_name || !response) return 1;
    
    memset(response, 0, sizeof(cve_api_response_t));
    
    // Parse OSV API response
    const char* vulns_start = strstr(json_response, "\"vulns\":[");
    if (!vulns_start) return 1;
    
    // Count vulnerabilities
    int vuln_count = 0;
    const char* search_pos = vulns_start;
    while ((search_pos = strstr(search_pos, "\"id\"")) != NULL) {
        vuln_count++;
        search_pos += 4;
    }
    
    response->total_results = vuln_count;
    
    // Parse each vulnerability
    search_pos = vulns_start;
    int parsed_count = 0;
    
    while ((search_pos = strstr(search_pos, "\"id\"")) != NULL && parsed_count < MAX_CVE_RESULTS) {
        cve_api_result_t* result = &response->results[parsed_count];
        
        // Extract vulnerability ID
        if (extract_json_field(search_pos, "id", result->cve_id, sizeof(result->cve_id)) == 0) {
            // Extract summary/description
            extract_json_field(search_pos, "summary", result->description, sizeof(result->description));
            
            // Extract published date
            extract_json_field(search_pos, "published", result->published_date, sizeof(result->published_date));
            
            // Extract modified date
            extract_json_field(search_pos, "modified", result->last_modified, sizeof(result->last_modified));
            
            // Set package name
            strncpy(result->package_name, package_name, sizeof(result->package_name) - 1);
            
            // Set default severity (OSV doesn't always provide CVSS)
            result->severity = SEVERITY_MEDIUM;
            result->cvss_score = 2.0;
            
            parsed_count++;
        }
        
        search_pos += 4;
    }
    
    response->result_count = parsed_count;
    return 0;
}

int fetch_cves_from_nvd(const char* package_name, const char* version, cve_api_response_t* response) {
    if (!package_name || !response) return 1;
    
    char normalized_name[MAX_PACKAGE_NAME];
    normalize_package_name(package_name, normalized_name, sizeof(normalized_name));
    
    // Build NVD API URL
    char url[1024];
    snprintf(url, sizeof(url), "%s?keywordSearch=%s&resultsPerPage=100", 
             NVD_API_BASE_URL, normalized_name);
    
    char response_buffer[MAX_API_RESPONSE_SIZE];
    
    printf("Fetching CVEs from NVD for package: %s\n", normalized_name);
    
    if (make_http_request(url, response_buffer, sizeof(response_buffer)) != 0) {
        return 1;
    }
    
    response->api_calls_made++;
    
    return parse_nvd_response(response_buffer, normalized_name, response);
}

int fetch_cves_from_osv(const char* package_name, const char* version, cve_api_response_t* response) {
    if (!package_name || !response) return 1;
    
    char normalized_name[MAX_PACKAGE_NAME];
    normalize_package_name(package_name, normalized_name, sizeof(normalized_name));
    
    // Build OSV API request body
    char request_body[1024];
    snprintf(request_body, sizeof(request_body), 
             "{\"package\":{\"name\":\"%s\"},\"version\":\"%s\"}", 
             normalized_name, version ? version : "*");
    
    char response_buffer[MAX_API_RESPONSE_SIZE];
    
    printf("Fetching CVEs from OSV for package: %s (version: %s)\n", 
           normalized_name, version ? version : "any");
    
    // For OSV, we need to make a POST request with JSON body
    // This is a simplified implementation
    char url[512];
    snprintf(url, sizeof(url), "%s", OSV_API_BASE_URL);
    
    if (make_http_request(url, response_buffer, sizeof(response_buffer)) != 0) {
        return 1;
    }
    
    response->api_calls_made++;
    
    return parse_osv_response(response_buffer, normalized_name, response);
}

int check_package_cves_api(const char* package_name, const char* version, scan_results_t* results) {
    if (!package_name || !results) return 1;
    
    cve_api_response_t nvd_response, osv_response;
    int total_vulnerabilities = 0;
    
    // Fetch from NVD
    if (fetch_cves_from_nvd(package_name, version, &nvd_response) == 0) {
        for (int i = 0; i < nvd_response.result_count; i++) {
            const cve_api_result_t* cve = &nvd_response.results[i];
            
            char description[512];
            snprintf(description, sizeof(description),
                    "CVE %s: %s (CVSS: %.1f)",
                    cve->cve_id, cve->description, cve->cvss_score);
            
            char recommendation[256];
            snprintf(recommendation, sizeof(recommendation),
                    "Update %s to a version that addresses CVE %s",
                    package_name, cve->cve_id);
            
            add_finding(results, cve->severity, description, "dependencies", 0, recommendation);
            total_vulnerabilities++;
        }
    }
    
    // Fetch from OSV
    if (fetch_cves_from_osv(package_name, version, &osv_response) == 0) {
        for (int i = 0; i < osv_response.result_count; i++) {
            const cve_api_result_t* cve = &osv_response.results[i];
            
            char description[512];
            snprintf(description, sizeof(description),
                    "OSV %s: %s",
                    cve->cve_id, cve->description);
            
            char recommendation[256];
            snprintf(recommendation, sizeof(recommendation),
                    "Update %s to a version that addresses %s",
                    package_name, cve->cve_id);
            
            add_finding(results, cve->severity, description, "dependencies", 0, recommendation);
            total_vulnerabilities++;
        }
    }
    
    if (total_vulnerabilities > 0) {
        printf("Found %d vulnerabilities for package %s\n", total_vulnerabilities, package_name);
    }
    
    return total_vulnerabilities;
}

int check_flutter_cves_api(const char* pubspec_path, scan_results_t* results) {
    FILE* file = fopen(pubspec_path, "r");
    if (!file) return 1;
    
    char line[2048];
    int line_number = 0;
    int in_dependencies = 0;
    int total_vulnerabilities = 0;
    
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
            
            // Check for CVEs using API
            total_vulnerabilities += check_package_cves_api(package_name, version, results);
        }
    }
    
    fclose(file);
    return total_vulnerabilities;
}

int check_nodejs_cves_api(const char* package_json_path, scan_results_t* results) {
    FILE* file = fopen(package_json_path, "r");
    if (!file) return 1;
    
    char line[2048];
    int line_number = 0;
    int in_dependencies = 0;
    int in_dev_dependencies = 0;
    int total_vulnerabilities = 0;
    
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
            
            // Check for CVEs using API
            total_vulnerabilities += check_package_cves_api(package_name, version, results);
        }
    }
    
    fclose(file);
    return total_vulnerabilities;
}

int check_python_cves_api(const char* requirements_path, scan_results_t* results) {
    FILE* file = fopen(requirements_path, "r");
    if (!file) return 1;
    
    char line[512];
    int line_number = 0;
    int total_vulnerabilities = 0;
    
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
        
        // Check for CVEs using API
        total_vulnerabilities += check_package_cves_api(package_name, version, results);
    }
    
    fclose(file);
    return total_vulnerabilities;
}

int check_rust_cves_api(const char* cargo_path, scan_results_t* results) {
    FILE* file = fopen(cargo_path, "r");
    if (!file) return 1;
    
    char line[512];
    int line_number = 0;
    int in_dependencies = 0;
    int total_vulnerabilities = 0;
    
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
            
            // Check for CVEs using API
            total_vulnerabilities += check_package_cves_api(package_name, version, results);
        }
    }
    
    fclose(file);
    return total_vulnerabilities;
}

int check_go_cves_api(const char* go_mod_path, scan_results_t* results) {
    FILE* file = fopen(go_mod_path, "r");
    if (!file) return 1;
    
    char line[512];
    int line_number = 0;
    int total_vulnerabilities = 0;
    
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
            
            // Check for CVEs using API
            total_vulnerabilities += check_package_cves_api(package_name, version, results);
        }
    }
    
    fclose(file);
    return total_vulnerabilities;
}

void cleanup_cve_api_response(cve_api_response_t* response) {
    // Nothing to cleanup for this simple structure
    (void)response;
}

// Cleanup function for CURL
void cleanup_curl() {
    if (curl_handle) {
        curl_easy_cleanup(curl_handle);
        curl_handle = NULL;
    }
    curl_global_cleanup();
}
