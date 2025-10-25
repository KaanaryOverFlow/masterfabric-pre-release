#ifndef CVE_API_H
#define CVE_API_H

#include "yaml_parser.h"
#include "sdk_analyzer.h"

#define NVD_API_BASE_URL "https://services.nvd.nist.gov/rest/json/cves/2.0"
#define OSV_API_BASE_URL "https://api.osv.dev/v1/query"
#define MAX_API_RESPONSE_SIZE 1048576  // 1MB
#define MAX_CVE_RESULTS 1000
#define MAX_PACKAGE_NAME 128
#define MAX_VERSION_LEN 64

typedef struct {
    char cve_id[32];
    char package_name[MAX_PACKAGE_NAME];
    char version_constraint[128];
    severity_level_t severity;
    char description[512];
    char published_date[32];
    char last_modified[32];
    double cvss_score;
    char vector_string[128];
} cve_api_result_t;

typedef struct {
    cve_api_result_t results[MAX_CVE_RESULTS];
    int result_count;
    int total_results;
    int api_calls_made;
} cve_api_response_t;

// Function prototypes
int fetch_cves_from_nvd(const char* package_name, const char* version, cve_api_response_t* response);
int fetch_cves_from_osv(const char* package_name, const char* version, cve_api_response_t* response);
int check_package_cves_api(const char* package_name, const char* version, scan_results_t* results);
int check_flutter_cves_api(const char* pubspec_path, scan_results_t* results);
int check_nodejs_cves_api(const char* package_json_path, scan_results_t* results);
int check_python_cves_api(const char* requirements_path, scan_results_t* results);
int check_rust_cves_api(const char* cargo_path, scan_results_t* results);
int check_go_cves_api(const char* go_mod_path, scan_results_t* results);

// HTTP and JSON parsing functions
int make_http_request(const char* url, char* response_buffer, size_t buffer_size);
int parse_nvd_response(const char* json_response, const char* package_name, cve_api_response_t* response);
int parse_osv_response(const char* json_response, const char* package_name, cve_api_response_t* response);
int extract_json_field(const char* json, const char* field_name, char* output, size_t output_size);
int parse_cvss_score(const char* cvss_vector, double* score, severity_level_t* severity);

// Utility functions
int normalize_package_name(const char* package_name, char* normalized_name, size_t name_size);
int version_matches_cve(const char* version, const char* cve_version_range);
void cleanup_cve_api_response(cve_api_response_t* response);

#endif // CVE_API_H
