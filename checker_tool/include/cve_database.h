#ifndef CVE_DATABASE_H
#define CVE_DATABASE_H

#include "yaml_parser.h"
#include "sdk_analyzer.h"

#define MAX_CVE_ENTRIES 1000
#define MAX_CVE_ID_LEN 32
#define MAX_CVE_DESCRIPTION 512
#define MAX_PACKAGE_NAME 128

typedef struct {
    char cve_id[MAX_CVE_ID_LEN];
    char package_name[MAX_PACKAGE_NAME];
    char version_constraint[64];
    severity_level_t severity;
    char description[MAX_CVE_DESCRIPTION];
    char published_date[32];
    char last_modified[32];
} cve_entry_t;

typedef struct {
    cve_entry_t entries[MAX_CVE_ENTRIES];
    int entry_count;
} cve_database_t;

// Function prototypes
int load_cve_database(const char* database_path, cve_database_t* database);
int check_package_cves(const char* package_name, const char* version, 
                      const cve_database_t* database, scan_results_t* results);
int check_flutter_cves(const char* pubspec_path, const cve_database_t* database, scan_results_t* results);
int check_nodejs_cves(const char* package_json_path, const cve_database_t* database, scan_results_t* results);
int check_python_cves(const char* requirements_path, const cve_database_t* database, scan_results_t* results);
int check_rust_cves(const char* cargo_path, const cve_database_t* database, scan_results_t* results);
int check_go_cves(const char* go_mod_path, const cve_database_t* database, scan_results_t* results);
int version_matches_constraint(const char* version, const char* constraint);
void cleanup_cve_database(cve_database_t* database);

#endif // CVE_DATABASE_H
