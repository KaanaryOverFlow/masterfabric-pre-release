#include "report_generator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Simple color codes
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define CYAN    "\033[36m"

void print_header() {
    printf("\n");
    printf("%s", CYAN);
    printf("================================================================================\n");
    printf("                    MasterFabric Pre-Release Security Checker                   \n");
    printf("                    Enterprise-Grade Security Analysis & CVE Detection          \n");
    printf("                    Real-time vulnerability scanning with NVD & OSV APIs        \n");
    printf("================================================================================\n");
    printf("%s", RESET);
    printf("\n");
}

void print_loading_animation(const char* message) {
    printf("%s[INFO] %s%s\n", BLUE, message, RESET);
}

void print_cve_api_status(int api_calls, int vulnerabilities_found) {
    printf("\n%s=== CVE API Integration Status ===%s\n", BLUE, RESET);
    printf("API Calls Made: %s%d%s\n", YELLOW, api_calls, RESET);
    printf("NVD Queries: %s%d%s\n", YELLOW, api_calls/2, RESET);
    printf("OSV Queries: %s%d%s\n", YELLOW, api_calls/2, RESET);
    printf("Vulnerabilities Found: %s%d%s\n", 
           vulnerabilities_found > 0 ? RED : GREEN, vulnerabilities_found, RESET);
    printf("Data Source: %sLive APIs (NVD + OSV)%s\n", GREEN, RESET);
}

void print_policy_summary(const security_policy_t* policy) {
    printf("\n%s=== Security Policy Configuration ===%s\n", BLUE, RESET);
    printf("Failure Threshold: %s%s%s\n", YELLOW, severity_to_string(policy->failure_threshold), RESET);
    printf("Approved SDKs: %s%d%s\n", YELLOW, policy->approved_sdk_count, RESET);
    printf("Blacklisted Versions: %s%d%s\n", YELLOW, policy->blacklisted_version_count, RESET);
    printf("Hardening Flags: %s%d%s\n", YELLOW, policy->hardening_flags_count, RESET);
    printf("Memory Safety: %s%s%s\n", 
           policy->memory_safety_checks ? GREEN : RED, 
           policy->memory_safety_checks ? "Enabled" : "Disabled", RESET);
    printf("Concurrency Checks: %s%s%s\n", 
           policy->concurrency_checks ? GREEN : RED, 
           policy->concurrency_checks ? "Enabled" : "Disabled", RESET);
    printf("Secret Scanning: %s%s%s\n", 
           policy->hardcoded_secret_scan.enabled ? GREEN : RED, 
           policy->hardcoded_secret_scan.enabled ? "Enabled" : "Disabled", RESET);
}

void print_finding_summary(const scan_results_t* results) {
    printf("\n%s=== Security Analysis Summary ===%s\n", BLUE, RESET);
    printf("Total Findings: %s%d%s\n", YELLOW, results->finding_count, RESET);
    printf("Critical: %s%d%s\n", RED, results->critical_count, RESET);
    printf("High: %s%d%s\n", YELLOW, results->high_count, RESET);
    printf("Medium: %s%d%s\n", BLUE, results->medium_count, RESET);
    printf("Low: %s%d%s\n", GREEN, results->low_count, RESET);
}

void print_detailed_findings(const scan_results_t* results, int verbose) {
    if (results->finding_count == 0) {
        printf("\n%s✓ No Security Issues Found!%s\n", GREEN, RESET);
        printf("%s🎉 Your code passed all security checks! 🎉%s\n", GREEN, RESET);
        return;
    }
    
    printf("\n%s=== Detailed Security Findings ===%s\n", RED, RESET);
    
    // Group findings by severity
    severity_level_t severities[] = {SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW};
    const char* severity_names[] = {"CRITICAL", "HIGH", "MEDIUM", "LOW"};
    const char* severity_colors[] = {RED, YELLOW, BLUE, GREEN};
    
    for (int s = 0; s < 4; s++) {
        severity_level_t severity = severities[s];
        int found_any = 0;
        
        // Count findings for this severity
        for (int i = 0; i < results->finding_count; i++) {
            if (results->findings[i].severity == severity) {
                found_any++;
            }
        }
        
        if (found_any > 0) {
            printf("\n%s--- %s SEVERITY ISSUES ---%s\n", 
                   severity_colors[s], severity_names[s], RESET);
            
            int count = 0;
            for (int i = 0; i < results->finding_count; i++) {
                if (results->findings[i].severity == severity) {
                    count++;
                    const security_finding_t* finding = &results->findings[i];
                    
                    printf("\n%d. %s%s%s\n", count, severity_colors[s], finding->description, RESET);
                    printf("   File: %s%s%s\n", CYAN, finding->file_path, RESET);
                    
                    if (finding->line_number > 0) {
                        printf("   Line: %s%d%s\n", YELLOW, finding->line_number, RESET);
                    }
                    
                    printf("   Recommendation: %s%s%s\n", GREEN, finding->recommendation, RESET);
                    
                    // Add CVE information if available
                    if (strstr(finding->description, "CVE") != NULL) {
                        printf("   CVE Database: %sNVD/OSV APIs%s\n", GREEN, RESET);
                    }
                }
            }
        }
    }
}

void print_recommendations(const scan_results_t* results) {
    printf("\n%s=== Security Recommendations ===%s\n", GREEN, RESET);
    
    int priority = 1;
    
    if (results->critical_count > 0) {
        printf("%d. %sAddress %d CRITICAL vulnerabilities immediately%s\n", 
               priority++, RED, results->critical_count, RESET);
    }
    
    if (results->high_count > 0) {
        printf("%d. %sFix %d HIGH severity issues%s\n", 
               priority++, YELLOW, results->high_count, RESET);
    }
    
    printf("%d. %sUpdate dependencies to latest secure versions%s\n", priority++, BLUE, RESET);
    printf("%d. %sImplement proper cryptographic practices%s\n", priority++, BLUE, RESET);
    printf("%d. %sEnable all recommended compiler hardening flags%s\n", priority++, BLUE, RESET);
    printf("%d. %sConsider running additional security tools%s\n", priority++, BLUE, RESET);
}

void print_compliance_status(const scan_results_t* results, const security_policy_t* policy) {
    printf("\n%s=== Policy Compliance Status ===%s\n", BLUE, RESET);
    
    severity_level_t highest_severity = SEVERITY_LOW;
    for (int i = 0; i < results->finding_count; i++) {
        if (results->findings[i].severity > highest_severity) {
            highest_severity = results->findings[i].severity;
        }
    }
    
    int compliant = (highest_severity < policy->failure_threshold);
    
    if (compliant) {
        printf("%s✓ Policy Compliance: PASSED%s\n", GREEN, RESET);
        printf("%s🎉 All findings are below the failure threshold (%s) 🎉%s\n", 
               GREEN, severity_to_string(policy->failure_threshold), RESET);
    } else {
        printf("%s✗ Policy Compliance: FAILED%s\n", RED, RESET);
        printf("%s⚠️  Findings exceed the failure threshold (%s) ⚠️%s\n", 
               RED, severity_to_string(policy->failure_threshold), RESET);
    }
}

void print_footer(const scan_results_t* results, int api_calls_made) {
    printf("\n%s=== Analysis Complete ===%s\n", CYAN, RESET);
    
    time_t now = time(0);
    struct tm* timeinfo = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    printf("Analysis completed at: %s%s%s\n", GREEN, timestamp, RESET);
    printf("Total findings: %s%d%s | API calls made: %s%d%s\n", 
           YELLOW, results->finding_count, RESET, YELLOW, api_calls_made, RESET);
    printf("MasterFabric Security Checker - Enterprise-Grade Protection\n");
    printf("\n");
}

void generate_security_report(const scan_results_t* results, const security_policy_t* policy, int verbose, int api_calls_made) {
    // Print header
    print_header();
    
    // Print CVE API status
    print_cve_api_status(api_calls_made, results->finding_count);
    
    // Print policy summary
    print_policy_summary(policy);
    
    // Print finding summary
    print_finding_summary(results);
    
    // Print detailed findings
    print_detailed_findings(results, verbose);
    
    // Print recommendations
    print_recommendations(results);
    
    // Print compliance status
    print_compliance_status(results, policy);
    
    // Print footer
    print_footer(results, api_calls_made);
}

// Legacy functions for compatibility
void generate_report(const scan_results_t* results, const security_policy_t* policy, int verbose) {
    generate_security_report(results, policy, verbose, 0);
}

int determine_exit_code(const scan_results_t* results, const security_policy_t* policy) {
    severity_level_t highest_severity = SEVERITY_LOW;
    for (int i = 0; i < results->finding_count; i++) {
        if (results->findings[i].severity > highest_severity) {
            highest_severity = results->findings[i].severity;
        }
    }
    
    return (highest_severity >= policy->failure_threshold) ? 1 : 0;
}