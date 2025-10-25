# Real-Time CVE API Integration

## Overview

The MasterFabric Pre-Release Security Checker now includes **real-time CVE API integration** that fetches live vulnerability data from official sources instead of using static databases. This provides the most up-to-date security information for comprehensive vulnerability analysis.

## 🚀 Real-Time CVE Sources

### 1. National Vulnerability Database (NVD) API
- **URL**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Coverage**: Official CVE database maintained by NIST
- **Data**: CVE IDs, descriptions, CVSS scores, severity levels
- **Update Frequency**: Real-time updates as new vulnerabilities are discovered

### 2. Open Source Vulnerabilities (OSV) API
- **URL**: `https://api.osv.dev/v1/query`
- **Coverage**: Open source package vulnerabilities
- **Data**: Package-specific vulnerabilities, version ranges, descriptions
- **Update Frequency**: Real-time updates from multiple sources

## 🔧 Technical Implementation

### HTTP Client Integration
```c
// CURL-based HTTP client for API requests
static CURL* curl_handle = NULL;

int make_http_request(const char* url, char* response_buffer, size_t buffer_size) {
    // Initialize CURL with SSL verification
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 30L);
    
    // Perform secure HTTPS request
    CURLcode res = curl_easy_perform(curl_handle);
    return (res == CURLE_OK) ? 0 : 1;
}
```

### JSON Response Parsing
```c
// Real-time JSON parsing for CVE data
int parse_nvd_response(const char* json_response, const char* package_name, cve_api_response_t* response) {
    // Extract CVE IDs, descriptions, CVSS scores
    // Parse vulnerability metadata
    // Calculate severity levels from CVSS vectors
}
```

### Multi-Platform Package Analysis
```c
// Flutter/Dart package analysis
int check_flutter_cves_api(const char* pubspec_path, scan_results_t* results) {
    // Parse pubspec.yaml dependencies
    // Query NVD and OSV APIs for each package
    // Return real-time vulnerability data
}

// Node.js package analysis
int check_nodejs_cves_api(const char* package_json_path, scan_results_t* results) {
    // Parse package.json dependencies
    // Query APIs for npm package vulnerabilities
    // Return live CVE information
}
```

## 📊 API Response Structure

### NVD API Response
```json
{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2023-1234",
        "descriptions": [
          {
            "lang": "en",
            "value": "HTTP package vulnerability allows request smuggling"
          }
        ],
        "published": "2023-01-15T10:00:00.000",
        "lastModified": "2023-01-20T15:30:00.000",
        "metrics": {
          "cvssMetricV31": [
            {
              "cvssData": {
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 9.8
              }
            }
          ]
        }
      }
    }
  ]
}
```

### OSV API Response
```json
{
  "vulns": [
    {
      "id": "OSV-2023-1234",
      "summary": "Package vulnerability in http library",
      "published": "2023-01-15T10:00:00Z",
      "modified": "2023-01-20T15:30:00Z",
      "affected": [
        {
          "package": {
            "name": "http",
            "ecosystem": "Pub"
          },
          "ranges": [
            {
              "type": "ECOSYSTEM",
              "events": [
                {"introduced": "0.0.0"},
                {"fixed": "0.13.0"}
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

## 🎯 Real-Time Analysis Features

### 1. Live Vulnerability Detection
- **Real-time CVE lookup** for each dependency
- **Version-specific vulnerability matching**
- **CVSS score calculation** and severity classification
- **Multi-source vulnerability aggregation**

### 2. Comprehensive Package Coverage
- **Flutter/Dart**: `pubspec.yaml` analysis
- **Node.js**: `package.json` analysis  
- **Python**: `requirements.txt` analysis
- **Rust**: `Cargo.toml` analysis
- **Go**: `go.mod` analysis

### 3. Advanced Vulnerability Matching
```c
// Version constraint matching
int version_matches_cve(const char* version, const char* cve_version_range) {
    // Parse semantic versioning
    // Match against CVE version ranges
    // Handle complex version constraints
}

// CVSS score parsing
int parse_cvss_score(const char* cvss_vector, double* score, severity_level_t* severity) {
    // Extract CVSS components
    // Calculate base score
    // Determine severity level
}
```

## 📈 Performance Optimizations

### 1. Connection Reuse
- **Persistent CURL handles** for multiple API calls
- **Connection pooling** to reduce latency
- **HTTP/2 support** for improved performance

### 2. Response Caching
- **In-memory caching** of API responses
- **Rate limiting** to respect API quotas
- **Batch processing** of multiple packages

### 3. Error Handling
- **Network timeout handling** (30 seconds)
- **SSL certificate verification**
- **Graceful degradation** when APIs are unavailable

## 🔍 Usage Examples

### Flutter App Analysis
```bash
./bin/masterfabric-prerelease --check ../cases/demo_flutter_vulnerable_app --verbose
```

**Output:**
```
Starting real-time CVE analysis using NVD and OSV APIs...
Checking Flutter dependencies for CVEs...
Fetching CVEs from NVD for package: http
Fetching CVEs from OSV for package: http (version: 0.12.2)
Found 3 vulnerabilities for package http
Found 2 CVE vulnerabilities in Flutter dependencies via API
```

### Node.js App Analysis
```bash
./bin/masterfabric-prerelease --check ../cases/demo_vulnerable_app --verbose
```

**Output:**
```
Starting real-time CVE analysis using NVD and OSV APIs...
Checking Node.js dependencies for CVEs...
Fetching CVEs from NVD for package: lodash
Fetching CVEs from OSV for package: lodash (version: 4.17.20)
Found 1 vulnerabilities for package lodash
Found 1 CVE vulnerabilities in Node.js dependencies via API
```

## 🛡️ Security Features

### 1. Secure API Communication
- **HTTPS-only** communication with APIs
- **SSL certificate verification**
- **User-Agent identification** for API requests
- **Rate limiting** to prevent abuse

### 2. Data Validation
- **JSON response validation**
- **Input sanitization** for package names
- **Version format validation**
- **CVE ID format verification**

### 3. Error Recovery
- **Network failure handling**
- **API timeout recovery**
- **Partial result processing**
- **Fallback to static analysis**

## 📊 Real-Time Results

### Flutter Demo App Analysis
```
Security Analysis Summary:
  Total Findings: 25
  Critical: 3      (Hardcoded API keys)
  High: 12         (Weak crypto, HTTP, SQL injection)
  Medium: 9        (Weak random, missing validation)
  Low: 1           (Missing cppcheck)

Real-time CVE Analysis:
  API Calls Made: 6
  NVD Queries: 3
  OSV Queries: 3
  Vulnerabilities Found: 0 (packages up to date)
```

### Next.js Demo App Analysis
```
Security Analysis Summary:
  Total Findings: 7
  Critical: 0
  High: 5          (Weak crypto, HTTP)
  Medium: 1        (Weak random)
  Low: 1           (Missing cppcheck)

Real-time CVE Analysis:
  API Calls Made: 4
  NVD Queries: 2
  OSV Queries: 2
  Vulnerabilities Found: 2 (lodash, node-fetch)
```

## 🔧 Configuration

### API Endpoints
```c
#define NVD_API_BASE_URL "https://services.nvd.nist.gov/rest/json/cves/2.0"
#define OSV_API_BASE_URL "https://api.osv.dev/v1/query"
```

### Request Headers
```c
curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "MasterFabric-Security-Checker/1.0");
curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 30L);
curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
```

### Response Limits
```c
#define MAX_API_RESPONSE_SIZE 1048576  // 1MB
#define MAX_CVE_RESULTS 1000
#define MAX_PACKAGE_NAME 128
```

## 🚀 Future Enhancements

### 1. Additional CVE Sources
- **GitHub Security Advisories API**
- **Snyk Vulnerability Database**
- **Sonatype OSS Index**
- **Retire.js Database**

### 2. Advanced Features
- **CVE trend analysis**
- **Vulnerability prediction**
- **Automated remediation suggestions**
- **Integration with package managers**

### 3. Performance Improvements
- **Async API calls**
- **Response compression**
- **Local CVE database caching**
- **Distributed vulnerability scanning**

## 📚 Dependencies

### Required Libraries
- **libcurl**: HTTP client for API requests
- **json-c**: JSON parsing and manipulation
- **pkg-config**: Library configuration

### Installation
```bash
# macOS
brew install curl json-c pkg-config

# Ubuntu/Debian
sudo apt-get install libcurl4-openssl-dev libjson-c-dev pkg-config

# CentOS/RHEL
sudo yum install libcurl-devel json-c-devel pkgconfig
```

## 🤝 Contributing

The real-time CVE API integration is designed for extensibility:
- Add new CVE data sources
- Implement additional package managers
- Enhance vulnerability matching algorithms
- Improve API response parsing

---

**Note**: This real-time CVE API integration provides the most current and comprehensive vulnerability analysis available, ensuring that security checks are always up-to-date with the latest threat intelligence.
