# MasterFabric Security Policy Specification

This document describes the format and options for the `.security.yaml` configuration file used by the MasterFabric Pre-Release Security Checker.

## File Location

The security policy file must be named `.security.yaml` and located in the root directory of the project being scanned.

## Configuration Sections

### Global Configuration

#### `failure_threshold`
Defines the minimum severity level that will cause the build to fail.

**Type**: String  
**Values**: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`  
**Default**: `HIGH`

```yaml
failure_threshold: HIGH
```

### SDK & Dependency Management

#### `approved_sdks`
List of approved third-party libraries and their version constraints.

**Type**: Array of objects  
**Required**: No

```yaml
approved_sdks:
  - name: "react"
    versions: ">=18.0.0"
  - name: "express"
    versions: ">=4.18.0"
  - name: "openssl"
    versions: ">=3.0.0"
```

#### `blacklisted_versions`
Specific versions of libraries that are explicitly forbidden.

**Type**: Array of strings  
**Required**: No

```yaml
blacklisted_versions:
  - "lodash@<4.17.21"
  - "node-fetch@<2.6.7"
  - "bcrypt@<5.0.0"
```

### Cryptographic Standards

#### `minimum_acceptable_standards`
Defines minimum acceptable cryptographic standards.

**Type**: Object  
**Required**: No

```yaml
minimum_acceptable_standards:
  symmetric_encryption: "AES-256-GCM"
  hashing: "SHA3-256"
  tls_version: "1.3"
```

**Supported Values**:
- `symmetric_encryption`: `AES-256-GCM`, `AES-256-CBC`, `ChaCha20-Poly1305`
- `hashing`: `SHA3-256`, `SHA3-512`, `SHA-256`, `BLAKE3`
- `tls_version`: `1.3`, `1.2`

### Secret Detection

#### `hardcoded_secret_scan`
Configuration for detecting hardcoded secrets in source code.

**Type**: Object  
**Required**: No

```yaml
hardcoded_secret_scan:
  enabled: true
  entropy_threshold: 4.5
```

**Options**:
- `enabled`: Enable/disable secret scanning (boolean)
- `entropy_threshold`: Minimum entropy for string to be considered a secret (float, 0.0-8.0)

### Binary Hardening

#### `required_hardening_flags`
Compiler flags required for security hardening.

**Type**: Array of strings  
**Required**: No

```yaml
required_hardening_flags:
  - "-fstack-protector-strong"
  - "-D_FORTIFY_SOURCE=2"
  - "-Wl,-z,relro"
  - "-Wl,-z,now"
  - "-fPIE"
  - "-pie"
```

#### `binary_checks`
Binary-level security feature requirements.

**Type**: Object  
**Required**: No

```yaml
binary_checks:
  strip_symbols: true
  pie_enabled: true
  stack_canary: true
```

**Options**:
- `strip_symbols`: Require debug symbols to be stripped (boolean)
- `pie_enabled`: Require Position Independent Executable (boolean)
- `stack_canary`: Require stack canary protection (boolean)

### Static Analysis

#### `memory_safety_checks`
Enable memory safety analysis using clang-tidy and cppcheck.

**Type**: Boolean  
**Default**: `true`

```yaml
memory_safety_checks: true
```

#### `concurrency_checks`
Enable concurrency and thread safety analysis.

**Type**: Boolean  
**Default**: `true`

```yaml
concurrency_checks: true
```

## Complete Example

```yaml
# Global configuration
failure_threshold: HIGH

# Approved dependencies
approved_sdks:
  - name: "react"
    versions: ">=18.0.0"
  - name: "next"
    versions: ">=13.1.0"
  - name: "express"
    versions: ">=4.18.0"
  - name: "openssl"
    versions: ">=3.0.0"

# Blacklisted versions
blacklisted_versions:
  - "lodash@<4.17.21"
  - "node-fetch@<2.6.7"
  - "bcrypt@<5.0.0"
  - "jsonwebtoken@<9.0.0"

# Cryptographic standards
minimum_acceptable_standards:
  symmetric_encryption: "AES-256-GCM"
  hashing: "SHA3-256"
  tls_version: "1.3"

# Secret detection
hardcoded_secret_scan:
  enabled: true
  entropy_threshold: 4.5

# Compiler hardening flags
required_hardening_flags:
  - "-fstack-protector-strong"
  - "-D_FORTIFY_SOURCE=2"
  - "-Wl,-z,relro"
  - "-Wl,-z,now"
  - "-fPIE"
  - "-pie"

# Binary security features
binary_checks:
  strip_symbols: true
  pie_enabled: true
  stack_canary: true

# Static analysis
memory_safety_checks: true
concurrency_checks: true
```

## Version Constraints

Version constraints follow semantic versioning with the following operators:

- `>=`: Greater than or equal to
- `>`: Greater than
- `<=`: Less than or equal to
- `<`: Less than
- `==`: Exactly equal to
- `~>`: Pessimistic operator (allows patch-level changes)
- `^`: Caret operator (allows compatible changes)

Examples:
```yaml
blacklisted_versions:
  - "package@<1.0.0"        # Less than 1.0.0
  - "package@>=2.0.0,<3.0.0" # Between 2.0.0 and 3.0.0
  - "package@~>1.2.3"       # >= 1.2.3, < 1.3.0
```

## Best Practices

1. **Start Strict**: Begin with a strict policy and relax as needed
2. **Regular Updates**: Keep dependency versions current
3. **Comprehensive Coverage**: Include all critical dependencies
4. **Documentation**: Document why specific versions are blacklisted
5. **Testing**: Test policy changes in development before production

## Migration Guide

When updating your security policy:

1. **Backup**: Keep a backup of your current policy
2. **Test**: Run the checker on your codebase with the new policy
3. **Review**: Review all findings and adjust as needed
4. **Document**: Document any policy changes and their rationale
5. **Deploy**: Deploy the new policy to your CI/CD pipeline

## Troubleshooting

### Common Issues

1. **Policy Not Found**: Ensure `.security.yaml` is in the project root
2. **Invalid YAML**: Use a YAML validator to check syntax
3. **Version Conflicts**: Review version constraints for conflicts
4. **False Positives**: Adjust entropy thresholds or add exceptions

### Getting Help

- Check the project documentation
- Review example configurations
- Open an issue on the project repository
- Consult the security team for policy guidance
