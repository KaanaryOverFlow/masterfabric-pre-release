# MasterFabric Pre-Release Security Checker

A comprehensive C-based security analysis tool designed to perform automated security checks on C/C++ and other projects before release.

## Features

- **Dependency Analysis**: Scans package.json, requirements.txt, Cargo.toml, and go.mod for vulnerable dependencies
- **Cryptographic Scanner**: Detects weak ciphers, hardcoded secrets, and insecure random number generation
- **Binary Hardening**: Verifies compiler flags and binary security features
- **Static Analysis**: Integrates with clang-tidy and cppcheck for memory safety and concurrency issues
- **Policy-Driven**: Configurable security policies via `.security.yaml` files
- **Multi-Language Support**: Works with C/C++, JavaScript/TypeScript, Python, Rust, and Go projects

## Installation

### Prerequisites

- GCC or Clang compiler
- Make
- clang-tidy (optional, for enhanced static analysis)
- cppcheck (optional, for enhanced static analysis)

### Build from Source

```bash
# Clone the repository
git clone <repository-url>
cd masterfabric-pre-release/checker_tool

# Build the tool
make

# Install system-wide (optional)
sudo make install
```

### Check Dependencies

```bash
make check-deps
```

## Usage

### Basic Usage

```bash
# Check current directory
masterfabric-prerelease --check

# Check specific directory
masterfabric-prerelease --check /path/to/project

# Verbose output
masterfabric-prerelease --check --verbose
```

### Command Line Options

- `--check [PATH]`: Check the specified directory for security issues
- `--verbose`: Enable verbose output with detailed information
- `--help`: Show help message
- `--version`: Show version information

### Exit Codes

- `0`: All checks passed
- `1`: Policy violations found
- `2`: Configuration error
- `3`: Scan error

## Configuration

The tool looks for a `.security.yaml` file in the target directory. This file defines the security policy and check parameters.

### Example Configuration

```yaml
failure_threshold: HIGH

approved_sdks:
  - name: "react"
    versions: ">=18.0.0"
  - name: "openssl"
    versions: ">=3.0.0"

blacklisted_versions:
  - "lodash@<4.17.21"
  - "node-fetch@<2.6.7"

minimum_acceptable_standards:
  symmetric_encryption: "AES-256-GCM"
  hashing: "SHA3-256"
  tls_version: "1.3"

hardcoded_secret_scan:
  enabled: true
  entropy_threshold: 4.5

required_hardening_flags:
  - "-fstack-protector-strong"
  - "-D_FORTIFY_SOURCE=2"

binary_checks:
  strip_symbols: true
  pie_enabled: true
  stack_canary: true

memory_safety_checks: true
concurrency_checks: true
```

## Security Checks

### 1. Dependency Analysis
- Scans package managers for known vulnerable dependencies
- Checks against approved SDK whitelist
- Identifies blacklisted versions
- Supports Node.js, Python, Rust, and Go ecosystems

### 2. Cryptographic Scanner
- Detects weak encryption algorithms (DES, MD5, SHA1, RC4)
- Identifies hardcoded secrets using entropy analysis
- Checks for insecure random number generation
- Validates minimum cryptographic standards

### 3. Binary Hardening
- Verifies compiler security flags in build files
- Checks for stack protection, ASLR/PIE, and RELRO
- Validates debug symbol stripping
- Analyzes ELF binary security features

### 4. Static Analysis
- Integrates with clang-tidy for C/C++ analysis
- Uses cppcheck for additional security checks
- Focuses on memory safety and concurrency issues
- Configurable check levels

## Testing

Run the test suite on the included demo application:

```bash
make test
```

This will run the security checker on a vulnerable Next.js application to demonstrate the tool's capabilities.

## Development

### Building

```bash
# Debug build
make debug

# Release build
make release

# Clean build artifacts
make clean
```

### Project Structure

```
checker_tool/
├── src/                 # Source files
│   ├── main.c          # CLI entry point
│   ├── yaml_parser.c   # YAML configuration parser
│   ├── sdk_analyzer.c  # Dependency analysis
│   ├── crypto_scanner.c # Cryptographic analysis
│   ├── binary_parser.c # Binary hardening checks
│   ├── static_analyzer.c # Static analysis integration
│   └── report_generator.c # Report generation
├── include/            # Header files
├── Makefile           # Build configuration
└── README.md          # This file
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

[License information to be added]

## Support

For issues and questions, please open an issue on the project repository.
