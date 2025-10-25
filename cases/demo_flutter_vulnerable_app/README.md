# Vulnerable Flutter Demo Application

This is a Flutter application intentionally designed with security vulnerabilities to demonstrate and test the MasterFabric Pre-Release Security Checker.

## ⚠️ WARNING

**This application contains intentional security vulnerabilities and should NEVER be used in production!**

## Purpose

This demo application serves as a test case for the MasterFabric Security Checker, showcasing various types of security issues that the tool can detect in Flutter/Dart applications:

## Known Vulnerabilities

### 1. Dependency Vulnerabilities
- **http@0.12.2**: Known CVE vulnerabilities in versions < 0.13.0
- **crypto@2.1.5**: Outdated version with security issues
- **shared_preferences@0.5.12**: Security vulnerabilities in versions < 2.0.0
- **sqflite@1.3.2**: Outdated version with known vulnerabilities
- **dio@3.0.10**: Security issues in versions < 4.0.0
- **uuid@2.2.2**: Outdated version with security problems

### 2. Cryptographic Issues
- **Weak Hashing**: Using MD5 and SHA1 instead of secure algorithms
- **Weak Encryption**: Using simple XOR encryption instead of AES
- **Insecure Random**: Using `Random()` for token generation
- **Hardcoded Secrets**: API keys and secret keys hardcoded in source code

### 3. Data Storage Vulnerabilities
- **Plain Text Storage**: Storing passwords and sensitive data in plain text
- **Unencrypted Database**: SQLite database without encryption
- **Insecure SharedPreferences**: Storing sensitive data without encryption
- **No Data Validation**: Missing input validation and sanitization

### 4. Network Security Issues
- **HTTP Instead of HTTPS**: Using insecure HTTP connections
- **Hardcoded API Keys**: API keys exposed in source code
- **No Certificate Pinning**: Missing SSL/TLS security measures
- **Insecure File Upload**: No file type validation or size limits

### 5. Code Vulnerabilities
- **SQL Injection**: Vulnerable database queries without parameterization
- **No Input Validation**: Missing input sanitization
- **Insecure Data Transmission**: Sending sensitive data over HTTP
- **Weak Authentication**: Insecure password handling

## Running the Demo

### Prerequisites
- Flutter SDK 3.0+
- Dart SDK 2.17+

### Installation
```bash
cd cases/demo_flutter_vulnerable_app
flutter pub get
```

### Development
```bash
flutter run
```

The application will be available on your connected device or emulator.

## Testing with MasterFabric Security Checker

To test the security checker against this vulnerable Flutter application:

```bash
# From the project root
cd checker_tool
./bin/masterfabric-prerelease --check ../cases/demo_flutter_vulnerable_app --verbose
```

## Expected Security Findings

When running the MasterFabric Security Checker on this application, you should see findings for:

1. **HIGH Severity**: Outdated vulnerable dependencies
2. **CRITICAL Severity**: Hardcoded secrets and API keys
3. **HIGH Severity**: Weak cryptographic algorithms (MD5, SHA1)
4. **MEDIUM Severity**: Weak random number generation
5. **HIGH Severity**: SQL injection vulnerabilities
6. **MEDIUM Severity**: Insecure data storage practices
7. **HIGH Severity**: HTTP instead of HTTPS usage

## Security Policy

The `.security.yaml` file in this directory defines a strict security policy that will catch all the intentional vulnerabilities in this demo application.

## Learning Objectives

This demo application helps developers understand:

- Common security vulnerabilities in Flutter applications
- How dependency management affects security in Dart/Flutter
- Importance of cryptographic best practices in mobile apps
- Value of automated security scanning for Flutter projects
- Configuration of security policies for mobile applications

## Remediation Examples

To fix the vulnerabilities in this application:

1. **Update Dependencies**: Upgrade all packages to latest secure versions
2. **Use Strong Crypto**: Replace MD5/SHA1 with SHA3-256, use AES-256-GCM
3. **Secure Random**: Use `Random.secure()` instead of `Random()`
4. **Environment Variables**: Move secrets to environment variables
5. **Input Validation**: Add proper input validation and sanitization
6. **HTTPS Only**: Use HTTPS for all network communications
7. **Database Encryption**: Implement proper database encryption
8. **Secure Storage**: Use encrypted storage for sensitive data

## Flutter-Specific Security Considerations

- **Platform Channels**: Secure communication between Dart and native code
- **Asset Security**: Protect sensitive assets and configuration files
- **Code Obfuscation**: Implement code obfuscation for release builds
- **Certificate Pinning**: Implement SSL certificate pinning
- **Biometric Authentication**: Use secure biometric authentication
- **Keychain/Keystore**: Store sensitive data in platform keychains

## Contributing

When adding new vulnerabilities to this demo:

1. Document the vulnerability in this README
2. Add appropriate comments in the code
3. Update the security policy if needed
4. Test that the MasterFabric checker detects the new vulnerability

Remember: This is for educational purposes only!
