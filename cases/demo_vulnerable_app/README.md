# Vulnerable Demo Application

This is a Next.js application intentionally designed with security vulnerabilities to demonstrate and test the MasterFabric Pre-Release Security Checker.

## ⚠️ WARNING

**This application contains intentional security vulnerabilities and should NEVER be used in production!**

## Purpose

This demo application serves as a test case for the MasterFabric Security Checker, showcasing various types of security issues that the tool can detect:

## Known Vulnerabilities

### 1. Dependency Vulnerabilities
- **lodash@4.17.20**: Known CVE vulnerabilities in versions < 4.17.21
- **node-fetch@2.6.6**: Security issues in versions < 2.6.7
- **bcrypt@3.0.6**: Outdated version with known vulnerabilities
- **jsonwebtoken@8.5.1**: Security issues in versions < 9.0.0
- **react@17.0.2**: Outdated version (policy requires >= 18.0.0)
- **next@13.0.0**: Outdated version (policy requires >= 13.1.0)

### 2. Cryptographic Issues
- **Weak Hashing**: Using MD5 instead of secure algorithms like SHA3-256
- **Weak Encryption**: Using deprecated AES-128-CBC with weak key derivation
- **Insecure Random**: Using `Math.random()` for token generation
- **Hardcoded Secrets**: API keys and secret keys hardcoded in source code

### 3. Code Vulnerabilities
- **SQL Injection**: Simulated vulnerable query construction
- **XSS Vulnerability**: Unsanitized user content rendering
- **Input Validation**: Missing input validation and sanitization
- **Insecure API**: Hardcoded insecure API endpoints

### 4. Configuration Issues
- **Missing Security Headers**: No security headers configured
- **Insecure Defaults**: Using insecure default configurations

## Running the Demo

### Prerequisites
- Node.js 16+ 
- npm or yarn

### Installation
```bash
cd demo_vulnerable_app
npm install
```

### Development
```bash
npm run dev
```

The application will be available at `http://localhost:3000`

## Testing with MasterFabric Security Checker

To test the security checker against this vulnerable application:

```bash
# From the project root
cd checker_tool
make test

# Or run manually
./bin/masterfabric-prerelease --check ../demo_vulnerable_app --verbose
```

## Expected Security Findings

When running the MasterFabric Security Checker on this application, you should see findings for:

1. **HIGH Severity**: Outdated vulnerable dependencies
2. **CRITICAL Severity**: Hardcoded secrets and API keys
3. **HIGH Severity**: Weak cryptographic algorithms (MD5, SHA1)
4. **MEDIUM Severity**: Weak random number generation
5. **MEDIUM Severity**: Missing security hardening flags
6. **LOW Severity**: Static analysis warnings

## Security Policy

The `.security.yaml` file in this directory defines a strict security policy that will catch all the intentional vulnerabilities in this demo application.

## Learning Objectives

This demo application helps developers understand:

- Common security vulnerabilities in web applications
- How dependency management affects security
- Importance of cryptographic best practices
- Value of automated security scanning
- Configuration of security policies

## Remediation Examples

To fix the vulnerabilities in this application:

1. **Update Dependencies**: Upgrade all packages to latest secure versions
2. **Use Strong Crypto**: Replace MD5/SHA1 with SHA3-256, use AES-256-GCM
3. **Secure Random**: Use `crypto.randomBytes()` instead of `Math.random()`
4. **Environment Variables**: Move secrets to environment variables
5. **Input Validation**: Add proper input validation and sanitization
6. **Security Headers**: Implement proper security headers

## Contributing

When adding new vulnerabilities to this demo:

1. Document the vulnerability in this README
2. Add appropriate comments in the code
3. Update the security policy if needed
4. Test that the MasterFabric checker detects the new vulnerability

Remember: This is for educational purposes only!
