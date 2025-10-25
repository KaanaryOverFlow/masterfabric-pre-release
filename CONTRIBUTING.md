# Contributing to MasterFabric Pre-Release Security Checker

<div align="center">

[![Contributors](https://img.shields.io/github/contributors/masterfabric/masterfabric-pre-release?logo=github)](https://github.com/masterfabric/masterfabric-pre-release/graphs/contributors)
[![Pull Requests Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/masterfabric/masterfabric-pre-release/pulls)
[![First Timers Friendly](https://img.shields.io/badge/first--timers--only-friendly-blue.svg)](https://github.com/masterfabric/masterfabric-pre-release/issues?q=is%3Aissue+is%3Aopen+label%3Afirst-timers-only)

**Thank you for your interest in contributing to MasterFabric Pre-Release Security Checker! 🎉**

</div>

---

## 🌟 Welcome Contributors!

We're excited that you want to contribute to MasterFabric Pre-Release Security Checker! This project aims to provide a comprehensive security analysis tool for C/C++, JavaScript/TypeScript, Python, Rust, Go, and Dart projects. Every contribution, no matter how small, helps us achieve this vision.

### 🎯 Our Mission
- 🛠️ Providing a robust, comprehensive security analysis tool for multiple programming languages
- 🎯 Enabling automated vulnerability detection and security policy enforcement  
- 📚 Delivering fully documented, production-ready security scanning capabilities

---

## 🤝 Ways to Contribute

### 📝 Reporting Issues
- 🐛 **Bug Reports**: Found a bug? Let us know!
- ✨ **Feature Requests**: Have an idea? We'd love to hear it!
- 📚 **Documentation**: Help improve our docs
- 🤔 **Questions**: Ask questions in discussions

### 💻 Code Contributions
- 🔍 **Security Analyzers**: Build new security analysis modules
- 🔧 **Core Features**: Implement new vulnerability detection capabilities
- 🧪 **Testing**: Write tests to improve coverage
- 🚀 **Performance**: Optimize existing code
- 🔐 **Security**: Enhance security scanning features

### 📖 Non-Code Contributions
- 📝 **Documentation**: Improve README, guides, and API docs
- 🎨 **Design**: UI/UX improvements and design assets
- 🌍 **Translation**: Help localize the security checker
- 📢 **Community**: Help others in discussions and issues

---

## 🛠️ Development Setup

### Prerequisites

Ensure you have the following installed:

```bash
# Required
- GCC or Clang compiler
- Make
- libcurl (for real-time CVE API integration)
- json-c (for JSON parsing)
- Git
- VS Code or any C/C++ IDE

# Optional (for enhanced analysis)
- clang-tidy
- cppcheck

# Recommended VS Code Extensions
- C/C++
- Makefile Tools
- GitLens
```

### 🚀 Quick Start

1. **Fork & Clone**
   ```bash
   # Fork the repository on GitHub
   # Then clone your fork
   git clone https://github.com/YOUR_USERNAME/masterfabric-pre-release.git
   cd masterfabric-pre-release
   ```

2. **Setup Development Environment**
   ```bash
   # Install dependencies (macOS)
   brew install curl json-c pkg-config
   
   # Or on Ubuntu/Debian:
   sudo apt-get install libcurl4-openssl-dev libjson-c-dev pkg-config
   
   # Build the security checker
   cd checker_tool
   make
   ```

3. **Verify Installation**
   ```bash
   # Run tests to ensure everything works
   make test
   
   # Test the security checker
   ./bin/masterfabric-prerelease --version
   ```

### 📁 Project Structure

```bash
masterfabric-pre-release/
├── checker_tool/          # C-based security checker
│   ├── src/              # Source files
│   ├── include/          # Header files
│   ├── obj/              # Object files
│   ├── bin/              # Binary executables
│   └── Makefile          # Build configuration
├── cases/                # Demo applications
│   ├── demo_vulnerable_app/      # Next.js demo with vulnerabilities
│   └── demo_flutter_vulnerable_app/  # Flutter demo with vulnerabilities
├── docs/                 # Documentation
└── README.md             # Project documentation
```

---

## 📋 Contribution Workflow

### 1. 🍴 Fork and Branch

```bash
# Create a new branch for your feature
git checkout -b feature/amazing-feature

# Or for bug fixes
git checkout -b fix/bug-description

# Or for documentation
git checkout -b docs/improvement-description
```

### 2. 🔧 Make Changes

Follow our coding standards:

#### **C/C++ Code Standards**
- Use consistent indentation (4 spaces)
- Follow [GNU Coding Standards](https://www.gnu.org/prep/standards/) guidelines
- Use meaningful variable and function names
- Add documentation comments for public APIs
- Implement proper error handling and memory management

#### **Commit Message Format**
Follow our [commit conventions](commits.md):

```bash
# Format: type: description
feat: add new payment gateway integration
fix: resolve cart calculation bug
docs: update API documentation
style: improve code formatting
test: add unit tests for product service
refactor: optimize inventory management logic
```

#### **Code Quality Checklist**
- [ ] Code follows project standards
- [ ] All tests pass (`make test`)
- [ ] No compiler warnings (`make clean && make`)
- [ ] Documentation updated if needed
- [ ] Commit messages follow conventions

### 3. 🧪 Testing

```bash
# Run all tests
make test

# Run specific test files
./bin/masterfabric-prerelease --check cases/demo_vulnerable_app

# Run with verbose output
./bin/masterfabric-prerelease --check --verbose

# Test with different security policies
./bin/masterfabric-prerelease --check cases/demo_flutter_vulnerable_app
```

### 4. 📝 Documentation

Update documentation when:
- Adding new features or APIs
- Changing existing behavior
- Adding new dependencies
- Modifying setup instructions

### 5. 🔄 Submit Pull Request

Use our [Pull Request Template](pull_request_template.md):

1. **Create PR** with descriptive title
2. **Fill out template** completely
3. **Link related issues** using keywords (`fixes #123`)
4. **Request review** from maintainers
5. **Address feedback** promptly

---

## 🎯 Contribution Guidelines

### 🐛 Reporting Bugs

When reporting bugs, please include:

```markdown
**Bug Description**
A clear description of what the bug is.

**Steps to Reproduce**
1. Go to '...'
2. Click on '...'
3. See error

**Expected Behavior**
What you expected to happen.

**Screenshots**
If applicable, add screenshots.

**Environment**
- OS: [e.g. macOS 14, Ubuntu 22.04, Windows 11]
- Compiler: [e.g. GCC 11.4, Clang 15.0]
- Architecture: [e.g. x86_64, ARM64]
```

### ✨ Requesting Features

For feature requests:

```markdown
**Feature Description**
Clear description of the feature.

**Problem Statement**
What problem does this solve?

**Proposed Solution**
How should this work?

**Alternatives Considered**
Other approaches you've thought about.

**Additional Context**
Screenshots, mockups, or examples.
```

### 🔍 Code Review Process

1. **Automated Checks**: CI/CD runs tests and checks
2. **Maintainer Review**: Core team reviews code
3. **Community Feedback**: Other contributors may comment
4. **Iteration**: Address feedback and improve
5. **Approval**: Maintainer approves changes
6. **Merge**: Changes are merged to main branch

---

## 🔍 Security Analysis Contributions

### Security Scanner Development

Follow our security analysis guidelines when contributing new scanners:

- **Comprehensive Coverage**: Support multiple programming languages
- **Real-time Data**: Integrate with live CVE databases
- **Policy-Driven**: Configurable security policies
- **Performance**: Efficient scanning without impacting build times

### Security Scanner Checklist

- [ ] Follows security analysis best practices
- [ ] Supports multiple programming languages
- [ ] Integrates with real-time CVE APIs
- [ ] Includes comprehensive documentation
- [ ] Includes usage examples
- [ ] Has unit and integration tests

---

## 🔐 Security Contributions

If you discover security vulnerabilities:

1. **DO NOT** create public issues
2. **Report privately** to `license@masterfabric.co`
3. **Follow** our [Security Policy](SECURITY.md)
4. **Wait** for acknowledgment before disclosure

---

## 📚 Documentation Contributions

Help improve our documentation:

### Areas That Need Help
- Security policy documentation
- Code examples and tutorials
- Integration guides for CI/CD
- Translation to other languages
- README improvements

### Documentation Standards
- Use clear, concise language
- Include code examples
- Add command-line examples for security scanning
- Keep information up-to-date
- Follow markdown best practices

---

## 🌍 Community Guidelines

### Code of Conduct

All contributors must follow our [Code of Conduct](CODE_OF_CONDUCT.md). In summary:

- **Be respectful** and inclusive
- **Be constructive** in feedback
- **Be patient** with newcomers
- **Be collaborative** and helpful

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and community chat
- **Pull Requests**: Code review and collaboration
- **Email**: `license@masterfabric.co` for private matters

---

## 🏷️ Issue Labels

We use labels to organize issues:

| Label | Description |
|-------|-------------|
| `bug` | Something isn't working |
| `enhancement` | New feature or request |
| `documentation` | Improvements or additions to docs |
| `good first issue` | Good for newcomers |
| `help wanted` | Extra attention is needed |
| `priority: high` | High priority items |
| `status: in progress` | Currently being worked on |

---

## 🎖️ Recognition

We appreciate all contributions! Contributors are recognized:

- **Contributors Graph**: Visible on GitHub
- **Release Notes**: Major contributions mentioned
- **Hall of Fame**: Top contributors highlighted
- **Special Thanks**: In project documentation

---

## 📞 Getting Help

Need help contributing? Here are your options:

### 💬 Ask Questions
- **GitHub Discussions**: For general questions
- **Issue Comments**: For specific code questions
- **Email**: `license@masterfabric.co` for private inquiries

### 📚 Resources
- [C Programming Language](https://en.cppreference.com/w/c)
- [GNU Coding Standards](https://www.gnu.org/prep/standards/)
- [Security Best Practices](https://owasp.org/www-project-top-ten/)
- [CVE Database](https://cve.mitre.org/)

---

## 🚀 Release Process

### Version Strategy
- **Major** (1.0.0): Breaking changes
- **Minor** (1.1.0): New features (backward compatible)
- **Patch** (1.1.1): Bug fixes

### Release Schedule
- **Regular releases**: Monthly minor releases
- **Hotfixes**: As needed for critical bugs
- **Major releases**: Quarterly with breaking changes

---

## ⚖️ Legal Information

### License
This project is licensed under GNU AGPL v3.0. By contributing, you agree that your contributions will be licensed under the same terms.

### Copyright
- **Owner**: MASTERFABRIC Bilişim Teknolojileri A.Ş.
- **Maintainer**: Gürkan Fikret Günak (@gurkanfikretgunak)
- **Contributors**: All contributors retain copyright of their contributions

### Contributor License Agreement (CLA)
By submitting a pull request, you confirm that:
- You have the right to license your contribution to us
- You agree to license your contribution under GNU AGPL v3.0
- Your contribution is your original work

---

<div align="center">

## 🎉 Thank You!

**Your contributions make MasterFabric Pre-Release Security Checker better for everyone!**

[![Contributors](https://contrib.rocks/image?repo=masterfabric/masterfabric-pre-release)](https://github.com/masterfabric/masterfabric-pre-release/graphs/contributors)

---

**Questions? Reach out!**
- 📧 Email: `license@masterfabric.co`
- 💬 GitHub: [@gurkanfikretgunak](https://github.com/gurkanfikretgunak)
- 🌐 Website: [masterfabric.co](https://masterfabric.co)

---

**Built with ❤️ by the MasterFabric Pre-Release Security Checker Community**

[⬆ Back to Top](#contributing-to-masterfabric-pre-release-security-checker)

</div>
