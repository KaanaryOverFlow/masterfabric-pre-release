# MasterFabric Pre-Release Security Checker - Commit Conventions

The commit type can include the following:

- [ ] feat – a new feature is introduced with the changes
- [ ] fix – a bug fix has occurred
- [ ] chore – changes that do not relate to a fix or feature and don't modify src or test files (for example updating dependencies)
- [ ] refactor – refactored code that neither fixes a bug nor adds a feature
- [ ] docs – updates to documentation such as a the README or other markdown files
- [ ] style – changes that do not affect the meaning of the code, likely related to code formatting such as white-space, missing semi-colons, and so on.
- [ ] test – including new or correcting previous tests
- [ ] perf – performance improvements
- [ ] ci – continuous integration related
- [ ] build – changes that affect the build system or external dependencies
- [ ] revert – reverts a previous commit
- [ ] add – when adding a new file, function, method, variable, and so on
- [ ] remove – when removing a file, function, method, variable, and so on
- [ ] update – when updating a file, function, method, variable, and so on
- [ ] rename – when renaming a file, function, method, variable, and so on
- [ ] move – when moving a file, function, method, variable, and so on
- [ ] copy – when copying a file, function, method, variable, and so on
- [ ] security – in case of vulnerabilities or security improvements
- [ ] hotfix – a bug hot fix has occurred
- [ ] scanner – when adding or modifying security analysis modules
- [ ] policy – when updating security policy configurations
- [ ] cve – when updating CVE detection or vulnerability scanning features

## Examples for MasterFabric Pre-Release Security Checker:

```bash
feat: add new cryptographic weakness scanner
fix: resolve memory leak in CVE API integration
security: enhance hardcoded secret detection algorithm
scanner: implement Python dependency vulnerability scanner
policy: update default security policy for Go projects
cve: integrate OSV API for real-time vulnerability data
docs: update security policy specification documentation
test: add unit tests for binary hardening verification
```

- signed by the author @gurkanfikretgunak