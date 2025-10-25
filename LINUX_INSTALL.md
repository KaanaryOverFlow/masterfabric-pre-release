# 🐧 Linux Installation Guide - MasterFabric Pre-Release Security Checker

## 📋 Prerequisites

### Required Dependencies

#### **Arch Linux / Manjaro**
```bash
# Install required packages
sudo pacman -S base-devel gcc make pkg-config curl json-c clang cppcheck

# Optional: Install additional development tools
sudo pacman -S git vim nano
```

#### **Ubuntu / Debian**
```bash
# Update package list
sudo apt update

# Install required packages
sudo apt install build-essential gcc make pkg-config libcurl4-openssl-dev libjson-c-dev clang-tidy cppcheck

# Optional: Install additional development tools
sudo apt install git vim nano
```

#### **Fedora / CentOS / RHEL**
```bash
# Install required packages
sudo dnf install gcc make pkg-config libcurl-devel json-c-devel clang-tools-extra cppcheck

# Or for older systems with yum:
# sudo yum install gcc make pkg-config libcurl-devel json-c-devel clang-tools-extra cppcheck
```

#### **openSUSE**
```bash
# Install required packages
sudo zypper install gcc make pkg-config libcurl-devel libjson-c-devel clang-tools cppcheck
```

## 🔧 Build Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/masterfabric-pre-release.git
cd masterfabric-pre-release
```

### 2. Update Makefile for Linux
The Makefile needs to be updated for Linux systems. Create a Linux-specific version:

```bash
# Copy and modify the Makefile
cp checker_tool/Makefile checker_tool/Makefile.linux
```

### 3. Build the Security Checker
```bash
cd checker_tool

# Check dependencies first
make check-deps

# Build the project
make all

# Or build with debug symbols
make debug

# Or build optimized release version
make release
```

### 4. Test the Installation
```bash
# Run tests on demo applications
make test

# Test manually
./bin/masterfabric-prerelease --help
./bin/masterfabric-prerelease --version
```

## 🚀 Usage Examples

### Basic Security Check
```bash
# Check a project directory
./bin/masterfabric-prerelease --check /path/to/your/project

# Check with verbose output
./bin/masterfabric-prerelease --check /path/to/your/project --verbose
```

### Test on Demo Applications
```bash
# Test on Flutter demo app
./bin/masterfabric-prerelease --check ../cases/demo_flutter_vulnerable_app --verbose

# Test on Next.js demo app
./bin/masterfabric-prerelease --check ../cases/demo_vulnerable_app --verbose
```

## 📦 System Installation

### Install to System Path
```bash
# Install to /usr/local/bin (requires sudo)
sudo make install

# Now you can run from anywhere
masterfabric-prerelease --help
```

### Uninstall
```bash
# Remove from system
sudo make uninstall
```

## 🔍 Troubleshooting

### Common Issues

#### **1. Missing Dependencies**
```bash
# Check what's missing
make check-deps

# Install missing packages based on your distribution
# (see prerequisites section above)
```

#### **2. Compilation Errors**
```bash
# Clean and rebuild
make clean
make all

# Check for specific errors
make debug  # Build with debug symbols for better error messages
```

#### **3. Permission Issues**
```bash
# Make sure the binary is executable
chmod +x bin/masterfabric-prerelease

# For system installation, use sudo
sudo make install
```

#### **4. Library Path Issues**
```bash
# If you get library not found errors, update library path
export LD_LIBRARY_PATH=/usr/lib:/usr/local/lib:$LD_LIBRARY_PATH

# Or add to your shell profile
echo 'export LD_LIBRARY_PATH=/usr/lib:/usr/local/lib:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc
```

### **5. CURL/JSON-C Issues**
```bash
# Check if libraries are properly installed
pkg-config --cflags --libs libcurl
pkg-config --cflags --libs json-c

# If not found, reinstall
# Arch: sudo pacman -S curl json-c
# Ubuntu: sudo apt install libcurl4-openssl-dev libjson-c-dev
```

## 🐳 Docker Support (Alternative)

If you prefer using Docker:

```bash
# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM archlinux:latest

# Install dependencies
RUN pacman -Syu --noconfirm base-devel gcc make pkg-config curl json-c clang cppcheck git

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Build the project
WORKDIR /app/checker_tool
RUN make all

# Set entry point
ENTRYPOINT ["./bin/masterfabric-prerelease"]
EOF

# Build Docker image
docker build -t masterfabric-security-checker .

# Run with Docker
docker run -v $(pwd):/workspace masterfabric-security-checker --check /workspace/your-project
```

## 🔧 Development Setup

### For Contributors
```bash
# Install additional development tools
# Arch Linux
sudo pacman -S valgrind gdb strace

# Ubuntu/Debian
sudo apt install valgrind gdb strace

# Build with debug symbols
make debug

# Run with debugging
gdb ./bin/masterfabric-prerelease
```

### IDE Setup
```bash
# Generate compile_commands.json for IDE support
# Install bear (Build EAR)
# Arch: sudo pacman -S bear
# Ubuntu: sudo apt install bear

# Generate compile database
bear -- make all
```

## 📊 Performance Optimization

### For Large Projects
```bash
# Build optimized version
make release

# Use parallel compilation
make -j$(nproc) all
```

### Memory Usage
```bash
# Monitor memory usage during analysis
valgrind --tool=massif ./bin/masterfabric-prerelease --check /path/to/project
```

## 🔒 Security Considerations

### Running as Non-Root
```bash
# Create dedicated user for security scanning
sudo useradd -m -s /bin/bash security-scanner
sudo usermod -aG users security-scanner

# Switch to security scanner user
sudo su - security-scanner

# Build and run as non-root user
cd /path/to/masterfabric-pre-release/checker_tool
make all
./bin/masterfabric-prerelease --check /path/to/project
```

## 📝 Notes

- **Arch Linux** users may need to install `base-devel` group for full development environment
- **Ubuntu/Debian** users should use `libcurl4-openssl-dev` instead of just `libcurl-dev`
- **Fedora** users might need to enable EPEL repository for some packages
- The tool works best with **GCC 9+** or **Clang 10+**
- For **older Linux distributions**, you may need to compile dependencies from source

## 🆘 Getting Help

If you encounter issues:

1. Check the troubleshooting section above
2. Verify all dependencies are installed: `make check-deps`
3. Try building with debug symbols: `make debug`
4. Check system logs: `journalctl -f` (systemd systems)
5. Report issues with your Linux distribution and version

## 🎯 Quick Start for Arch Linux

```bash
# One-liner installation for Arch Linux
sudo pacman -S base-devel gcc make pkg-config curl json-c clang cppcheck && \
git clone https://github.com/your-username/masterfabric-pre-release.git && \
cd masterfabric-pre-release/checker_tool && \
make all && \
./bin/masterfabric-prerelease --help
```

This should get you up and running quickly on Arch Linux! 🚀
