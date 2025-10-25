#!/bin/bash

# MasterFabric Pre-Release Security Checker - Linux Setup Script
# This script automatically detects your Linux distribution and installs dependencies

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    elif [ -f /etc/arch-release ]; then
        DISTRO="arch"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    else
        DISTRO="unknown"
    fi
}

# Function to install dependencies based on distribution
install_dependencies() {
    print_status "Detected distribution: $DISTRO"
    
    case $DISTRO in
        "arch"|"manjaro")
            print_status "Installing dependencies for Arch Linux..."
            sudo pacman -Syu --noconfirm base-devel gcc make pkg-config curl json-c clang cppcheck
            ;;
        "ubuntu"|"debian"|"pop"|"elementary")
            print_status "Installing dependencies for Ubuntu/Debian..."
            sudo apt update
            sudo apt install -y build-essential gcc make pkg-config libcurl4-openssl-dev libjson-c-dev clang-tidy cppcheck
            ;;
        "fedora"|"rhel"|"centos")
            print_status "Installing dependencies for Fedora/RHEL/CentOS..."
            sudo dnf install -y gcc make pkg-config libcurl-devel json-c-devel clang-tools-extra cppcheck
            ;;
        "opensuse"|"sles")
            print_status "Installing dependencies for openSUSE..."
            sudo zypper install -y gcc make pkg-config libcurl-devel libjson-c-devel clang-tools cppcheck
            ;;
        *)
            print_error "Unsupported Linux distribution: $DISTRO"
            print_warning "Please install the following packages manually:"
            echo "  - gcc (C compiler)"
            echo "  - make (build tool)"
            echo "  - pkg-config (package configuration)"
            echo "  - libcurl development headers"
            echo "  - json-c development headers"
            echo "  - clang-tidy (static analysis)"
            echo "  - cppcheck (static analysis)"
            exit 1
            ;;
    esac
}

# Function to build the project
build_project() {
    print_status "Building MasterFabric Pre-Release Security Checker..."
    
    cd checker_tool
    
    # Use Linux-specific Makefile if available
    if [ -f Makefile.linux ]; then
        print_status "Using Linux-specific Makefile..."
        cp Makefile.linux Makefile
    fi
    
    # Check dependencies
    print_status "Checking dependencies..."
    make check-deps
    
    # Build the project
    print_status "Compiling..."
    make all
    
    print_success "Build completed successfully!"
}

# Function to run tests
run_tests() {
    print_status "Running tests..."
    
    # Test basic functionality
    if [ -f bin/masterfabric-prerelease ]; then
        print_status "Testing basic functionality..."
        ./bin/masterfabric-prerelease --help > /dev/null && print_success "Help command works"
        ./bin/masterfabric-prerelease --version > /dev/null && print_success "Version command works"
        
        # Run demo tests
        print_status "Running demo application tests..."
        make test
    else
        print_error "Binary not found. Build may have failed."
        exit 1
    fi
}

# Function to install to system
install_system() {
    print_status "Installing to system..."
    
    if [ -f bin/masterfabric-prerelease ]; then
        sudo make install
        print_success "Installed to /usr/local/bin/masterfabric-prerelease"
        print_status "You can now run 'masterfabric-prerelease' from anywhere"
    else
        print_error "Binary not found. Cannot install."
        exit 1
    fi
}

# Main function
main() {
    echo "=========================================="
    echo "MasterFabric Pre-Release Security Checker"
    echo "Linux Setup Script"
    echo "=========================================="
    echo ""
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        print_error "Please do not run this script as root. It will use sudo when needed."
        exit 1
    fi
    
    # Check if sudo is available
    if ! command -v sudo &> /dev/null; then
        print_error "sudo is required but not installed. Please install sudo first."
        exit 1
    fi
    
    # Detect distribution
    detect_distro
    
    # Install dependencies
    install_dependencies
    
    # Build project
    build_project
    
    # Run tests
    run_tests
    
    # Ask if user wants to install to system
    echo ""
    read -p "Do you want to install to system (/usr/local/bin)? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_system
    else
        print_status "You can run the tool with: ./checker_tool/bin/masterfabric-prerelease"
    fi
    
    echo ""
    print_success "Setup completed successfully!"
    echo ""
    echo "Usage examples:"
    echo "  ./checker_tool/bin/masterfabric-prerelease --help"
    echo "  ./checker_tool/bin/masterfabric-prerelease --check /path/to/project --verbose"
    echo ""
    echo "For more information, see LINUX_INSTALL.md"
}

# Run main function
main "$@"
