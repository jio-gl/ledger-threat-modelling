#!/bin/bash

# Copyright 2025 Ledger Threat Modelling Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Ledger Threat Modelling - Installation Script
# This script sets up the required tools for formal security analysis

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
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

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command_exists java; then
        print_error "Java is not installed. Please install Java 8+ and try again."
        exit 1
    fi
    
    if ! command_exists python3; then
        print_error "Python 3 is not installed. Please install Python 3.8+ and try again."
        exit 1
    fi
    
    if ! command_exists pip3; then
        print_error "pip3 is not installed. Please install pip3 and try again."
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Create directory structure
create_directories() {
    print_status "Creating directory structure..."
    
    mkdir -p tools/planners
    mkdir -p tools/validators
    mkdir -p docs
    mkdir -p examples/results
    mkdir -p pddl/plans
    
    print_success "Directory structure created"
}

# Setup Python virtual environment
setup_python_env() {
    print_status "Setting up Python virtual environment..."
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_success "Virtual environment created"
    else
        print_warning "Virtual environment already exists"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        print_success "Python dependencies installed"
    else
        print_warning "requirements.txt not found, skipping Python dependencies"
    fi
}

# Download Alloy Analyzer
download_alloy() {
    print_status "Downloading Alloy Analyzer..."
    
    ALLOY_URL="https://github.com/AlloyTools/org.alloytools.alloy/releases/download/v6.0.0/org.alloytools.alloy.dist.jar"
    ALLOY_PATH="tools/alloy.jar"
    
    if [ ! -f "$ALLOY_PATH" ]; then
        if command_exists wget; then
            wget -O "$ALLOY_PATH" "$ALLOY_URL"
        elif command_exists curl; then
            curl -L -o "$ALLOY_PATH" "$ALLOY_URL"
        else
            print_error "Neither wget nor curl is available. Please install one of them."
            exit 1
        fi
        print_success "Alloy Analyzer downloaded"
    else
        print_warning "Alloy Analyzer already exists"
    fi
}

# Download Fast Downward planner
download_fast_downward() {
    print_status "Downloading Fast Downward planner..."
    
    DOWNWARD_DIR="tools/planners/downward"
    
    if [ ! -d "$DOWNWARD_DIR" ]; then
        git clone https://github.com/aibasel/downward.git "$DOWNWARD_DIR"
        
        # Build Fast Downward
        cd "$DOWNWARD_DIR"
        ./build.py
        cd - > /dev/null
        
        print_success "Fast Downward planner installed"
    else
        print_warning "Fast Downward already exists"
    fi
}

# Download FF planner
download_ff_planner() {
    print_status "Downloading FF planner..."
    
    FF_DIR="tools/planners/ff"
    FF_URL="https://fai.cs.uni-saarland.de/hoffmann/ff/FF-v2.3.tgz"
    
    if [ ! -d "$FF_DIR" ]; then
        mkdir -p "$FF_DIR"
        cd "$FF_DIR"
        
        if command_exists wget; then
            wget "$FF_URL"
        elif command_exists curl; then
            curl -O "$FF_URL"
        fi
        
        tar -xzf FF-v2.3.tgz
        cd FF-v2.3
        make
        
        # Create symlink for easier access
        ln -sf "$(pwd)/ff" "../ff"
        
        cd - > /dev/null
        print_success "FF planner installed"
    else
        print_warning "FF planner already exists"
    fi
}

# Verify installation
verify_installation() {
    print_status "Verifying installation..."
    
    # Check Alloy
    if [ -f "tools/alloy.jar" ]; then
        print_success "✓ Alloy Analyzer found"
    else
        print_error "✗ Alloy Analyzer not found"
    fi
    
    # Check Fast Downward
    if [ -f "tools/planners/downward/fast-downward.py" ]; then
        print_success "✓ Fast Downward planner found"
    else
        print_warning "✗ Fast Downward planner not found"
    fi
    
    # Check FF
    if [ -f "tools/planners/ff/ff" ]; then
        print_success "✓ FF planner found"
    else
        print_warning "✗ FF planner not found"
    fi
    
    # Check Python environment
    if [ -d "venv" ]; then
        print_success "✓ Python virtual environment found"
    else
        print_warning "✗ Python virtual environment not found"
    fi
}

# Print usage instructions
print_usage() {
    echo ""
    echo "🎉 Installation completed!"
    echo ""
    echo "To get started:"
    echo ""
    echo "1. Activate the Python virtual environment:"
    echo "   source venv/bin/activate"
    echo ""
    echo "2. Open Alloy Analyzer:"
    echo "   java -jar tools/alloy.jar"
    echo ""
    echo "3. Load a security model:"
    echo "   Open alloy/instances/ledger_security_properties.als"
    echo ""
    echo "4. Run PDDL planning:"
    echo "   python3 tools/planners/downward/fast-downward.py \\"
    echo "     pddl/domains/ledger-comprehensive.pddl \\"
    echo "     pddl/problems/nano-s-physical-attack.pddl \\"
    echo "     --search \"astar(lmcut())\""
    echo ""
    echo "For more information, see README.md"
    echo ""
}

# Main installation function
main() {
    echo "🔧 Ledger Threat Modelling - Installation Script"
    echo "================================================"
    echo ""
    
    check_prerequisites
    create_directories
    setup_python_env
    download_alloy
    
    # Optional: Download planners (can be skipped if not needed)
    read -p "Download PDDL planners? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        download_fast_downward
        download_ff_planner
    else
        print_warning "Skipping PDDL planners installation"
    fi
    
    verify_installation
    print_usage
}

# Run main function
main "$@" 