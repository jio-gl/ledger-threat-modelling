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

#!/usr/bin/env python3
"""
Test script to verify installation
"""

import os
import subprocess
import sys

def test_planners():
    """Test if planners are properly installed"""
    print("Testing PDDL planners...")
    
    # Test FF
    ff_path = "tools/planners/ff/ff"
    if os.path.exists(ff_path):
        print("✅ FF planner found")
    else:
        print("⚠️  FF planner not found (Fast Downward will be used)")
    
    # Test Fast Downward
    fd_path = "tools/planners/downward/fast-downward.py"
    if os.path.exists(fd_path):
        print("✅ Fast Downward found")
    else:
        print("❌ Fast Downward not found")
    
    # Test VAL - check multiple possible locations
    val_paths = [
        "tools/planners/val/validate",
        "tools/planners/val/build/validate", 
        "tools/planners/val/build/Validate"
    ]
    
    val_found = False
    for val_path in val_paths:
        if os.path.exists(val_path):
            print("✅ VAL validator found")
            val_found = True
            break
    
    if not val_found:
        print("⚠️  VAL validator not found (plan validation will be limited)")

def test_alloy():
    """Test if Alloy is properly installed"""
    print("Testing Alloy...")
    alloy_path = "tools/alloy.jar"
    if os.path.exists(alloy_path):
        print("✅ Alloy Analyzer found")
    else:
        print("❌ Alloy Analyzer not found")

def test_python_deps():
    """Test Python dependencies"""
    print("Testing Python dependencies...")
    deps = ['networkx', 'matplotlib', 'yaml', 'click']
    
    for dep in deps:
        try:
            __import__(dep)
            print(f"✅ {dep} imported successfully")
        except ImportError:
            print(f"❌ {dep} not available")

if __name__ == "__main__":
    print("Ledger Threat Modeling - Installation Test")
    print("=" * 50)
    
    test_planners()
    print()
    test_alloy()
    print()
    test_python_deps()
    
    print("\nTest complete!")
