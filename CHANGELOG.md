# Changelog

All notable changes to this project will be documented in this file.

## [1.0.1] - 2025-05-27

### License Update

#### Changed
- **License**: Updated from MIT to Apache License 2.0 across all files
- **Copyright year**: Updated to 2025 throughout the repository
- **License headers**: Added Apache 2.0 license headers to all source files:
  - Python files (`tools/test_installation.py`)
  - Shell scripts (`install.sh`)
  - Alloy models (`alloy/instances/*.als`)
  - PDDL files (`pddl/domains/*.pddl`, `pddl/problems/*.pddl`)

#### Files Updated
- `LICENSE` - Complete Apache 2.0 license text
- `README.md` - Updated license reference
- `CHANGELOG.md` - Updated dates and license references
- All source code files with appropriate license headers

## [1.0.0] - 2025-05-27

### Repository Cleanup for GitHub Publication

#### Removed
- **Large binary files**: 
  - `tools/alloy.jar` (19MB) - Now downloaded by install script
  - `tools/planners/downward/` - Downloaded during setup
  - `tools/planners/ff/` - Downloaded during setup
  - `tools/planners/ff-v2.3.tar.gz` - Temporary archive
  
- **Virtual environment**: 
  - `venv/` directory - Users create their own
  
- **Temporary test files**:
  - `test_counterexamples.py`
  - `simple_counterexample_test.als`
  - `verify_alloy_syntax.py`
  - `test_alloy_syntax.py`
  
- **Generated tools**:
  - `tools/generators/` - Removed complex generated scripts

#### Added
- **`.gitignore`**: Comprehensive ignore file for tools, virtual environments, and temporary files
- **`LICENSE`**: Apache License 2.0 for open source publication
- **Updated `README.md`**: Clean documentation with setup instructions
- **Streamlined `install.sh`**: Simplified installation script

#### Changed
- **Repository size**: Reduced from ~20MB+ to 276KB
- **Installation approach**: Tools now downloaded on-demand rather than pre-bundled
- **Documentation**: Focused on core functionality and clear setup instructions
- **License**: Updated to Apache License 2.0

#### Repository Structure (Post-Cleanup)
```
ledger-threat-modelling/
├── .gitignore                      # Git ignore rules
├── LICENSE                         # Apache License 2.0
├── README.md                       # Main documentation
├── CHANGELOG.md                    # This file
├── requirements.txt                # Python dependencies
├── install.sh                      # Setup script
├── alloy/                          # Alloy formal models
│   ├── models/                     # Core security models
│   ├── instances/                  # Attack scenarios
│   └── analysis/                   # Analysis files
├── pddl/                           # PDDL planning models
│   ├── domains/                    # Domain definitions
│   ├── problems/                   # Problem instances
│   └── plans/                      # Generated plans
├── docs/                           # Documentation
├── examples/                       # Example analyses
└── tools/                          # Tool installation (empty initially)
    ├── planners/                   # PDDL planners (downloaded)
    ├── validators/                 # Plan validators (downloaded)
    └── test_installation.py        # Installation test script
```

#### Benefits
- **Faster cloning**: Significantly reduced repository size
- **Cleaner structure**: Removed temporary and generated files
- **Better maintenance**: Clear separation of source code and downloaded tools
- **Cross-platform**: Tools downloaded based on user's platform during setup
- **Version control**: Only source files tracked, not large binaries

### Security Models

#### Alloy Models
- Formal security property verification
- Device architecture modeling (Nano S, Nano X, Stax)
- Attack scenario specifications
- Key confidentiality assertions

#### PDDL Models  
- Automated attack planning
- Comprehensive threat domains
- Device-specific problem instances
- Multi-vector attack scenarios

### Installation
Users can now set up the environment with:
```bash
git clone https://github.com/your-username/ledger-threat-modelling.git
cd ledger-threat-modelling
chmod +x install.sh
./install.sh
```

This will download all necessary tools (Alloy Analyzer, PDDL planners) and set up the Python environment automatically. 