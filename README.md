# Ledger Hardware Wallet Threat Modelling

A comprehensive threat modelling framework for Ledger hardware wallets using automated planning (PDDL) and formal methods (Alloy).

## 🎯 Overview

This project provides formal security models and threat analysis for Ledger hardware wallets, including:

- **Attack Planning Models** (PDDL): Automated discovery of attack paths and vulnerabilities ✅ **Working**
- **Formal Security Models** (Alloy): Mathematical specifications of device architecture and security properties ⚠️ **Work in Progress**
- **Comprehensive Attack Scenarios**: Physical, software, supply chain, and wireless attacks
- **Security Property Verification**: Automated checking of key confidentiality, display integrity, and device genuineness

## 📁 Repository Structure

```
ledger-threat-modelling/
├── pddl/                           # PDDL planning models (WORKING)
│   ├── domains/                    # Attack domain definitions
│   ├── problems/                   # Specific attack scenarios
│   └── plans/                      # Generated attack plans
├── alloy/                          # Alloy formal models (WIP)
│   ├── models/                     # Core security property models
│   ├── instances/                  # Concrete attack scenarios
│   └── analysis/                   # Analysis and verification files
├── docs/                           # Documentation
├── examples/                       # Example analyses and results
├── tools/                          # Tool installation scripts
├── requirements.txt                # Python dependencies
├── install.sh                      # Automated setup script
└── README.md                       # This file
```

## 🚀 Quick Start

### Prerequisites

- **Java 8+** (for Alloy Analyzer)
- **Python 3.8+** (for PDDL tools and scripts)
- **Git** (for cloning the repository)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/ledger-threat-modelling.git
   cd ledger-threat-modelling
   ```

2. **Run the automated setup:**
   ```bash
   chmod +x install.sh
   ./install.sh
   ```

   This will:
   - Download and install Alloy Analyzer
   - Set up PDDL planners (Fast Downward, FF)
   - Install Python dependencies
   - Verify the installation

3. **Manual setup (alternative):**
   ```bash
   # Create Python virtual environment
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
   # Install Python dependencies
   pip install -r requirements.txt
   
   # Download Alloy Analyzer
   mkdir -p tools
   wget -O tools/alloy.jar https://github.com/AlloyTools/org.alloytools.alloy/releases/download/v6.0.0/org.alloytools.alloy.dist.jar
   ```

## 🔍 Usage

### PDDL Attack Planning ✅

1. **Run attack planning:**
   ```bash
   # Using Fast Downward planner
   python3 tools/planners/downward/fast-downward.py \
     pddl/domains/ledger-comprehensive.pddl \
     pddl/problems/ledger-nano-s.pddl \
     --search "astar(lmcut())"
   ```

2. **Analyze generated plans:**
   ```bash
   # Plans are saved in the current directory as sas_plan
   cat sas_plan
   ```

3. **Available attack scenarios:**
   - `pddl/problems/ledger-nano-s.pddl` - Nano S physical attacks
   - `pddl/problems/ledger-nano-x.pddl` - Nano X wireless + physical attacks  
   - `pddl/problems/ledger-stax-comprehensive.pddl` - Stax multi-vector attacks

### Alloy Security Models ⚠️ (Work in Progress)

1. **Open Alloy Analyzer:**
   ```bash
   java -jar tools/alloy.jar
   ```

2. **Load a security model:**
   - Open `alloy/instances/ledger_security_properties.als`
   - Execute commands to check security properties
   - Analyze counterexamples for attack scenarios

3. **Key commands in the model:**
   ```alloy
   // Check if key confidentiality can be violated
   check KeyConfidentialityAssertion for 4 but 1 Device, 1 Attacker
   
   // Find attack scenarios
   run SimpleSeCompromiseAttack for 4 but 1 Device, 1 Attacker
   run SupplyChainAttack for 4 but 1 Device, 1 Attacker
   ```

   **Note**: The Alloy models are currently under development. Some assertions may not find counterexamples as expected.

## 📊 Security Models

### Device Types Modeled

- **Nano S**: USB-only device with MCU-driven display
- **Nano X**: Bluetooth-enabled device with SE-driven display  
- **Stax**: NFC/Bluetooth device with touchscreen

### Attack Vectors Covered

#### Physical Attacks
- Fault injection attacks on Secure Element
- Side-channel attacks (power, EM, timing)
- Evil maid attacks with device replacement
- Bootloader exploitation

#### Supply Chain Attacks
- Pre-compromised devices
- Malicious firmware installation
- Component substitution

#### Wireless Attacks
- Bluetooth Man-in-the-Middle
- NFC eavesdropping
- Proximity-based attacks

#### Software Attacks
- Malicious applications
- Host OS compromise
- Rogue HSM servers

### Security Properties Verified

1. **Key Confidentiality**: Private keys cannot be extracted
2. **Display Integrity**: Display shows authentic information
3. **Device Genuineness**: Device authenticity can be verified
4. **PIN Security**: PIN cannot be bypassed without physical access

## 🔬 Analysis Results

### PDDL Planning Results ✅

1. **Working Attack Paths**: PDDL successfully generates attack sequences for:
   - Physical access → PIN bypass → seed extraction
   - Supply chain compromise → pre-compromised device
   - Wireless proximity → BLE MITM → communication eavesdropping
   - Multi-vector attacks combining physical, software, and social engineering

2. **Verified Attack Scenarios**: All device types (Nano S, Nano X, Stax) have validated attack paths

### Alloy Analysis Results ⚠️ (In Development)

1. **Current Limitations**: 
   - Key confidentiality assertions not finding expected counterexamples
   - Model constraints may be too restrictive for counterexample generation
   - Under active development to resolve assertion checking issues

2. **Theoretical Coverage**: Models cover SE compromise, supply chain attacks, and multi-vector scenarios

## 🛠️ Development

### Adding New Attack Scenarios

1. **Alloy Models**: Add new predicates in `alloy/instances/attack-scenarios.als`
2. **PDDL Models**: Create new problem files in `pddl/problems/`
3. **Verification**: Add corresponding check commands

### Running Tests

```bash
# Test Alloy model syntax
python3 tools/test_alloy_syntax.py

# Verify PDDL domain validity
python3 tools/test_pddl_domains.py
```

## 📚 Documentation

- [Alloy Model Documentation](docs/alloy-models.md)
- [PDDL Domain Specification](docs/pddl-domains.md)
- [Attack Scenario Catalog](docs/attack-scenarios.md)
- [Security Analysis Results](docs/security-analysis.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-attack-model`)
3. Commit your changes (`git commit -am 'Add new attack model'`)
4. Push to the branch (`git push origin feature/new-attack-model`)
5. Create a Pull Request

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Alloy Analyzer](https://alloytools.org/) for formal specification
- [Fast Downward](https://www.fast-downward.org/) for automated planning
- [Ledger](https://www.ledger.com/) for hardware wallet architecture insights

## 📞 Contact

For questions or collaboration opportunities, please open an issue or contact the maintainers.

---

**⚠️ Disclaimer**: This research is for educational and security analysis purposes only. Do not use these models to attack real devices without proper authorization. 