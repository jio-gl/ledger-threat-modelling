# Ledger Hardware Wallet Threat Model Overview

## Table of Contents
1. [Introduction](#introduction)
2. [Security Objectives](#security-objectives)
3. [Architecture Analysis](#architecture-analysis)
4. [Security Mechanisms](#security-mechanisms)
5. [Attack Vectors & Threats](#attack-vectors--threats)
6. [Modeling Approach](#modeling-approach)
7. [References](#references)

## Introduction

This document provides a comprehensive analysis of Ledger hardware wallet security based on the official [Ledger Donjon threat model](https://donjon.ledger.com/threat-model/) and security research. It serves as the foundation for our formal modeling approach using PDDL and Alloy.

Ledger hardware wallets are designed to provide physical and logical security for cryptocurrency assets by implementing a defense-in-depth strategy across multiple layers: hardware, firmware, software, and user interaction.

## Security Objectives

Based on Ledger's official threat model, the primary security objectives are:

### 1. Confidentiality of User Seeds and Private Keys
- **Goal**: Ensure that cryptographic seeds and private keys never leave the secure element
- **Implementation**: Hardware-based key storage in certified secure elements (ST31/ST33)
- **Threats**: Physical attacks, side-channel analysis, firmware extraction

### 2. User Consent and Transaction Integrity
- **Goal**: Prevent unauthorized transactions and ensure "What You See Is What You Sign" (WYSIWYG)
- **Implementation**: Secure display and input mechanisms, user confirmation requirements
- **Threats**: Display tampering, input bypass, social engineering

### 3. Device Genuineness Verification
- **Goal**: Allow users to verify their device is authentic and unmodified
- **Implementation**: HSM-based attestation using device-unique key pairs
- **Threats**: Supply chain attacks, device replacement, fake devices

### 4. User Privacy Protection
- **Goal**: Prevent device fingerprinting and user identification
- **Implementation**: Limited device identifiers, secure communication protocols
- **Threats**: Wireless tracking, transaction correlation

### 5. Firmware and IP Protection
- **Goal**: Protect secure element vendor IP and prevent firmware extraction
- **Implementation**: Code confidentiality, integrity checks, secure boot
- **Threats**: Firmware dumping, reverse engineering, tampering

## Architecture Analysis

### Device Architectures

#### Ledger Nano S (Basic Architecture)
```
┌─────────────────┐    ┌──────────────┐
│   STM32F042     │◄──►│    ST31      │
│      MCU        │    │Secure Element│
└─────────┬───────┘    └──────────────┘
          │
    ┌─────▼─────┐
    │  Display  │
    │  Buttons  │
    │    USB    │
    └───────────┘
```

**Key Characteristics:**
- MCU drives display and handles user input
- Single point of compromise for display integrity
- USB-only connectivity
- Simpler attack surface but MCU compromise affects UI

#### Ledger Nano X (Enhanced Architecture)
```
┌─────────────────┐    ┌──────────────┐
│   STM32WB55     │◄──►│    ST33      │
│   MCU + BLE     │    │Secure Element│
└─────────┬───────┘    └──────┬───────┘
          │                   │
    ┌─────▼─────┐       ┌─────▼─────┐
    │    USB    │       │  Display  │
    │    BLE    │       │  Buttons  │
    │  Battery  │       └───────────┘
    └───────────┘
```

**Key Characteristics:**
- SE directly drives display and buttons (security improvement)
- BLE connectivity introduces wireless attack surface
- Battery enables mobile usage
- Improved security for UI components

#### Ledger Stax (Advanced Architecture)
```
┌─────────────────┐    ┌──────────────┐
│   STM32WB35     │◄──►│    ST33      │
│      MCU        │    │Secure Element│
└─────────┬───────┘    └──────┬───────┘
          │                   │
    ┌─────▼─────┐       ┌─────▼─────┐
    │  USB-C    │       │Touchscreen│
    │    BLE    │       │  Display  │
    │    NFC    │       └───────────┘
    └───────────┘
```

**Key Characteristics:**
- SE drives touchscreen display directly
- NFC capability adds proximity attack surface
- Modern touchscreen interface
- Multiple wireless protocols

## Security Mechanisms

### 1. Device Genuineness

**HSM-Based Attestation Process:**
1. **Manufacturing**: Each device generates unique key pair, public key signed by Ledger HSM
2. **Attestation Storage**: Signed certificate stored in secure element
3. **Verification**: HSM challenges device to prove authenticity
4. **Root of Trust**: Based on Ledger's master signing key

**PDDL Modeling Considerations:**
- Model genuine vs non-genuine devices
- HSM connection and challenge-response
- Rogue HSM scenarios (DNS poisoning)
- Certificate validation failures

### 2. Secure Display and Inputs

**Implementation:**
- **Nano S**: MCU-driven display (potential vulnerability)
- **Nano X/Stax**: SE-driven display (enhanced security)
- **User Confirmation**: Physical button/touch required for transactions
- **WYSIWYG**: Transaction details displayed on trusted screen

**Attack Vectors:**
- Display tampering (easier on Nano S)
- Input bypass or injection
- MCU compromise affecting UI
- Social engineering around verification

### 3. Physical Resistance

**Secure Element Protection:**
- Certified against physical attacks (EAL5+)
- Tamper resistance and detection
- Side-channel attack countermeasures
- Limited PIN attempts with device wipe

**Attack Categories:**
- **Invasive**: Chip decapping, microprobing
- **Semi-invasive**: Fault injection, laser attacks
- **Non-invasive**: Power analysis, electromagnetic analysis, timing attacks

### 4. PIN Security Mechanism

**Implementation:**
- 4-8 digit PIN protection
- 3 attempt limit before device wipe
- Protection against brute force
- Timing attack countermeasures

**Vulnerabilities:**
- Weak PIN selection by users
- Timing side-channel attacks
- Fault injection to bypass counter
- Social engineering for PIN disclosure

### 5. Random Number Generation

**Requirements:**
- High-quality entropy for seed generation
- TRNG (True Random Number Generator) in SE
- EAL5+ certification for randomness quality
- Protection against entropy reduction attacks

### 6. Transport Security

**USB Security:**
- Untrusted transport assumption
- MCU handles protocol, SE validates content
- No security assumptions on USB data

**BLE Security (Nano X/Stax):**
- Encrypted communication channels
- Pairing and authentication
- Proximity-based attacks possible
- Man-in-the-middle considerations

**NFC Security (Stax):**
- Very short range communication
- Potential for eavesdropping
- Physical proximity required

## Attack Vectors & Threats

### Physical Attacks

#### High-Impact Attacks
1. **Seed Extraction**
   - Prerequisites: Physical access + PIN bypass + SE compromise
   - Impact: Complete compromise of all derived keys
   - Defenses: PIN protection, SE tamper resistance, device wipe

2. **Evil Maid Attack**
   - Method: Device replacement with PIN-capturing clone
   - Impact: PIN capture, transaction manipulation
   - Defenses: Genuineness checks, user verification habits

3. **Fault Injection**
   - Method: Voltage/clock glitching, laser fault injection
   - Target: PIN verification, cryptographic operations
   - Impact: Security bypass, computation errors
   - Defenses: SE fault detection, redundant checks

#### Medium-Impact Attacks
4. **Display Tampering**
   - Method: MCU compromise (Nano S), hardware modification
   - Impact: False transaction display, address substitution
   - Defenses: SE-driven display (newer models), user verification

5. **Side-Channel Analysis**
   - Method: Power analysis, EM analysis, timing analysis
   - Target: Cryptographic operations, PIN entry
   - Impact: Key recovery, PIN disclosure
   - Defenses: Countermeasures in SE, randomization

### Wireless Attacks

1. **BLE Eavesdropping**
   - Method: Proximity-based wireless interception
   - Target: Nano X, Stax communication
   - Impact: Transaction monitoring, pattern analysis
   - Defenses: Encryption, limited range

2. **BLE Man-in-the-Middle**
   - Method: Pairing hijacking, packet injection
   - Impact: Transaction manipulation, data interception
   - Defenses: Mutual authentication, user verification

3. **NFC Proximity Attacks**
   - Method: Close-range communication interception
   - Target: Stax NFC functionality
   - Impact: Data eavesdropping, unauthorized activation
   - Defenses: Very limited range, user awareness

### Network Attacks

1. **DNS Poisoning**
   - Method: Redirect HSM connections to rogue servers
   - Impact: Fake genuineness verification, malicious updates
   - Defenses: Certificate pinning, multiple verification paths

2. **Firmware Update MITM**
   - Method: Intercept and modify firmware updates
   - Impact: Malicious firmware installation
   - Defenses: Signature verification, secure channels

3. **Rogue HSM Deployment**
   - Method: Setup fake HSM servers
   - Impact: False genuineness verification
   - Defenses: Certificate validation, public key pinning

### Software/Social Attacks

1. **Ledger Live Compromise**
   - Method: Malware, supply chain attack, trojans
   - Impact: Transaction manipulation, address substitution
   - Defenses: User verification on device, secure display

2. **Host OS Compromise**
   - Method: System-level malware, rootkits
   - Impact: Complete control over user environment
   - Defenses: Hardware wallet isolation, user verification

3. **Phishing Attacks**
   - Method: Social engineering, fake interfaces
   - Impact: User deception, credential theft
   - Defenses: Security awareness, device verification habits

4. **Supply Chain Attacks**
   - Method: Manufacturing compromise, shipping interception
   - Impact: Pre-compromised devices, backdoors
   - Defenses: Sealed packaging, genuineness verification

## Modeling Approach

### PDDL Modeling Strategy

Our PDDL models capture:

1. **Device Architecture**: Different component configurations and connections
2. **Attacker Capabilities**: Skill levels, tool availability, access types
3. **Attack Progressions**: Multi-step attack sequences with prerequisites
4. **Defense Mechanisms**: Security features and their effectiveness
5. **Goal Conditions**: Various compromise levels and attack objectives

### Key PDDL Predicates

```lisp
;; Device Security State
(genuine ?device)
(physical-access ?device)
(seed-extracted ?device)
(pin-bypassed ?device)

;; Component Architecture
(belongs-to ?component ?device)
(compromised ?component)
(connected ?component1 ?component2)

;; Attacker Capabilities
(attacker-has-tools ?attacker)
(attacker-skill-level-high ?attacker)
(attacker-in-proximity ?attacker ?device)
```

### Attack Modeling Patterns

1. **Prerequisites Chains**: Physical access → PIN bypass → SE compromise → seed extraction
2. **Alternative Paths**: Multiple routes to same goal (brute force vs timing attack)
3. **Defense Triggers**: Automatic responses (device wipe, HSM blocking)
4. **Probabilistic Elements**: Skill-dependent success rates

### Alloy Modeling Complement

While PDDL focuses on planning attack sequences, Alloy models provide:

1. **State Space Analysis**: All possible system states and transitions
2. **Invariant Verification**: Security properties that must always hold
3. **Formal Verification**: Mathematical proofs of security properties
4. **Counter-example Generation**: Scenarios where security fails

## Implementation Insights

### Critical Security Dependencies

1. **SE Integrity**: Ultimate foundation of security
2. **PIN Protection**: First line of defense against physical attacks
3. **Display Trust**: Essential for user verification
4. **Genuineness Verification**: Protection against supply chain attacks

### Architecture Trade-offs

1. **Nano S**: Simpler but MCU compromise affects display
2. **Nano X**: Better display security but adds BLE attack surface  
3. **Stax**: Most features but largest attack surface (BLE + NFC)

### Attack Surface Evolution

- **Physical attacks**: Remain primary threat for high-value targets
- **Wireless attacks**: Growing importance with BLE/NFC adoption
- **Software attacks**: Increasing sophistication of malware
- **Social engineering**: Exploiting user behavior and trust

## References

1. [Ledger Donjon Threat Model](https://donjon.ledger.com/threat-model/)
2. [Ledger Security Research](https://donjon.ledger.com/)
3. [Hardware Wallet Security Analysis](https://donjon.ledger.com/a-closer-look-into-ledger-security-the-root-of-trust/)
4. [BLE Security Model](https://donjon.ledger.com/bluetooth/)
5. [PDDL Documentation](https://planning.wiki/)
6. [Alloy Analyzer](https://alloytools.org/) 