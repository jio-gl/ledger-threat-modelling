/*
 * Copyright 2025 Ledger Threat Modelling Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Ledger Attack Scenarios - Concrete Instances
// This file contains specific instances demonstrating various attack scenarios

module attack_scenarios

open ledger_security_properties

// =============================================================================
// PHYSICAL ATTACK SCENARIOS
// =============================================================================

// Scenario 1: Basic Physical Attack on Nano S (Feasible)
pred NanoSPhysicalAttack {
    // Attacker gains physical access and compromises MCU
    some d: NanoS, a: Attacker | {
        // Attacker gains physical access
        d in a.hasPhysicalAccess
        d.physicalAccess = True
        a.hasTools = True
        a.skillLevel = High
        
        // Attacker compromises MCU (which drives display on Nano S)
        some mcu: MCU | mcu in d.components and mcu.compromised = True
        
        // PIN bypass becomes possible
        d.pinBypassed = True
    }
}

// Scenario 2: Fault Injection Attack on Secure Element
pred NanoSFaultInjectionAttack {
    // Advanced physical attack targeting SE directly
    some d: NanoS, a: Attacker | {
        FaultInjectionAttack[d, a]
        
        // Verify attack succeeds
        some se: SecureElement | se in d.components and se.compromised = True
        d.seedExtracted = True
    }
}

// Scenario 3: Side Channel Attack on Nano X
pred NanoXSideChannelAttack {
    // Power/EM/timing analysis attack
    some d: NanoX, a: Attacker | {
        SideChannelAttack[d, a]
        
        // Verify attack succeeds
        some se: SecureElement | se in d.components and se.compromised = True
        d.seedExtracted = True
    }
}

// Scenario 4: Timing Attack on PIN Entry
pred StaxTimingAttack {
    // Timing analysis to bypass PIN
    some d: Stax, a: Attacker | {
        TimingAttackPIN[d, a]
        
        // Verify PIN bypass
        d.pinBypassed = True
    }
}

// Scenario 5: Evil Maid Attack with Device Replacement
pred StaxEvilMaidReplacement {
    // Device replacement with monitoring clone
    some d: Stax, a: Attacker | {
        EvilMaidDeviceReplacement[d, a]
        
        // Verify complete compromise
        d.genuine = False
        all c: d.components | c.compromised = True
        d.pinBypassed = True
        d.seedExtracted = True
    }
}

// Scenario 6: Bootloader Exploit Attack
pred NanoXBootloaderExploit {
    // Bootloader vulnerability exploitation
    some d: NanoX, a: Attacker | {
        BootloaderExploitAttack[d, a]
        
        // Verify firmware compromise leads to SE compromise
        d.bootloaderUnlocked = True
        d.firmwareCompromised = True
        some se: SecureElement | se in d.components and se.compromised = True
        d.seedExtracted = True
    }
}

// =============================================================================
// SUPPLY CHAIN ATTACK SCENARIOS
// =============================================================================

// Scenario 7: Supply Chain Compromise
pred SupplyChainCompromiseAttack {
    // Pre-compromised device from supply chain
    some d: Device, a: Attacker | {
        SupplyChainAttack[d, a]
        
        // Verify comprehensive compromise
        d.supplyChainCompromised = True
        d.genuine = False
        d.firmwareCompromised = True
        some se: SecureElement, mcu: MCU | 
            se in d.components and mcu in d.components and
            se.compromised = True and mcu.compromised = True
        d.pinBypassed = True
        d.seedExtracted = True
    }
}

// =============================================================================
// WIRELESS ATTACK SCENARIOS
// =============================================================================

// Scenario 8: BLE Man-in-the-Middle Attack on Nano X
pred NanoXBLEMITMAttack {
    // BLE proximity attack with MITM
    some d: NanoX, a: Attacker, s: Software | {
        BLEMITMAttack[d, a, s]
        
        // Verify BLE compromise
        some ble: BLE | ble in d.components and ble.compromised = True
        d.communicationsEavesdropped = True
        s.compromised = True
    }
}

// Scenario 9: NFC Eavesdropping on Stax
pred StaxNFCEavesdropping {
    // Close proximity NFC attack
    some d: Stax, a: Attacker | {
        // Legitimate device
        d.genuine = True
        
        // Attacker in very close proximity for NFC
        d in a.proximity
        a.skillLevel = Medium  // NFC attacks require less skill
        
        // NFC component monitoring
        some nfc: NFC | nfc in d.components and nfc.compromised = True
        
        // Communications eavesdropped but limited impact
        d.communicationsEavesdropped = True
        d.seedExtracted != True
        d.pinBypassed != True
    }
}

// =============================================================================
// SOFTWARE/NETWORK ATTACK SCENARIOS
// =============================================================================

// Scenario 10: Malicious App Installation
pred MaliciousAppInstallation {
    // Malicious app compromises device
    some d: Device, a: Attacker, app: App | {
        MaliciousAppAttack[d, a, app]
        
        // Verify app compromise
        app.malicious = True
        d in app.installedOn
        some mcu: MCU | mcu in d.components and mcu.compromised = True
        d.displayTampered = True
    }
}

// Scenario 11: Rogue HSM Server Attack
pred RogueHSMServerAttack {
    // Network-based attack using rogue HSM
    some d: Device, a: Attacker, s: Server | {
        RogueHSMAttack[d, a, s]
        
        // Verify rogue server compromise
        a.controlsNetwork = True
        s.rogue = True
        s.certificateValid = False
        d.firmwareCompromised = True
    }
}

// =============================================================================
// MULTI-VECTOR ATTACK SCENARIOS
// =============================================================================

// Scenario 12: Combined Physical + Software Attack
pred CombinedAttackScenario {
    // Sophisticated attack using multiple vectors
    some d: Stax, a: Attacker, s: Software, u: User | {
        CombinedPhysicalSoftwareAttack[d, a, s, u]
        
        // Verify comprehensive compromise
        d.physicalAccess = True
        s.compromised = True
        s.hostOSCompromised = True
        u.deceived = True
        some mcu: MCU, se: SecureElement |
            mcu in d.components and se in d.components and
            mcu.compromised = True and se.compromised = True
        d.pinBypassed = True
        d.seedExtracted = True
    }
}

// Scenario 13: Sophisticated Attack Chain
pred SophisticatedAttackChain {
    // Multi-stage attack demonstrating various techniques
    some d: Device, a: Attacker, s: Software, u: User, app: App | {
        // High-skill attacker with tools
        a.skillLevel = High
        a.hasTools = True
        a.controlsNetwork = True
        
        // Multiple attack vectors
        d.physicalAccess = True
        d in a.hasPhysicalAccess
        
        // Software environment compromised
        s.compromised = True
        s.malwarePresent = True
        s.hostOSCompromised = True
        
        // Malicious app installed
        app.malicious = True
        d in app.installedOn
        
        // User social engineered
        u.vigilant = False
        u.deceived = True
        
        // Multiple components compromised
        some se: SecureElement, mcu: MCU, ble: BLE |
            se + mcu + ble in d.components and
            se.compromised = True and
            mcu.compromised = True and
            ble.compromised = True
        
        // Device integrity compromised
        d.genuine = False
        d.firmwareCompromised = True
        d.displayTampered = True
        d.communicationsEavesdropped = True
        
        // Security goals breached
        d.pinBypassed = True
        d.seedExtracted = True
    }
}

// =============================================================================
// DEFENSE FAILURE SCENARIOS
// =============================================================================

// Scenario 14: Defense Bypass Through Supply Chain
pred DefenseBypassSupplyChain {
    // Even vigilant users can be compromised through supply chain
    some d: Device, a: Attacker, u: User | {
        // User is vigilant but device is pre-compromised
        u.vigilant = True
        u.verifiedAddress = True
        d in u.trustsDisplay
        
        // But supply chain was compromised
        SupplyChainAttack[d, a]
        
        // User's vigilance doesn't help against pre-compromised device
        d.supplyChainCompromised = True
        d.genuine = False
        d.seedExtracted = True
    }
}

// Scenario 15: Advanced Persistent Threat (APT)
pred AdvancedPersistentThreat {
    // Nation-state level attack with multiple capabilities
    some d: Device, a: Attacker, s: Software, server: Server | {
        // Highly sophisticated attacker
        a.skillLevel = High
        a.hasTools = True
        a.controlsNetwork = True
        
        // Multiple attack vectors deployed
        d.physicalAccess = True
        d in a.hasPhysicalAccess
        
        // Network infrastructure compromised
        server.rogue = True
        server.certificateValid = False
        
        // Software supply chain compromised
        s.compromised = True
        s.malwarePresent = True
        s.hostOSCompromised = True
        
        // Device completely compromised
        d.supplyChainCompromised = True
        d.firmwareCompromised = True
        d.bootloaderUnlocked = True
        
        // All components compromised
        all c: d.components | c.compromised = True
        
        // All security properties violated
        d.genuine = False
        d.pinBypassed = True
        d.seedExtracted = True
        d.displayTampered = True
        d.communicationsEavesdropped = True
    }
}

// =============================================================================
// KEY CONFIDENTIALITY BREACH SCENARIOS
// =============================================================================

// Scenario 16: Minimal Key Compromise - Fault Injection
pred MinimalKeyCompromiseFaultInjection {
    // Simplest attack that breaks key confidentiality
    some d: Device, a: Attacker | {
        FaultInjectionAttack[d, a]
        
        // Minimal conditions for key compromise
        a.skillLevel = High
        a.hasTools = True
        d.physicalAccess = True
        
        // SE compromised directly
        some se: SecureElement | se in d.components and se.compromised = True
        
        // Key confidentiality breached
        d.seedExtracted = True
    }
}

// Scenario 17: Minimal Key Compromise - Supply Chain
pred MinimalKeyCompromiseSupplyChain {
    // Supply chain attack breaks key confidentiality
    some d: Device, a: Attacker | {
        SupplyChainAttack[d, a]
        
        // Pre-compromised device
        d.supplyChainCompromised = True
        d.genuine = False
        
        // Key confidentiality breached from the start
        d.seedExtracted = True
    }
}

// =============================================================================
// ANALYSIS COMMANDS FOR INSTANCES (OPTIMIZED FOR COUNTEREXAMPLES)
// =============================================================================

// Run specific attack scenarios that should break key confidentiality
run NanoSFaultInjectionAttack for 4 but 1 NanoS, 1 Attacker
run NanoXSideChannelAttack for 4 but 1 NanoX, 1 Attacker
run StaxEvilMaidReplacement for 4 but 1 Stax, 1 Attacker
run SupplyChainCompromiseAttack for 4 but 1 Device, 1 Attacker
run CombinedAttackScenario for 4 but 1 Stax, 1 Attacker, 1 Software, 1 User

// Run minimal attacks that break key confidentiality
run MinimalKeyCompromiseFaultInjection for 4 but 1 Device, 1 Attacker
run MinimalKeyCompromiseSupplyChain for 4 but 1 Device, 1 Attacker

// Run sophisticated multi-vector attacks
run SophisticatedAttackChain for 4 but 1 Device, 1 Attacker, 1 Software, 1 User, 1 App
run AdvancedPersistentThreat for 4 but 1 Device, 1 Attacker, 1 Software, 1 Server

// Test defense bypass scenarios
run DefenseBypassSupplyChain for 4 but 1 Device, 1 Attacker, 1 User

// Test wireless and network attacks
run NanoXBLEMITMAttack for 4 but 1 NanoX, 1 Attacker, 1 Software
run RogueHSMServerAttack for 4 but 1 Device, 1 Attacker, 1 Server

// Test software-based attacks
run MaliciousAppInstallation for 4 but 1 Device, 1 Attacker, 1 App

// Compare attack effectiveness across device types
run FaultInjectionAttack for 4 but exactly 3 Device, 1 Attacker
run SupplyChainAttack for 4 but exactly 3 Device, 1 Attacker 