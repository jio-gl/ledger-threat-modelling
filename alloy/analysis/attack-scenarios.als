// Ledger Attack Scenarios - Concrete Instances
// This file contains specific instances demonstrating various attack scenarios

module attack_scenarios

open ledger_security_properties

// =============================================================================
// PHYSICAL ATTACK SCENARIOS
// =============================================================================

// Scenario 1: Basic Physical Attack on Nano S
pred NanoSPhysicalAttack {
    // Attacker gains physical access and compromises MCU
    some d: NanoS, a: Attacker | {
        // Initial state: genuine device
        d.genuine = True
        
        // Attacker gains physical access
        d in a.hasPhysicalAccess
        d.physicalAccess = True
        a.hasTools = True
        a.skillLevel = High
        
        // Attacker compromises MCU and this enables display tampering
        some mcu: MCU, disp: Display | 
            mcu in d.components and mcu.compromised = True and
            disp in d.components and mcu in disp.connectedTo and 
            disp.compromised = True
        
        // PIN bypass becomes possible
        d.pinBypassed = True
        
        // But SE remains secure initially
        all se: SecureElement | se in d.components implies se.compromised != True
    }
}

// Scenario 2: Evil Maid Attack on Stax
pred StaxEvilMaidAttack {
    // Device replacement with PIN-capturing clone
    some d: Stax, a: Attacker | {
        // Device appears genuine but is actually replaced
        d.genuine = False
        
        // Attacker has sophisticated capabilities
        d in a.hasPhysicalAccess
        a.hasTools = True
        a.skillLevel = High
        
        // Multiple components compromised in clone device
        some se: SecureElement, mcu: MCU, touch: Display |
            se + mcu + touch in d.components and
            se.compromised = True and
            mcu.compromised = True and
            touch.compromised = True
        
        // Communications are eavesdropped
        some ble: BLE, nfc: NFC | ble + nfc in d.components and
            ble.compromised = True and nfc.compromised = True
        
        // PIN bypass achieved
        d.pinBypassed = True
    }
}

// Scenario 3: Sophisticated SE Attack with Fault Injection
pred SEFaultInjectionAttack {
    // Advanced physical attack targeting Secure Element
    some d: NanoX, a: Attacker | {
        // Legitimate device under attack
        d.genuine = True
        d.physicalAccess = True
        d in a.hasPhysicalAccess
        
        // Highly skilled attacker with specialized tools
        a.hasTools = True
        a.skillLevel = High
        
        // Fault injection compromises SE
        some se: SecureElement | se in d.components and se.compromised = True
        
        // PIN bypass through fault injection
        d.pinBypassed = True
        
        // Seed extraction becomes possible
        d.seedExtracted = True
        
        // But display remains secure (SE-driven on Nano X)
        all disp: Display | disp in d.components implies disp.compromised != True
    }
}

// =============================================================================
// WIRELESS ATTACK SCENARIOS
// =============================================================================

// Scenario 4: BLE Proximity Attack on Nano X
pred NanoXBLEAttack {
    // Attacker in BLE range performing proximity attack
    some d: NanoX, a: Attacker, u: User | {
        // Legitimate device with BLE enabled
        d.genuine = True
        d.physicalAccess = False
        
        // Attacker in proximity but no physical access
        d in a.proximity
        not (d in a.hasPhysicalAccess)
        a.skillLevel = High
        a.hasTools = True
        
        // BLE component is targeted
        some ble: BLE | ble in d.components and ble.compromised = True
        
        // User is not vigilant
        u.vigilant = False
        
        // Communications can be eavesdropped
        // But device core remains secure
        all se: SecureElement | se in d.components implies se.compromised != True
        d.pinBypassed != True
        d.seedExtracted != True
    }
}

// Scenario 5: NFC Eavesdropping on Stax
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
        
        // Limited impact - just eavesdropping
        d.seedExtracted != True
        d.pinBypassed != True
        all se: SecureElement | se in d.components implies se.compromised != True
    }
}

// =============================================================================
// SOFTWARE/SOCIAL ATTACK SCENARIOS
// =============================================================================

// Scenario 6: Ledger Live Compromise with Phishing
pred LedgerLivePhishingAttack {
    // Software compromise combined with social engineering
    some d: Device, u: User, s: Software, a: Attacker | {
        // Legitimate device
        d.genuine = True
        d.physicalAccess = False
        
        // Software compromise
        s.compromised = True
        s.malwarePresent = True
        
        // Social engineering success
        u.vigilant = False
        u.deceived = True
        
        // Attacker capabilities
        a.skillLevel = Medium
        
        // User trust in device display is manipulated
        d in u.trustsDisplay
        
        // But hardware wallet display integrity depends on architecture
        // If SE drives display, it remains secure
        all se: SecureElement, disp: Display |
            (se + disp in d.components and se in disp.connectedTo) implies
            disp.compromised != True
    }
}

// Scenario 7: Supply Chain Attack
pred SupplyChainAttack {
    // Pre-compromised device from supply chain
    some d: Device, a: Attacker | {
        // Device appears genuine but is compromised
        d.genuine = False
        
        // Sophisticated supply chain compromise
        a.skillLevel = High
        a.hasTools = True
        
        // Multiple components pre-compromised
        some c1, c2: Component | c1 != c2 and c1 + c2 in d.components and
            c1.compromised = True and c2.compromised = True
        
        // Firmware is compromised
        d.firmwareCompromised = True
        
        // PIN can be captured
        d.pinBypassed = True
        
        // Seed extraction is possible
        d.seedExtracted = True
    }
}

// =============================================================================
// MULTI-VECTOR ATTACK SCENARIOS
// =============================================================================

// Scenario 8: Combined Physical + Software Attack
pred MultiVectorAttack {
    // Sophisticated attack using multiple vectors
    some d: Stax, a: Attacker, u: User, s: Software | {
        // Initially genuine device
        d.genuine = True
        
        // Highly skilled attacker
        a.skillLevel = High
        a.hasTools = True
        
        // Physical access gained
        d.physicalAccess = True
        d in a.hasPhysicalAccess
        
        // Software environment compromised
        s.compromised = True
        s.malwarePresent = True
        
        // User social engineered
        u.vigilant = False
        u.deceived = True
        
        // Multiple components compromised
        some mcu: MCU, ble: BLE, nfc: NFC |
            mcu + ble + nfc in d.components and
            mcu.compromised = True and
            ble.compromised = True and
            nfc.compromised = True
        
        // PIN bypass achieved
        d.pinBypassed = True
        
        // SE might still resist (depending on attack sophistication)
        some se: SecureElement | se in d.components and
            (se.compromised = True implies d.seedExtracted = True)
    }
}

// =============================================================================
// DEFENSE SUCCESS SCENARIOS
// =============================================================================

// Scenario 9: Successful Defense Against Physical Attack
pred SuccessfulDefense {
    // Device successfully resists attack
    some d: NanoX, a: Attacker, u: User | {
        // Genuine device
        d.genuine = True
        
        // Attacker attempts physical attack
        d.physicalAccess = True
        d in a.hasPhysicalAccess
        a.hasTools = True
        a.skillLevel = Medium  // Not highest skill level
        
        // Vigilant user
        u.vigilant = True
        d in u.trustsDisplay
        
        // PIN protection holds
        d.pinBypassed != True
        
        // SE remains secure
        all se: SecureElement | se in d.components implies se.compromised != True
        
        // Seed remains protected
        d.seedExtracted != True
        
        // Display integrity maintained (SE-driven)
        all disp: Display | disp in d.components implies
            (some se: SecureElement | se in disp.connectedTo) implies
            disp.compromised != True
    }
}

// Scenario 10: Device Wipe Defense Mechanism
pred DeviceWipeDefense {
    // Device wipes itself after attack attempts
    some d: Device, a: Attacker | {
        // Genuine device under attack
        d.genuine = True
        d.physicalAccess = True
        d in a.hasPhysicalAccess
        
        // Attack attempts fail, trigger wipe
        d.pinBypassed != True  // PIN attacks failed
        
        // Seed becomes unavailable
        d.seedExtracted != True
        
        // Device is protected even with physical access
        all se: SecureElement | se in d.components implies se.compromised != True
    }
}

// =============================================================================
// ANALYSIS COMMANDS FOR INSTANCES (REFACTORED FOR EFFICIENCY)
// =============================================================================

// Run specific attack scenarios with reduced scope
run NanoSPhysicalAttack for 3 but 1 NanoS, 1 Attacker
run StaxEvilMaidAttack for 3 but 1 Stax, 1 Attacker  
run SEFaultInjectionAttack for 3 but 1 NanoX, 1 Attacker
run NanoXBLEAttack for 3 but 1 NanoX, 1 Attacker, 1 User
run StaxNFCEavesdropping for 3 but 1 Stax, 1 Attacker
run LedgerLivePhishingAttack for 3 but 1 Device, 1 User, 1 Software, 1 Attacker
run SupplyChainAttack for 3 but 1 Device, 1 Attacker
run MultiVectorAttack for 3 but 1 Stax, 1 Attacker, 1 User, 1 Software
run SuccessfulDefense for 3 but 1 NanoX, 1 Attacker, 1 User
run DeviceWipeDefense for 3 but 1 Device, 1 Attacker

// Compare attack success across device types (simplified)
run PhysicalAttack for 3 but exactly 2 Device, 1 Attacker
run WirelessAttack for 3 but exactly 2 Device, 1 Attacker

// Analyze defense effectiveness (simplified)
run SecurityCompromised for 3 but exactly 2 Device
run MultiVectorAttack for 3 but exactly 2 Device, exactly 1 Attacker 