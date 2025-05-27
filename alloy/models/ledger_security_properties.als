// Ledger Hardware Wallet Security Properties Model
// This model captures the core security properties and attack scenarios
// for Ledger devices using Alloy's formal specification language

module ledger_security_properties

// =============================================================================
// BASIC SIGNATURES AND TYPES
// =============================================================================

abstract sig Device {
    components: set Component,
    genuine: lone Bool,
    physicalAccess: lone Bool,
    pinBypassed: lone Bool,
    seedExtracted: lone Bool,
    firmwareCompromised: lone Bool,
    supplyChainCompromised: lone Bool
}

// Device types
sig NanoS, NanoX, Stax extends Device {}

abstract sig Component {
    compromised: lone Bool
}

// Component types
sig SecureElement, MCU, Display, Buttons, USB, BLE, NFC extends Component {}

sig Attacker {
    hasPhysicalAccess: set Device,
    hasTools: lone Bool,
    skillLevel: SkillLevel,
    proximity: set Device
}

enum SkillLevel { Low, Medium, High }
enum Bool { True, False }

sig User {
    vigilant: lone Bool,
    deceived: lone Bool,
    trustsDisplay: set Device
}

sig Software {
    compromised: lone Bool,
    malwarePresent: lone Bool
}

// =============================================================================
// DEVICE ARCHITECTURE CONSTRAINTS (RELAXED FOR FEASIBILITY)
// =============================================================================

// Components can belong to devices (relaxed constraint)
fact ComponentBelonging {
    all c: Component | c in Device.components
}

// Device-specific architecture constraints (relaxed)
fact NanoSArchitecture {
    all d: NanoS | {
        // Nano S has SE, MCU, Display, Buttons, USB (at least one of each)
        some se: SecureElement | se in d.components
        some mcu: MCU | mcu in d.components  
        some disp: Display | disp in d.components
        some btn: Buttons | btn in d.components
        some usb: USB | usb in d.components
        
        // No wireless components
        no ble: BLE | ble in d.components
        no nfc: NFC | nfc in d.components
    }
}

fact NanoXArchitecture {
    all d: NanoX | {
        // Nano X has SE, MCU, Display, Buttons, USB, BLE (at least one of each)
        some se: SecureElement | se in d.components
        some mcu: MCU | mcu in d.components
        some disp: Display | disp in d.components
        some btn: Buttons | btn in d.components
        some usb: USB | usb in d.components
        some ble: BLE | ble in d.components
        
        // No NFC
        no nfc: NFC | nfc in d.components
    }
}

fact StaxArchitecture {
    all d: Stax | {
        // Stax has SE, MCU, Display, USB, BLE, NFC (at least one of each)
        some se: SecureElement | se in d.components
        some mcu: MCU | mcu in d.components
        some disp: Display | disp in d.components
        some usb: USB | usb in d.components
        some ble: BLE | ble in d.components
        some nfc: NFC | nfc in d.components
        
        // No buttons (touchscreen)
        no btn: Buttons | btn in d.components
    }
}

// =============================================================================
// SECURITY PROPERTIES AND INVARIANTS
// =============================================================================

// Enhanced Key Confidentiality Property - FIXED LOGIC
pred KeyConfidentiality[d: Device] {
    // Key confidentiality is maintained UNLESS any of these conditions occur:
    // 1. SE is compromised, OR
    // 2. Supply chain is compromised, OR  
    // 3. Firmware is compromised AND PIN bypassed, OR
    // 4. Device is not genuine AND PIN bypassed
    
    // If any of these attack conditions are true, then seed extraction is possible
    (
        (some se: SecureElement | se in d.components and se.compromised = True) or
        d.supplyChainCompromised = True or
        (d.firmwareCompromised = True and d.pinBypassed = True) or
        (d.genuine = False and d.pinBypassed = True)
    ) implies d.seedExtracted = True
    
    // Conversely, if seed is extracted, at least one attack vector succeeded
    d.seedExtracted = True implies (
        (some se: SecureElement | se in d.components and se.compromised = True) or
        d.supplyChainCompromised = True or
        (d.firmwareCompromised = True and d.pinBypassed = True) or
        (d.genuine = False and d.pinBypassed = True)
    )
}

// Display Integrity Property  
pred DisplayIntegrity[d: Device] {
    // If display-driving component is compromised, display cannot be trusted
    all disp: Display | disp in d.components implies {
        (disp.compromised = True) implies 
        (no u: User | d in u.trustsDisplay)
    }
}

// Device Genuineness Property
pred DeviceGenuineness[d: Device] {
    // Physical access without proper verification can lead to non-genuine device
    d.physicalAccess = True implies {
        (some a: Attacker | d in a.hasPhysicalAccess and a.skillLevel = High)
        implies d.genuine != True
    }
}

// PIN Security Property
pred PINSecurity[d: Device] {
    // PIN bypass should only be possible with physical access and certain conditions
    d.pinBypassed = True implies {
        d.physicalAccess = True and
        (some a: Attacker | d in a.hasPhysicalAccess and 
         (a.hasTools = True or a.skillLevel = High))
    }
}

// =============================================================================
// ATTACK SCENARIOS
// =============================================================================

// Physical Attack Scenario
pred PhysicalAttack[d: Device, a: Attacker] {
    // Attacker gains physical access
    d in a.hasPhysicalAccess
    d.physicalAccess = True
    
    // If attacker has tools and high skill, can compromise components
    (a.hasTools = True and a.skillLevel = High) implies {
        some c: d.components | c.compromised = True
    }
    
    // If SE is compromised and PIN bypassed, seed can be extracted
    (some se: SecureElement | se in d.components and se.compromised = True) and
    d.pinBypassed = True implies d.seedExtracted = True
}

// Evil Maid Attack Scenario
pred EvilMaidAttack[d: Device, a: Attacker] {
    // Attacker has physical access and tools
    d in a.hasPhysicalAccess
    a.hasTools = True
    
    // Device becomes non-genuine (replaced or modified)
    d.genuine = False
    
    // Communications can be eavesdropped
    some c: d.components | c.compromised = True
}

// Wireless Attack Scenario (for devices with wireless capabilities)
pred WirelessAttack[d: Device, a: Attacker] {
    // Only applicable to devices with wireless components
    (some ble: BLE | ble in d.components) or (some nfc: NFC | nfc in d.components)
    
    // Attacker in proximity
    d in a.proximity
    
    // Wireless components can be compromised
    a.skillLevel = High implies {
        some wireless: (BLE + NFC) | wireless in d.components and wireless.compromised = True
    }
}

// Software Attack Scenario
pred SoftwareAttack[s: Software, u: User, d: Device] {
    // Software becomes compromised
    s.compromised = True
    s.malwarePresent = True
    
    // User becomes deceived
    u.deceived = True
    u.vigilant = False
    
    // User trust in device display may be manipulated
    d in u.trustsDisplay implies {
        // But hardware wallet display should still be secure if SE drives it
        all disp: Display | disp in d.components implies {
            disp.compromised != True
        }
    }
}

// =============================================================================
// SECURITY GOALS AND ASSERTIONS
// =============================================================================

// Assert that key confidentiality holds under normal conditions
assert KeyConfidentialityAssertion {
    all d: Device | KeyConfidentiality[d]
}

// Assert that display integrity is maintained for SE-driven displays
assert DisplayIntegrityAssertion {
    all d: Device | DisplayIntegrity[d]
}

// Assert that PIN security mechanisms work as expected
assert PINSecurityAssertion {
    all d: Device | PINSecurity[d]
}

// =============================================================================
// ANALYSIS PREDICATES
// =============================================================================

// Find scenarios where security is compromised
pred SecurityCompromised {
    some d: Device | {
        d.seedExtracted = True or
        d.firmwareCompromised = True or
        (some se: SecureElement | se in d.components and se.compromised = True)
    }
}

// Find scenarios where multiple attack vectors succeed
pred MultiVectorAttack {
    some d: Device, a: Attacker, s: Software, u: User | {
        PhysicalAttack[d, a] and
        SoftwareAttack[s, u, d] and
        d.seedExtracted = True
    }
}

// Find minimal attack scenarios
pred MinimalAttack {
    some d: Device, a: Attacker | {
        PhysicalAttack[d, a] and
        d.seedExtracted = True and
        // Minimize compromised components
        #(d.components & compromised.True) <= 2
    }
}

// =============================================================================
// COMMANDS FOR ANALYSIS
// =============================================================================

// Check security properties (these should find counterexamples now)
check KeyConfidentialityAssertion for 4 but 1 Device, 1 Attacker
check DisplayIntegrityAssertion for 3 but 1 Device, 1 User  
check PINSecurityAssertion for 3 but 1 Device, 1 Attacker

// Find attack scenarios
run SecurityCompromised for 4 but 1 Device, 1 Attacker
run MultiVectorAttack for 4 but 1 Device, 1 Attacker, 1 Software, 1 User
run MinimalAttack for 4 but 1 Device, 1 Attacker

// Analyze specific device types
run PhysicalAttack for 3 but 1 NanoS, 1 Attacker
run WirelessAttack for 3 but 1 NanoX, 1 Attacker
run EvilMaidAttack for 3 but 1 Stax, 1 Attacker 