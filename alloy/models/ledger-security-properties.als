// Ledger Hardware Wallet Security Properties Model
// This model captures the core security properties and attack scenarios
// for Ledger devices using Alloy's formal specification language

module ledger-security-properties

// =============================================================================
// BASIC SIGNATURES AND TYPES
// =============================================================================

abstract sig Device {
    components: set Component,
    genuine: lone Bool,
    physicalAccess: lone Bool,
    pinBypassed: lone Bool,
    seedExtracted: lone Bool,
    firmwareCompromised: lone Bool
}

// Device types
sig NanoS, NanoX, Stax extends Device {}

abstract sig Component {
    belongsTo: Device,
    compromised: lone Bool,
    connectedTo: set Component
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
// DEVICE ARCHITECTURE CONSTRAINTS
// =============================================================================

// All components belong to exactly one device
fact ComponentBelonging {
    all c: Component | one d: Device | c in d.components and c.belongsTo = d
}

// Device-specific architecture constraints
fact NanoSArchitecture {
    all d: NanoS | {
        // Nano S has SE, MCU, Display, Buttons, USB
        one se: SecureElement, one mcu: MCU, one disp: Display, 
        one btn: Buttons, one usb: USB | 
        d.components = se + mcu + disp + btn + usb
        
        // MCU drives display and buttons (security concern)
        mcu in disp.connectedTo
        mcu in btn.connectedTo
        
        // SE and MCU are connected
        se in mcu.connectedTo and mcu in se.connectedTo
        
        // No wireless components
        no ble: BLE | ble in d.components
        no nfc: NFC | nfc in d.components
    }
}

fact NanoXArchitecture {
    all d: NanoX | {
        // Nano X has SE, MCU, Display, Buttons, USB, BLE
        one se: SecureElement, one mcu: MCU, one disp: Display,
        one btn: Buttons, one usb: USB, one ble: BLE |
        d.components = se + mcu + disp + btn + usb + ble
        
        // SE drives display and buttons (security improvement)
        se in disp.connectedTo
        se in btn.connectedTo
        
        // MCU handles wireless and USB
        mcu in ble.connectedTo and mcu in usb.connectedTo
        
        // SE and MCU are connected
        se in mcu.connectedTo and mcu in se.connectedTo
    }
}

fact StaxArchitecture {
    all d: Stax | {
        // Stax has SE, MCU, Display (touchscreen), USB, BLE, NFC
        one se: SecureElement, one mcu: MCU, one disp: Display,
        one usb: USB, one ble: BLE, one nfc: NFC |
        d.components = se + mcu + disp + usb + ble + nfc
        
        // SE drives touchscreen display
        se in disp.connectedTo
        
        // MCU handles all communication interfaces
        mcu in usb.connectedTo and mcu in ble.connectedTo and mcu in nfc.connectedTo
        
        // SE and MCU are connected
        se in mcu.connectedTo and mcu in se.connectedTo
    }
}

// =============================================================================
// SECURITY PROPERTIES AND INVARIANTS
// =============================================================================

// Key Confidentiality Property
pred KeyConfidentiality[d: Device] {
    // If SE is not compromised and PIN not bypassed, seed should not be extracted
    (d.components.compromised != True and d.pinBypassed != True) 
    implies d.seedExtracted != True
}

// Display Integrity Property  
pred DisplayIntegrity[d: Device] {
    // If display-driving component is compromised, display cannot be trusted
    all disp: Display | disp in d.components implies {
        (disp.connectedTo.compromised = True) implies 
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
            disp.connectedTo in SecureElement implies disp.compromised != True
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

// Check security properties
check KeyConfidentialityAssertion for 3 but 1 Device, 1 Attacker
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