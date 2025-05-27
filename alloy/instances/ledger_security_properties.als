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
    displayTampered: lone Bool,
    communicationsEavesdropped: lone Bool,
    deviceWiped: lone Bool,
    bootloaderUnlocked: lone Bool,
    supplyChainCompromised: lone Bool
}

// Device types
sig NanoS, NanoX, Stax extends Device {}

abstract sig Component {
    compromised: lone Bool,
    hasVulnerability: lone Bool
}

// Component types
sig SecureElement, MCU, Display, Buttons, USB, BLE, NFC extends Component {}

sig Attacker {
    hasPhysicalAccess: set Device,
    hasTools: lone Bool,
    skillLevel: SkillLevel,
    proximity: set Device,
    controlsNetwork: lone Bool
}

enum SkillLevel { Low, Medium, High }
enum Bool { True, False }

sig User {
    vigilant: lone Bool,
    deceived: lone Bool,
    trustsDisplay: set Device,
    verifiedAddress: lone Bool
}

sig Software {
    compromised: lone Bool,
    malwarePresent: lone Bool,
    hostOSCompromised: lone Bool
}

sig Server {
    rogue: lone Bool,
    certificateValid: lone Bool
}

sig App {
    malicious: lone Bool,
    installedOn: set Device
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
// ENHANCED ATTACK SCENARIOS (FROM PDDL MODEL)
// =============================================================================

// Fault Injection Attack - can compromise SE directly
pred FaultInjectionAttack[d: Device, a: Attacker] {
    // Requires physical access and high skill
    d.physicalAccess = True
    d in a.hasPhysicalAccess
    a.hasTools = True
    a.skillLevel = High
    
    // Can compromise SE directly, bypassing normal protections
    some se: SecureElement | se in d.components and se.compromised = True
    
    // This leads to seed extraction even without PIN bypass
    d.seedExtracted = True
}

// Side Channel Attack - power/EM/timing analysis
pred SideChannelAttack[d: Device, a: Attacker] {
    // Requires physical access and sophisticated tools
    d.physicalAccess = True
    d in a.hasPhysicalAccess
    a.hasTools = True
    a.skillLevel = High
    
    // Can extract secrets through side channels
    some se: SecureElement | se in d.components and se.compromised = True
    d.seedExtracted = True
}

// Timing Attack on PIN Entry
pred TimingAttackPIN[d: Device, a: Attacker] {
    // Physical access required
    d.physicalAccess = True
    d in a.hasPhysicalAccess
    a.skillLevel = High
    
    // Can bypass PIN through timing analysis
    d.pinBypassed = True
}

// Supply Chain Attack - device pre-compromised
pred SupplyChainAttack[d: Device, a: Attacker] {
    // Sophisticated attacker compromises supply chain
    a.skillLevel = High
    a.hasTools = True
    
    // Device appears genuine but is compromised
    d.genuine = False
    d.supplyChainCompromised = True
    d.firmwareCompromised = True
    
    // Multiple components pre-compromised
    some se: SecureElement, mcu: MCU | 
        se in d.components and mcu in d.components and
        se.compromised = True and mcu.compromised = True
    
    // PIN can be captured and seed extracted
    d.pinBypassed = True
    d.seedExtracted = True
}

// Evil Maid Attack with Device Replacement
pred EvilMaidDeviceReplacement[d: Device, a: Attacker] {
    // Attacker has physical access and tools
    d in a.hasPhysicalAccess
    a.hasTools = True
    a.skillLevel = High
    
    // Device is replaced with monitoring version
    d.genuine = False
    d.communicationsEavesdropped = True
    
    // All components compromised in replacement device
    all c: d.components | c.compromised = True
    
    // PIN captured and seed extracted
    d.pinBypassed = True
    d.seedExtracted = True
}

// Bootloader Exploit Attack
pred BootloaderExploitAttack[d: Device, a: Attacker] {
    // Physical access and tools required
    d.physicalAccess = True
    d in a.hasPhysicalAccess
    a.hasTools = True
    a.skillLevel = High
    
    // Bootloader unlocked through exploit
    d.bootloaderUnlocked = True
    d.firmwareCompromised = True
    
    // Can compromise SE through firmware
    some se: SecureElement | se in d.components and se.compromised = True
    d.seedExtracted = True
}

// Malicious App Installation Attack
pred MaliciousAppAttack[d: Device, a: Attacker, app: App] {
    // Attacker installs malicious app
    a.hasTools = True
    app.malicious = True
    d in app.installedOn
    
    // App can compromise device components
    some mcu: MCU | mcu in d.components and mcu.compromised = True
    
    // May lead to display tampering
    d.displayTampered = True
}

// Combined Physical + Software Attack
pred CombinedPhysicalSoftwareAttack[d: Device, a: Attacker, s: Software, u: User] {
    // Physical access gained
    d.physicalAccess = True
    d in a.hasPhysicalAccess
    a.hasTools = True
    a.skillLevel = High
    
    // Software environment compromised
    s.compromised = True
    s.malwarePresent = True
    s.hostOSCompromised = True
    
    // User social engineered
    u.vigilant = False
    u.deceived = True
    
    // Multiple attack vectors succeed
    some mcu: MCU, se: SecureElement |
        mcu in d.components and se in d.components and
        mcu.compromised = True and se.compromised = True
    
    // PIN bypass and seed extraction
    d.pinBypassed = True
    d.seedExtracted = True
}

// BLE Man-in-the-Middle Attack
pred BLEMITMAttack[d: Device, a: Attacker, s: Software] {
    // Device has BLE capability
    some ble: BLE | ble in d.components
    
    // Attacker in proximity
    d in a.proximity
    a.hasTools = True
    a.skillLevel = High
    
    // BLE and software compromised
    some ble: BLE | ble in d.components and ble.compromised = True
    s.compromised = True
    
    // Communications eavesdropped
    d.communicationsEavesdropped = True
}

// Rogue HSM Server Attack
pred RogueHSMAttack[d: Device, a: Attacker, s: Server] {
    // Attacker controls network
    a.controlsNetwork = True
    a.skillLevel = High
    
    // Rogue server deployed
    s.rogue = True
    s.certificateValid = False
    
    // Firmware can be compromised through rogue HSM
    d.firmwareCompromised = True
}

// =============================================================================
// ENHANCED SECURITY PROPERTIES
// =============================================================================

// Enhanced Key Confidentiality Property - SIMPLIFIED FOR COUNTEREXAMPLES
pred KeyConfidentiality[d: Device] {
    // Key confidentiality is violated if seed is extracted
    // This should NOT happen under normal conditions
    d.seedExtracted != True
}

// Display Integrity Property (Enhanced)
pred DisplayIntegrity[d: Device] {
    // Display integrity compromised if:
    // 1. MCU compromised (for MCU-driven displays), OR
    // 2. Display tampered, OR
    // 3. Device not genuine
    
    (some mcu: MCU | mcu in d.components and mcu.compromised = True) or
    d.displayTampered = True or
    d.genuine = False
    implies
    (no u: User | d in u.trustsDisplay)
}

// Device Genuineness Property (Enhanced)
pred DeviceGenuineness[d: Device] {
    // Device genuineness can be compromised through:
    // 1. Supply chain attacks, OR
    // 2. Evil maid attacks with replacement, OR
    // 3. Sophisticated physical attacks
    
    d.supplyChainCompromised = True or
    (some a: Attacker | d in a.hasPhysicalAccess and a.skillLevel = High and a.hasTools = True)
    implies d.genuine != True
}

// PIN Security Property (Enhanced)
pred PINSecurity[d: Device] {
    // PIN can be bypassed through:
    // 1. Physical attacks with tools, OR
    // 2. Timing attacks, OR
    // 3. Supply chain compromise, OR
    // 4. Firmware compromise
    
    d.pinBypassed = True implies (
        (d.physicalAccess = True and 
         some a: Attacker | d in a.hasPhysicalAccess and (a.hasTools = True or a.skillLevel = High)) or
        d.supplyChainCompromised = True or
        d.firmwareCompromised = True
    )
}

// =============================================================================
// SECURITY GOALS AND ASSERTIONS
// =============================================================================

// Assert that key confidentiality holds under normal conditions
assert KeyConfidentialityAssertion {
    all d: Device | KeyConfidentiality[d]
}

// Assert that display integrity is maintained
assert DisplayIntegrityAssertion {
    all d: Device | DisplayIntegrity[d]
}

// Assert that PIN security mechanisms work as expected
assert PINSecurityAssertion {
    all d: Device | PINSecurity[d]
}

// Assert that device genuineness can be verified
assert DeviceGenuinenessAssertion {
    all d: Device | DeviceGenuineness[d]
}

// =============================================================================
// ANALYSIS PREDICATES
// =============================================================================

// Find scenarios where security is compromised
pred SecurityCompromised {
    some d: Device | {
        d.seedExtracted = True or
        d.firmwareCompromised = True or
        (some se: SecureElement | se in d.components and se.compromised = True) or
        d.supplyChainCompromised = True
    }
}

// Find scenarios where multiple attack vectors succeed
pred MultiVectorAttack {
    some d: Device, a: Attacker, s: Software, u: User | {
        CombinedPhysicalSoftwareAttack[d, a, s, u] and
        d.seedExtracted = True
    }
}

// Find sophisticated attack scenarios
pred SophisticatedAttack {
    some d: Device, a: Attacker | {
        a.skillLevel = High and a.hasTools = True and
        (FaultInjectionAttack[d, a] or SideChannelAttack[d, a] or SupplyChainAttack[d, a]) and
        d.seedExtracted = True
    }
}

// Find minimal attack scenarios that break key confidentiality
pred MinimalKeyCompromise {
    some d: Device, a: Attacker | {
        (FaultInjectionAttack[d, a] or SideChannelAttack[d, a] or SupplyChainAttack[d, a]) and
        d.seedExtracted = True
    }
}

// =============================================================================
// COMMANDS FOR ANALYSIS
// =============================================================================

// Check security properties (these should find counterexamples now)
check KeyConfidentialityAssertion for 4 but 1 Device, 1 Attacker
check DisplayIntegrityAssertion for 4 but 1 Device, 1 User  
check PINSecurityAssertion for 4 but 1 Device, 1 Attacker
check DeviceGenuinenessAssertion for 4 but 1 Device, 1 Attacker

// Find attack scenarios
run SecurityCompromised for 4 but 1 Device, 1 Attacker
run MultiVectorAttack for 4 but 1 Device, 1 Attacker, 1 Software, 1 User
run SophisticatedAttack for 4 but 1 Device, 1 Attacker
run MinimalKeyCompromise for 4 but 1 Device, 1 Attacker

// Test specific attack types
run FaultInjectionAttack for 4 but 1 Device, 1 Attacker
run SideChannelAttack for 4 but 1 Device, 1 Attacker
run SupplyChainAttack for 4 but 1 Device, 1 Attacker
run EvilMaidDeviceReplacement for 4 but 1 Device, 1 Attacker
run BootloaderExploitAttack for 4 but 1 Device, 1 Attacker

// Analyze specific device types under attack
run FaultInjectionAttack for 4 but 1 NanoS, 1 Attacker
run SideChannelAttack for 4 but 1 NanoX, 1 Attacker
run SupplyChainAttack for 4 but 1 Stax, 1 Attacker

// Test simple attacks that should violate key confidentiality
run SimpleSeCompromiseAttack for 4 but 1 Device, 1 Attacker
run SimpleSupplyChainAttack for 4 but 1 Device, 1 Attacker  
run SimpleFirmwarePinAttack for 4 but 1 Device, 1 Attacker

// Test if these simple attacks violate the assertion
check KeyConfidentialityAssertion for 4 but 1 Device, 1 Attacker, exactly 1 SecureElement

// =============================================================================
// SIMPLE ATTACK SCENARIOS FOR COUNTEREXAMPLE GENERATION
// =============================================================================

// Simple SE Compromise Attack - directly violates key confidentiality
pred SimpleSeCompromiseAttack {
    some d: Device, a: Attacker, se: SecureElement | {
        // Basic setup
        se in d.components
        d in a.hasPhysicalAccess
        a.skillLevel = High
        a.hasTools = True
        d.physicalAccess = True
        
        // SE gets compromised - this will trigger seed extraction via fact
        se.compromised = True
        
        // Verify the attack violates key confidentiality
        not KeyConfidentiality[d]
    }
}

// Simple Supply Chain Attack - directly violates key confidentiality  
pred SimpleSupplyChainAttack {
    some d: Device, a: Attacker | {
        // Attacker compromises supply chain
        a.skillLevel = High
        a.hasTools = True
        
        // Device is pre-compromised - this will trigger seed extraction via fact
        d.supplyChainCompromised = True
        d.genuine = False
        
        // Verify the attack violates key confidentiality
        not KeyConfidentiality[d]
    }
}

// Simple Firmware + PIN Attack - directly violates key confidentiality
pred SimpleFirmwarePinAttack {
    some d: Device, a: Attacker | {
        // Attacker gains access
        d in a.hasPhysicalAccess
        a.skillLevel = High
        a.hasTools = True
        d.physicalAccess = True
        
        // Both firmware and PIN compromised - this will trigger seed extraction via fact
        d.firmwareCompromised = True
        d.pinBypassed = True
        
        // Verify the attack violates key confidentiality
        not KeyConfidentiality[d]
    }
}

// =============================================================================
// ATTACK ENABLING FACTS
// =============================================================================

// Fact: SE compromise leads to seed extraction
fact SECompromiseLeadsToSeedExtraction {
    all d: Device | {
        (some se: SecureElement | se in d.components and se.compromised = True)
        implies d.seedExtracted = True
    }
}

// Fact: Supply chain compromise leads to seed extraction
fact SupplyChainCompromiseLeadsToSeedExtraction {
    all d: Device | {
        d.supplyChainCompromised = True implies d.seedExtracted = True
    }
}

// Fact: Firmware + PIN compromise leads to seed extraction
fact FirmwarePinCompromiseLeadsToSeedExtraction {
    all d: Device | {
        (d.firmwareCompromised = True and d.pinBypassed = True)
        implies d.seedExtracted = True
    }
}

// Fact: Non-genuine device with PIN bypass leads to seed extraction
fact NonGenuinePinBypassLeadsToSeedExtraction {
    all d: Device | {
        (d.genuine = False and d.pinBypassed = True)
        implies d.seedExtracted = True
    }
}

// ============================================================================= 