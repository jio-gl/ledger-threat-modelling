// Ledger Security Analysis Framework
// Comprehensive analysis methods for evaluating security properties

module security_analysis

open ledger_security_properties
open communication_protocols
open attack_scenarios

// =============================================================================
// SECURITY METRICS AND MEASUREMENT
// =============================================================================

// Security Level Enumeration
enum SecurityLevel { None, Low, Medium, High, Maximum }

// Calculate device security level based on current state
fun deviceSecurityLevel[d: Device]: SecurityLevel {
    (d.seedExtracted = True) => None
    else (d.firmwareCompromised = True) => Low  
    else (d.pinBypassed = True) => Low
    else (some c: d.components | c.compromised = True) => Medium
    else (d.physicalAccess = True) => Medium
    else (d.genuine = False) => Low
    else High
}

// Calculate attack surface size for a device
fun attackSurface[d: Device]: Int {
    #(d.components) +
    (d.physicalAccess = True => 2 else 0) +
    ((some ble: BLE | ble in d.components) => 1 else 0) +
    ((some nfc: NFC | nfc in d.components) => 1 else 0)
}

// Measure compromise depth
fun compromiseDepth[d: Device]: Int {
    #{c: d.components | c.compromised = True} +
    (d.pinBypassed = True => 1 else 0) +
    (d.seedExtracted = True => 2 else 0) +
    (d.firmwareCompromised = True => 2 else 0)
}

// =============================================================================
// SECURITY PROPERTY ANALYSIS
// =============================================================================

// Confidentiality Analysis
pred confidentialityAnalysis[d: Device] {
    // Key confidentiality is maintained if:
    // 1. SE is not compromised, AND
    // 2. PIN is not bypassed, AND  
    // 3. No seed extraction occurred
    
    let seCompromised = (some se: SecureElement | se in d.components and se.compromised = True) |
    let keysSafe = (not seCompromised and d.pinBypassed != True and d.seedExtracted != True) |
    
    keysSafe implies deviceSecurityLevel[d] in (Medium + High + Maximum)
}

// Integrity Analysis
pred integrityAnalysis[d: Device] {
    // Device integrity is maintained if:
    // 1. Device is genuine, AND
    // 2. Firmware is not compromised, AND
    // 3. Display integrity is maintained
    
    let displayIntact = (all disp: Display | disp in d.components implies {
        // If SE drives display, integrity is better
        (some se: SecureElement | se in disp.connectedTo) implies disp.compromised != True
    }) |
    
    (d.genuine = True and d.firmwareCompromised != True and displayIntact) 
    implies deviceSecurityLevel[d] in (Medium + High + Maximum)
}

// Availability Analysis  
pred availabilityAnalysis[d: Device] {
    // Device availability is maintained if device is operational
    let deviceOperational = (d.firmwareCompromised != True) |
    
    deviceOperational implies deviceSecurityLevel[d] != None
}

// =============================================================================
// ATTACK VECTOR ANALYSIS
// =============================================================================

// Physical Attack Vector Analysis
pred physicalAttackVectorAnalysis[d: Device, a: Attacker] {
    d.physicalAccess = True and d in a.hasPhysicalAccess
    
    // Analyze attack progression
    let canBypassPIN = (a.hasTools = True or a.skillLevel = High) |
    let canCompromiseSE = (a.hasTools = True and a.skillLevel = High) |
    let canExtractSeed = (canBypassPIN and canCompromiseSE) |
    
    // Physical attacks are most dangerous
    canExtractSeed implies deviceSecurityLevel[d] = None
}

// Wireless Attack Vector Analysis
pred wirelessAttackVectorAnalysis[d: Device, a: Attacker] {
    d in a.proximity
    
    // Different wireless capabilities have different risk levels
    let bleRisk = (some ble: BLE | ble in d.components) |
    let nfcRisk = (some nfc: NFC | nfc in d.components) |
    
    // Wireless attacks generally limited to eavesdropping
    (bleRisk or nfcRisk) and a.skillLevel = High implies
        deviceSecurityLevel[d] in (Medium + High)  // Not complete compromise
}

// Software Attack Vector Analysis
pred softwareAttackVectorAnalysis[d: Device, s: Software, u: User] {
    s.compromised = True and u.deceived = True
    
    // Software attacks limited by hardware wallet isolation
    let hardwareProtection = (all se: SecureElement | se in d.components implies se.compromised != True) |
    
    hardwareProtection implies deviceSecurityLevel[d] in (Medium + High)
}

// =============================================================================
// COMPARATIVE DEVICE ANALYSIS
// =============================================================================

// Compare security across device types
pred deviceSecurityComparison {
    some ns: NanoS, nx: NanoX, st: Stax | {
        // Nano S: Simpler but MCU drives display
        let nsDisplayRisk = (some mcu: MCU, disp: Display | 
            mcu + disp in ns.components and mcu in disp.connectedTo) |
        
        // Nano X: Better display security, adds BLE
        let nxWirelessRisk = (some ble: BLE | ble in nx.components) |
        let nxDisplaySafe = (some se: SecureElement, disp: Display |
            se + disp in nx.components and se in disp.connectedTo) |
        
        // Stax: Most features, largest attack surface
        let stAttackSurface = attackSurface[st] |
        let stWirelessRisk = (some ble: BLE, nfc: NFC | ble + nfc in st.components) |
        
        // Security ordering under normal conditions
        (nsDisplayRisk and nxDisplaySafe) implies 
            deviceSecurityLevel[nx] >= deviceSecurityLevel[ns]
        
        (stAttackSurface > attackSurface[nx]) implies
            // Stax has larger attack surface but better display security
            true
    }
}

// =============================================================================
// DEFENSE EFFECTIVENESS ANALYSIS
// =============================================================================

// PIN Defense Effectiveness
pred pinDefenseAnalysis[d: Device, a: Attacker] {
    // PIN protection effectiveness varies by attack type
    let physicalAccess = (d.physicalAccess = True and d in a.hasPhysicalAccess) |
    let highSkillAttacker = (a.skillLevel = High) |
    let specializedTools = (a.hasTools = True) |
    
    // PIN can be bypassed under certain conditions
    (physicalAccess and (highSkillAttacker or specializedTools)) implies
        d.pinBypassed = True
}

// SE Defense Effectiveness
pred seDefenseAnalysis[d: Device, a: Attacker] {
    some se: SecureElement | se in d.components and {
        // SE provides strongest defense
        let physicalAttack = (d.physicalAccess = True and a.hasTools = True) |
        let sophisticatedAttack = (physicalAttack and a.skillLevel = High) |
        
        // SE compromise requires sophisticated physical attack
        se.compromised = True implies sophisticatedAttack
        
        // SE compromise enables seed extraction
        (se.compromised = True and d.pinBypassed = True) implies
            d.seedExtracted = True
    }
}

// Display Defense Effectiveness  
pred displayDefenseAnalysis[d: Device] {
    all disp: Display | disp in d.components implies {
        // SE-driven displays are more secure
        let seDriven = (some se: SecureElement | se in disp.connectedTo) |
        let mcuDriven = (some mcu: MCU | mcu in disp.connectedTo and not seDriven) |
        
        // MCU compromise affects MCU-driven displays
        mcuDriven and (some mcu: MCU | mcu in d.components and mcu.compromised = True)
            implies disp.compromised = True
        
        // SE-driven displays resist MCU compromise
        seDriven and (some se: SecureElement | se in d.components and se.compromised != True)
            implies disp.compromised != True
    }
}

// =============================================================================
// ATTACK SUCCESS PROBABILITY ANALYSIS
// =============================================================================

// Model attack success likelihood
fun attackSuccessProbability[d: Device, a: Attacker]: Int {
    let baseSuccess = 0 |
    let physicalBonus = (d.physicalAccess = True => 3 else 0) |
    let skillBonus = (a.skillLevel = High => 2 else (a.skillLevel = Medium => 1 else 0)) |
    let toolsBonus = (a.hasTools = True => 2 else 0) |
    let deviceBonus = (d.genuine = False => 3 else 0) |
    
    baseSuccess + physicalBonus + skillBonus + toolsBonus + deviceBonus
}

// =============================================================================
// COMPREHENSIVE SECURITY ASSESSMENT
// =============================================================================

// Overall security assessment combining all factors
pred comprehensiveSecurityAssessment[d: Device] {
    let confLevel = (confidentialityAnalysis[d] => 1 else 0) |
    let intLevel = (integrityAnalysis[d] => 1 else 0) |  
    let availLevel = (availabilityAnalysis[d] => 1 else 0) |
    let surfaceSize = attackSurface[d] |
    let compromiseLevel = compromiseDepth[d] |
    
    // Overall security is function of CIA triad and attack surface
    let overallSecurity = confLevel + intLevel + availLevel - (surfaceSize / 3) - compromiseLevel |
    
    overallSecurity >= 2 implies deviceSecurityLevel[d] in (High + Maximum)
    overallSecurity = 1 implies deviceSecurityLevel[d] = Medium
    overallSecurity <= 0 implies deviceSecurityLevel[d] in (None + Low)
}

// =============================================================================
// SECURITY ANALYSIS COMMANDS
// =============================================================================

// Run comprehensive security analysis
run comprehensiveSecurityAssessment for 4 but exactly 3 Device

// Compare device security levels
run deviceSecurityComparison for 4 but 1 NanoS, 1 NanoX, 1 Stax

// Analyze attack vector effectiveness
run physicalAttackVectorAnalysis for 3 but 1 Device, 1 Attacker
run wirelessAttackVectorAnalysis for 3 but 1 Device, 1 Attacker  
run softwareAttackVectorAnalysis for 3 but 1 Device, 1 Software, 1 User

// Analyze defense mechanisms
run pinDefenseAnalysis for 3 but 1 Device, 1 Attacker
run seDefenseAnalysis for 3 but 1 Device, 1 Attacker
run displayDefenseAnalysis for 3 but 1 Device

// Security property analysis
run confidentialityAnalysis for 3 but 1 Device
run integrityAnalysis for 3 but 1 Device
run availabilityAnalysis for 3 but 1 Device

// Find scenarios with specific security levels
run { some d: Device | deviceSecurityLevel[d] = High } for 4
run { some d: Device | deviceSecurityLevel[d] = Low } for 4
run { some d: Device | deviceSecurityLevel[d] = None } for 4

// Analyze attack success probabilities
run { some d: Device, a: Attacker | attackSuccessProbability[d, a] >= 5 } for 4
run { some d: Device, a: Attacker | attackSuccessProbability[d, a] <= 2 } for 4

// Find optimal attack strategies  
run { some d: Device, a: Attacker | 
    physicalAttackVectorAnalysis[d, a] and deviceSecurityLevel[d] = None } for 4

// Find effective defense configurations
run { some d: Device | 
    comprehensiveSecurityAssessment[d] and deviceSecurityLevel[d] = High } for 4 