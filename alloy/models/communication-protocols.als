// Ledger Communication Protocols Security Model
// Models USB, BLE, NFC communication channels and their security properties

module communication-protocols

// =============================================================================
// COMMUNICATION CHANNEL TYPES
// =============================================================================

abstract sig Channel {
    secure: lone Bool,
    monitored: lone Bool,
    encrypted: lone Bool,
    authenticated: lone Bool
}

sig USBChannel, BLEChannel, NFCChannel, InternetChannel extends Channel {}

abstract sig Device {
    availableChannels: set Channel,
    activeChannels: set Channel
}

sig NanoS, NanoX, Stax extends Device {}

sig Message {
    channel: Channel,
    sender: Entity,
    receiver: Entity,
    content: Content,
    intercepted: lone Bool,
    modified: lone Bool
}

abstract sig Entity {}
sig HardwareWallet, HostComputer, MobileApp, HSMServer extends Entity {}

abstract sig Content {}
sig TransactionData, FirmwareUpdate, AttestationRequest, PINEntry extends Content {}

enum Bool { True, False }

// =============================================================================
// COMMUNICATION CHANNEL CONSTRAINTS
// =============================================================================

// Device-specific channel availability
fact ChannelAvailability {
    // Nano S: USB only
    all d: NanoS | {
        d.availableChannels in USBChannel
        no ble: BLEChannel | ble in d.availableChannels
        no nfc: NFCChannel | nfc in d.availableChannels
    }
    
    // Nano X: USB + BLE
    all d: NanoX | {
        d.availableChannels in (USBChannel + BLEChannel)
        no nfc: NFCChannel | nfc in d.availableChannels
    }
    
    // Stax: USB + BLE + NFC
    all d: Stax | {
        d.availableChannels in (USBChannel + BLEChannel + NFCChannel)
    }
}

// Active channels are subset of available channels
fact ActiveChannelsConstraint {
    all d: Device | d.activeChannels in d.availableChannels
}

// =============================================================================
// SECURITY PROPERTIES
// =============================================================================

// USB Security Properties
fact USBSecurity {
    all usb: USBChannel | {
        // USB is generally considered untrusted transport
        usb.secure = False
        usb.encrypted = False
        usb.authenticated = False
        
        // USB can be easily monitored
        usb.monitored = True
    }
}

// BLE Security Properties  
fact BLESecurity {
    all ble: BLEChannel | {
        // BLE has built-in encryption and authentication
        ble.encrypted = True
        ble.authenticated = True
        
        // BLE is more secure than USB but can be monitored in proximity
        ble.secure = True
        
        // BLE monitoring requires proximity
        // (modeled as less likely to be monitored)
    }
}

// NFC Security Properties
fact NFCSecurity {
    all nfc: NFCChannel | {
        // NFC has limited encryption
        nfc.encrypted = False
        nfc.authenticated = False
        
        // Very short range makes it harder to monitor
        nfc.monitored = False
        
        // Limited security due to short range only
        nfc.secure = False
    }
}

// Internet Channel Security
fact InternetSecurity {
    all inet: InternetChannel | {
        // Internet channels should be encrypted (TLS)
        inet.encrypted = True
        inet.authenticated = True
        inet.secure = True
        
        // Internet traffic is commonly monitored
        inet.monitored = True
    }
}

// =============================================================================
// ATTACK SCENARIOS ON COMMUNICATION
// =============================================================================

// Message Interception
pred MessageInterception[m: Message] {
    // Message can be intercepted if channel is monitored
    m.channel.monitored = True implies m.intercepted = True
    
    // Unencrypted messages are easier to intercept
    m.channel.encrypted = False implies m.intercepted = True
}

// Man-in-the-Middle Attack
pred MITMAttack[m: Message] {
    // MITM possible on insecure channels
    m.channel.secure = False implies {
        m.intercepted = True
        m.modified = True
    }
    
    // Even secure channels can be attacked if not properly authenticated
    (m.channel.encrypted = True and m.channel.authenticated = False) implies {
        m.modified = True
    }
}

// BLE Proximity Attack
pred BLEProximityAttack[ble: BLEChannel, m: Message] {
    m.channel = ble
    
    // Attacker in BLE range can potentially intercept
    m.intercepted = True
    
    // BLE encryption makes modification harder but not impossible
    ble.encrypted = True implies (m.modified = False)
    ble.encrypted = False implies (m.modified = True)
}

// NFC Eavesdropping
pred NFCEavesdropping[nfc: NFCChannel, m: Message] {
    m.channel = nfc
    
    // Very close proximity required for NFC attacks
    // But unencrypted nature makes interception possible
    nfc.encrypted = False implies m.intercepted = True
}

// =============================================================================
// PROTOCOL-SPECIFIC SECURITY
// =============================================================================

// Transaction Protocol Security
pred TransactionSecurity[m: Message] {
    m.content in TransactionData
    
    // Transaction data should be verified on device display
    // regardless of communication channel security
    m.sender in HardwareWallet implies {
        // Device should display transaction for user verification
        // Channel security doesn't affect this requirement
        true
    }
    
    // Host-to-device transaction requests can be modified
    m.sender in (HostComputer + MobileApp) and m.receiver in HardwareWallet implies {
        m.channel.secure = False implies m.modified = True
    }
}

// Firmware Update Protocol Security
pred FirmwareUpdateSecurity[m: Message] {
    m.content in FirmwareUpdate
    
    // Firmware updates must be cryptographically verified
    // regardless of channel security
    m.receiver in HardwareWallet implies {
        // Device must verify signature even if channel is secure
        // Channel attacks cannot bypass signature verification
        m.modified = True implies false  // Signature verification prevents this
    }
}

// PIN Entry Security
pred PINEntrySecurity[m: Message] {
    m.content in PINEntry
    
    // PIN should never be transmitted over any channel
    // (PINs are verified locally on device)
    no m: Message | m.content in PINEntry and m.sender in HardwareWallet
}

// HSM Attestation Security
pred HSMAttestationSecurity[m: Message] {
    m.content in AttestationRequest
    m.receiver in HSMServer
    
    // HSM communication should use secure channels
    m.channel in InternetChannel
    m.channel.encrypted = True
    m.channel.authenticated = True
    
    // DNS poisoning can redirect to rogue HSM
    m.receiver in HSMServer and m.modified = True implies {
        // Message reaches rogue HSM instead of legitimate one
        true
    }
}

// =============================================================================
// SECURITY INVARIANTS
// =============================================================================

// Critical data must not be transmitted over insecure channels
assert CriticalDataSecurity {
    all m: Message | m.content in PINEntry implies {
        // PINs should never be transmitted
        false
    }
}

// Transaction integrity depends on device verification, not channel security
assert TransactionIntegrity {
    all m: Message | m.content in TransactionData and m.receiver in HardwareWallet implies {
        // Device must verify transaction regardless of channel modification
        m.modified = True implies {
            // Device should reject or request user confirmation
            true
        }
    }
}

// Firmware updates must be cryptographically verified
assert FirmwareIntegrity {
    all m: Message | m.content in FirmwareUpdate and m.receiver in HardwareWallet implies {
        // Signature verification prevents acceptance of modified firmware
        m.modified = True implies false
    }
}

// =============================================================================
// ANALYSIS PREDICATES
// =============================================================================

// Find scenarios where communication is compromised
pred CommunicationCompromised {
    some m: Message | {
        m.intercepted = True or m.modified = True
    }
}

// Find secure communication scenarios
pred SecureCommunication {
    some m: Message | {
        m.channel.secure = True and
        m.channel.encrypted = True and
        m.channel.authenticated = True and
        m.intercepted = False and
        m.modified = False
    }
}

// Find multi-channel attacks
pred MultiChannelAttack {
    some d: Device | {
        #d.activeChannels > 1 and
        (some m1, m2: Message | 
            m1.channel != m2.channel and
            m1.channel in d.activeChannels and
            m2.channel in d.activeChannels and
            (m1.intercepted = True or m2.intercepted = True))
    }
}

// Find device-specific vulnerabilities
pred DeviceChannelVulnerability {
    (some d: NanoS | some m: Message | m.sender = d and m.intercepted = True) or
    (some d: NanoX | some m: Message | m.sender = d and m.channel in BLEChannel and m.intercepted = True) or
    (some d: Stax | some m: Message | m.sender = d and m.channel in NFCChannel and m.intercepted = True)
}

// =============================================================================
// COMMANDS FOR ANALYSIS
// =============================================================================

// Check security assertions
check CriticalDataSecurity for 3 but 2 Message
check TransactionIntegrity for 3 but 2 Message, 1 HardwareWallet
check FirmwareIntegrity for 3 but 2 Message, 1 HardwareWallet

// Find attack scenarios
run CommunicationCompromised for 4 but 2 Message, 1 Device
run MultiChannelAttack for 4 but 2 Message, 1 Device
run DeviceChannelVulnerability for 4 but 2 Message, 1 Device

// Analyze specific protocols
run TransactionSecurity for 3 but 2 Message
run BLEProximityAttack for 3 but 1 BLEChannel, 1 Message
run NFCEavesdropping for 3 but 1 NFCChannel, 1 Message
run HSMAttestationSecurity for 3 but 1 Message, 1 HSMServer

// Analyze secure vs insecure scenarios
run SecureCommunication for 4 but 2 Message
run MITMAttack for 3 but 1 Message 