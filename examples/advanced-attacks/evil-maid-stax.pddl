;; Advanced Evil Maid Attack Example - Stax
;; This demonstrates a sophisticated device replacement attack

(define (problem advanced-evil-maid-stax)
  (:domain ledger-comprehensive-threat-model)

  (:objects
    ;; Device
    stax - device
    
    ;; Components
    se-stax - secure-element
    mcu-stax - mcu
    touchscreen-stax - peripheral
    nfc-chip-stax - peripheral
    ble-module-stax - peripheral
    usb-connector-stax - peripheral
    
    ;; Servers
    ledger-hsm - server
    rogue-hsm - server
    
    ;; Entities
    sophisticated-attacker - attacker
    target-user - user
    
    ;; Software
    ledger-live - software
    host-os - software
    
    ;; Keys and Apps
    master-key - key
    btc-app - app
    eth-app - app
    
    ;; Firmware
    original-firmware - firmware
    malicious-firmware - firmware
    
    ;; Channels
    usb-ch - channel
    ble-ch - channel
    nfc-ch - channel
    internet-ch - channel
  )

  (:init
    ;; ===== Device Initial State =====
    (genuine stax)  ;; Device appears genuine but is actually replaced
    (not (physical-access stax))
    (not (pin-bypassed stax))
    (not (pin-captured stax))
    (not (seed-extracted stax))
    (not (communications-eavesdropped stax))
    (master-seed-present stax)
    (wireless-enabled stax)
    
    ;; ===== Component Architecture =====
    (belongs-to se-stax stax)
    (belongs-to mcu-stax stax)
    (belongs-to touchscreen-stax stax)
    (belongs-to nfc-chip-stax stax)
    (belongs-to ble-module-stax stax)
    (belongs-to usb-connector-stax stax)
    
    ;; Stax connections
    (connected se-stax mcu-stax)
    (connected mcu-stax se-stax)
    (connected se-stax touchscreen-stax)
    (connected mcu-stax nfc-chip-stax)
    (connected mcu-stax ble-module-stax)
    (connected mcu-stax usb-connector-stax)
    
    ;; Component security state (initially secure)
    (not (compromised se-stax))
    (not (compromised mcu-stax))
    (not (compromised touchscreen-stax))
    (not (compromised nfc-chip-stax))
    (not (compromised ble-module-stax))
    
    ;; ===== Wireless & Proximity =====
    (not (within-ble-range stax))
    (not (within-nfc-range stax))
    (not (in-faraday-cage stax))
    (ble-paired stax ledger-live)
    
    ;; ===== HSM Configuration =====
    (not (connected-hsm stax ledger-hsm))
    (not (connected-hsm stax rogue-hsm))
    (not (passed-genuine-check stax))
    (not (blocked-by-hsm stax))
    (not (rogue ledger-hsm))
    (not (rogue rogue-hsm))  ;; Will become rogue during attack
    (hsm-certificate-valid ledger-hsm)
    (not (hsm-certificate-valid rogue-hsm))
    
    ;; ===== Attacker Capabilities =====
    (not (attacker-has-physical-access sophisticated-attacker stax))
    (attacker-has-tools sophisticated-attacker)
    (attacker-skill-level-high sophisticated-attacker)
    (not (attacker-in-proximity sophisticated-attacker stax))
    (attacker-controls-network sophisticated-attacker)  ;; Can perform DNS attacks
    
    ;; ===== User Properties =====
    (user-vigilant target-user)
    (not (user-deceived target-user))
    (user-trusts-display target-user stax)
    (not (phishing-attempt-successful target-user))
    
    ;; ===== Software Environment =====
    (ledgerlive-running ledger-live stax)
    (not (ledgerlive-compromised ledger-live))
    (not (host-os-compromised host-os))
    
    ;; ===== Keys and Apps =====
    (app-installed btc-app stax)
    (app-installed eth-app stax)
    (key-derived master-key stax)
    (not (key-exposed master-key))
    
    ;; ===== Firmware =====
    (firmware-version original-firmware stax)
    (not (firmware-vulnerable original-firmware))
    (firmware-vulnerable malicious-firmware)
    (not (rollback-protection-active stax))
    
    ;; ===== Communication Channels =====
    (channel-available usb-ch stax)
    (channel-available ble-ch stax)
    (channel-available nfc-ch stax)
    (channel-available internet-ch stax)
    (channel-secure usb-ch)
    (channel-secure ble-ch)
    (channel-secure nfc-ch)
    (channel-secure internet-ch)
  )

  ;; ===== Attack Goal =====
  ;; Goal: Complete evil maid attack with PIN capture and communications compromise
  (:goal 
    (and
      ;; Device replacement successful
      (not (genuine stax))
      (physical-access stax)
      
      ;; PIN capture mechanism active
      (pin-captured stax)
      
      ;; Communications compromised
      (communications-eavesdropped stax)
      
      ;; Multiple components compromised
      (compromised se-stax)
      (compromised mcu-stax)
      (compromised touchscreen-stax)
      
      ;; Network infrastructure compromised
      (connected-hsm stax rogue-hsm)
      
      ;; User deceived about device genuineness
      (user-deceived target-user)
    )
  )
)

;; Expected attack sequence:
;; 1. gain-physical-access(sophisticated-attacker, stax)
;; 2. evil-maid-attack(sophisticated-attacker, stax)
;; 3. deploy-rogue-hsm(sophisticated-attacker, rogue-hsm)
;; 4. dns-poison-hsm(sophisticated-attacker, stax, ledger-hsm, rogue-hsm)
;; 5. social-engineering-attack(sophisticated-attacker, target-user)
;;
;; This advanced attack demonstrates how a sophisticated attacker can:
;; - Replace the device with a malicious clone
;; - Set up network infrastructure to bypass genuineness checks
;; - Capture PINs and eavesdrop on all communications
;; - Deceive even vigilant users about the device's authenticity 