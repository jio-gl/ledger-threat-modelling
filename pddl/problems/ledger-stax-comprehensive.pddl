;; Copyright 2025 Ledger Threat Modelling Project
;;
;; Licensed under the Apache License, Version 2.0 (the "License");
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

(define (problem ledger-stax-comprehensive-threat)
  (:domain ledger-comprehensive-threat-model)

  ;; ==========================================================================
  ;; OBJECTS - Ledger Stax Specific Architecture
  ;; ==========================================================================
  (:objects
    ;; Devices
    stax - device
    
    ;; Servers
    ledger-hsm - server
    rogue-hsm - server
    
    ;; Software
    ledger-live - software
    host-os - software
    
    ;; Attackers and Users
    eve - attacker        ;; Sophisticated attacker
    alice - user          ;; End user
    
    ;; Hardware Components (Stax specific)
    se-stax - secure-element     ;; ST33 Secure Element
    mcu-stax - mcu              ;; STM32WB35 MCU
    touchscreen-stax - peripheral ;; Touch display
    nfc-chip-stax - peripheral   ;; ST25R3916 NFC chip
    usb-connector - peripheral   ;; USB-C connector
    ble-module - peripheral      ;; Bluetooth LE module
    
    ;; Apps and Keys
    btc-app - app
    eth-app - app
    malicious-app - app
    master-key - key
    btc-key - key
    eth-key - key
    
    ;; Firmware
    current-firmware - firmware
    update-firmware - firmware
    malicious-firmware - firmware
    
    ;; Communication Channels
    usb-channel - channel
    ble-channel - channel
    nfc-channel - channel
    internet-channel - channel
  )

  ;; ==========================================================================
  ;; INITIAL STATE - Stax Device Configuration
  ;; ==========================================================================
  (:init
    ;; ===== Device Properties =====
    (genuine stax)
    (not (physical-access stax))
    (not (pin-bypassed stax))
    (not (pin-captured stax))
    (not (seed-extracted stax))
    (not (firmware-compromised stax))
    (not (display-tampered stax))
    (not (communications-eavesdropped stax))
    (not (key-confidentiality-compromised stax))
    (not (device-wiped stax))
    (not (bootloader-unlocked stax))
    (master-seed-present stax)
    (wireless-enabled stax)
    
    ;; ===== Hardware Architecture (Stax specific) =====
    (belongs-to se-stax stax)
    (belongs-to mcu-stax stax)
    (belongs-to touchscreen-stax stax)
    (belongs-to nfc-chip-stax stax)
    (belongs-to usb-connector stax)
    (belongs-to ble-module stax)
    
    ;; Component connections (Stax architecture)
    (connected se-stax mcu-stax)
    (connected mcu-stax se-stax)
    (connected se-stax touchscreen-stax)  ;; SE drives display directly
    (connected touchscreen-stax se-stax)
    (connected mcu-stax nfc-chip-stax)
    (connected nfc-chip-stax mcu-stax)
    (connected mcu-stax ble-module)
    (connected ble-module mcu-stax)
    (connected mcu-stax usb-connector)
    (connected usb-connector mcu-stax)
    
    ;; Component security state
    (not (compromised se-stax))
    (not (compromised mcu-stax))
    (not (compromised touchscreen-stax))
    (not (compromised nfc-chip-stax))
    (not (compromised usb-connector))
    (not (compromised ble-module))
    
    ;; ===== Wireless Proximity =====
    (not (within-ble-range stax))
    (not (within-nfc-range stax))
    (not (in-faraday-cage stax))
    (not (ble-paired stax ledger-live))
    
    ;; ===== HSM & Root-of-Trust =====
    (not (connected-hsm stax ledger-hsm))
    (not (connected-hsm stax rogue-hsm))
    (not (passed-genuine-check stax))
    (not (blocked-by-hsm stax))
    (not (rogue ledger-hsm))
    (rogue rogue-hsm)
    (hsm-certificate-valid ledger-hsm)
    (not (hsm-certificate-valid rogue-hsm))
    (not (firmware-signed-by-genuine stax))
    (not (firmware-update-rejected stax))
    
    ;; ===== Software Environment =====
    (ledgerlive-running ledger-live stax)
    (not (ledgerlive-compromised ledger-live))
    (not (host-os-compromised host-os))
    (not (malware-present ledger-live))
    (not (malware-present host-os))
    
    ;; ===== User Properties =====
    (user-vigilant alice)         ;; Alice starts vigilant
    (not (user-deceived alice))
    (user-trusts-display alice stax)
    (not (user-verified-address alice))
    (not (phishing-attempt-successful alice))
    
    ;; ===== Attacker Capabilities =====
    (not (attacker-has-physical-access eve stax))
    (attacker-has-tools eve)
    (attacker-skill-level-high eve)
    (not (attacker-in-proximity eve stax))
    (attacker-controls-network eve)  ;; Eve has network capabilities
    
    ;; ===== Apps and Keys =====
    (app-installed btc-app stax)
    (app-installed eth-app stax)
    (not (app-installed malicious-app stax))
    (not (app-malicious btc-app))
    (not (app-malicious eth-app))
    (app-malicious malicious-app)
    
    (key-derived master-key stax)
    (key-derived btc-key stax)
    (key-derived eth-key stax)
    (not (key-exposed master-key))
    (not (key-exposed btc-key))
    (not (key-exposed eth-key))
    (key-in-use btc-key btc-app)
    (key-in-use eth-key eth-app)
    
    ;; ===== Firmware =====
    (firmware-version current-firmware stax)
    (not (firmware-vulnerable current-firmware))
    (firmware-update-available update-firmware)
    (firmware-vulnerable malicious-firmware)
    (not (rollback-protection-active stax))
    
    ;; ===== Communication Channels =====
    (channel-available usb-channel stax)
    (channel-available ble-channel stax)
    (channel-available nfc-channel stax)
    (channel-available internet-channel stax)
    (channel-secure usb-channel)
    (channel-secure ble-channel)
    (channel-secure nfc-channel)
    (channel-secure internet-channel)
    (not (channel-monitored usb-channel))
    (not (channel-monitored ble-channel))
    (not (channel-monitored nfc-channel))
    (not (channel-monitored internet-channel))
    (not (mitm-attack-active usb-channel))
    (not (mitm-attack-active ble-channel))
    (not (mitm-attack-active nfc-channel))
    (not (mitm-attack-active internet-channel))
    
    ;; ===== Transaction State =====
    (not (transaction-pending stax))
    (not (address-verified stax))
    (not (transaction-signed stax))
    (operation-requires-pin stax)
    
    ;; ===== Supply Chain =====
    (not (supply-chain-compromised stax))
    (not (package-tampered stax))
    (not (counterfeit-device stax))
  )

  ;; ==========================================================================
  ;; GOALS - Multiple Attack Scenarios
  ;; ==========================================================================
  (:goal 
    (or
      ;; ===== High Impact Goals =====
      (seed-extracted stax)                    ;; Ultimate goal: extract master seed
      (key-confidentiality-compromised stax)   ;; Compromise key confidentiality
      (firmware-compromised stax)              ;; Install malicious firmware
      
      ;; ===== Medium Impact Goals =====
      (display-tampered stax)                  ;; Compromise display integrity
      (pin-bypassed stax)                      ;; Bypass PIN protection
      (communications-eavesdropped stax)       ;; Eavesdrop on communications
      (blocked-by-hsm stax)                    ;; Block device via rogue HSM
      
      ;; ===== Software/Social Goals =====
      (ledgerlive-compromised ledger-live)     ;; Compromise Ledger Live
      (phishing-attempt-successful alice)      ;; Successful phishing attack
      (user-deceived alice)                    ;; Social engineering success
      
      ;; ===== Specific Component Compromises =====
      (compromised se-stax)                    ;; Compromise Secure Element
      (compromised mcu-stax)                   ;; Compromise MCU
      (app-installed malicious-app stax)       ;; Install malicious app
      
      ;; ===== Network Attack Goals =====
      (connected-hsm stax rogue-hsm)          ;; Connect to rogue HSM
      (mitm-attack-active internet-channel)    ;; Active MITM attack
      
      ;; ===== Supply Chain Goals =====
      (supply-chain-compromised stax)         ;; Supply chain compromise
      (counterfeit-device stax)               ;; Device counterfeiting
    )
  )
) 