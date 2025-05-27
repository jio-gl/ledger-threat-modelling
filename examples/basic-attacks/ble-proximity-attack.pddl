;; Basic BLE Proximity Attack Example - Nano X
;; This demonstrates a wireless proximity attack scenario

(define (problem basic-ble-proximity-attack)
  (:domain ledger-comprehensive-threat-model)

  (:objects
    ;; Device
    nano-x - device
    
    ;; Components
    se-nanox - secure-element
    mcu-nanox - mcu
    display-nanox - peripheral
    buttons-nanox - peripheral
    usb-nanox - peripheral
    ble-nanox - peripheral
    
    ;; Entities
    mallory - attacker
    bob - user
    
    ;; Software
    ledger-live - software
    mobile-app - software
    
    ;; Keys and Apps
    master-key - key
    btc-app - app
    
    ;; Channels
    usb-ch - channel
    ble-ch - channel
  )

  (:init
    ;; ===== Device Initial State =====
    (genuine nano-x)
    (not (physical-access nano-x))
    (not (pin-bypassed nano-x))
    (not (seed-extracted nano-x))
    (not (communications-eavesdropped nano-x))
    (master-seed-present nano-x)
    (wireless-enabled nano-x)
    
    ;; ===== Component Architecture =====
    (belongs-to se-nanox nano-x)
    (belongs-to mcu-nanox nano-x)
    (belongs-to display-nanox nano-x)
    (belongs-to buttons-nanox nano-x)
    (belongs-to usb-nanox nano-x)
    (belongs-to ble-nanox nano-x)
    
    ;; Nano X connections (SE drives display/buttons, MCU handles BLE)
    (connected se-nanox mcu-nanox)
    (connected mcu-nanox se-nanox)
    (connected se-nanox display-nanox)
    (connected se-nanox buttons-nanox)
    (connected mcu-nanox usb-nanox)
    (connected mcu-nanox ble-nanox)
    
    ;; Component security state
    (not (compromised se-nanox))
    (not (compromised mcu-nanox))
    (not (compromised ble-nanox))
    
    ;; ===== Wireless Proximity =====
    (not (within-ble-range nano-x))
    (not (in-faraday-cage nano-x))
    (ble-paired nano-x ledger-live)
    
    ;; ===== Attacker Capabilities =====
    (not (attacker-has-physical-access mallory nano-x))
    (attacker-has-tools mallory)
    (attacker-skill-level-high mallory)  ;; Skilled wireless attacker
    (not (attacker-in-proximity mallory nano-x))
    
    ;; ===== User Properties =====
    (not (user-vigilant bob))  ;; User not aware of wireless threats
    (user-trusts-display bob nano-x)
    
    ;; ===== Software Environment =====
    (ledgerlive-running ledger-live nano-x)
    (not (ledgerlive-compromised ledger-live))
    (not (host-os-compromised mobile-app))
    
    ;; ===== Keys and Apps =====
    (app-installed btc-app nano-x)
    (key-derived master-key nano-x)
    (not (key-exposed master-key))
    
    ;; ===== Communication Channels =====
    (channel-available usb-ch nano-x)
    (channel-available ble-ch nano-x)
    (channel-secure usb-ch)
    (channel-secure ble-ch)
    (not (mitm-attack-active ble-ch))
  )

  ;; ===== Attack Goal =====
  ;; Goal: Approach BLE range and eavesdrop on communications
  (:goal 
    (and
      (within-ble-range nano-x)
      (communications-eavesdropped nano-x)
      (attacker-in-proximity mallory nano-x)
    )
  )
)

;; Expected attack sequence:
;; 1. approach-ble-range(mallory, nano-x)
;; 2. eavesdrop-ble(mallory, nano-x, mcu-nanox)
;;
;; This basic example shows how an attacker can approach a Nano X device
;; within BLE range and eavesdrop on wireless communications.
;; This is a limited attack that doesn't compromise the device core security. 