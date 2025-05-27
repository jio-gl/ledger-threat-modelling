;; Advanced Multi-Vector SE Compromise Attack
;; This demonstrates a sophisticated attack combining multiple vectors to compromise the Secure Element

(define (problem advanced-multi-vector-se-compromise)
  (:domain ledger-comprehensive-threat-model)

  (:objects
    ;; Device - Nano X (has both physical and wireless vectors)
    nano-x - device
    
    ;; Components
    se-nanox - secure-element
    mcu-nanox - mcu
    display-nanox - peripheral
    buttons-nanox - peripheral
    usb-nanox - peripheral
    ble-nanox - peripheral
    
    ;; Entities
    nation-state-attacker - attacker
    high-value-target - user
    
    ;; Software
    ledger-live - software
    host-os - software
    
    ;; Keys and Apps
    master-key - key
    btc-app - app
    eth-app - app
    defi-app - app
    
    ;; Firmware
    current-fw - firmware
    backdoored-fw - firmware
    
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
    (not (display-tampered nano-x))
    (master-seed-present nano-x)
    (wireless-enabled nano-x)
    
    ;; ===== Component Architecture =====
    (belongs-to se-nanox nano-x)
    (belongs-to mcu-nanox nano-x)
    (belongs-to display-nanox nano-x)
    (belongs-to buttons-nanox nano-x)
    (belongs-to usb-nanox nano-x)
    (belongs-to ble-nanox nano-x)
    
    ;; Nano X connections (SE drives display/buttons for security)
    (connected se-nanox mcu-nanox)
    (connected mcu-nanox se-nanox)
    (connected se-nanox display-nanox)
    (connected se-nanox buttons-nanox)
    (connected mcu-nanox usb-nanox)
    (connected mcu-nanox ble-nanox)
    
    ;; Component security state
    (not (compromised se-nanox))
    (not (compromised mcu-nanox))
    (not (compromised display-nanox))
    (not (compromised ble-nanox))
    
    ;; ===== Wireless & Proximity =====
    (not (within-ble-range nano-x))
    (not (in-faraday-cage nano-x))
    (ble-paired nano-x ledger-live)
    
    ;; ===== Attacker Capabilities =====
    (not (attacker-has-physical-access nation-state-attacker nano-x))
    (attacker-has-tools nation-state-attacker)
    (attacker-skill-level-high nation-state-attacker)
    (not (attacker-in-proximity nation-state-attacker nano-x))
    (attacker-controls-network nation-state-attacker)
    
    ;; ===== User Properties =====
    (user-vigilant high-value-target)
    (not (user-deceived high-value-target))
    (user-trusts-display high-value-target nano-x)
    (not (phishing-attempt-successful high-value-target))
    
    ;; ===== Software Environment =====
    (ledgerlive-running ledger-live nano-x)
    (not (ledgerlive-compromised ledger-live))
    (not (host-os-compromised host-os))
    
    ;; ===== Keys and Apps =====
    (app-installed btc-app nano-x)
    (app-installed eth-app nano-x)
    (app-installed defi-app nano-x)
    (key-derived master-key nano-x)
    (not (key-exposed master-key))
    
    ;; ===== Firmware =====
    (firmware-version current-fw nano-x)
    (not (firmware-vulnerable current-fw))
    (firmware-vulnerable backdoored-fw)
    (not (rollback-protection-active nano-x))
    
    ;; ===== Communication Channels =====
    (channel-available usb-ch nano-x)
    (channel-available ble-ch nano-x)
    (channel-secure usb-ch)
    (channel-secure ble-ch)
  )

  ;; ===== Attack Goal =====
  ;; Ultimate goal: Compromise SE and extract seed through multi-vector attack
  (:goal 
    (and
      ;; Physical vector success
      (physical-access nano-x)
      (pin-bypassed nano-x)
      
      ;; Wireless vector success  
      (within-ble-range nano-x)
      (communications-eavesdropped nano-x)
      
      ;; Software vector success
      (ledgerlive-compromised ledger-live)
      (host-os-compromised host-os)
      
      ;; Social engineering success
      (user-deceived high-value-target)
      
      ;; Hardware compromise achieved
      (compromised se-nanox)
      (compromised mcu-nanox)
      
      ;; Ultimate goal: seed extraction
      (seed-extracted nano-x)
      (key-confidentiality-compromised nano-x)
    )
  )
)

;; Expected complex attack sequence:
;; Stage 1 - Software Preparation:
;; 1. supply-chain-attack(nation-state-attacker, ledger-live)
;; 2. compromise-host-os(nation-state-attacker, host-os)
;;
;; Stage 2 - Social Engineering:
;; 3. social-engineering-attack(nation-state-attacker, high-value-target)
;; 4. phishing-attack(nation-state-attacker, high-value-target, ledger-live, nano-x)
;;
;; Stage 3 - Proximity/Wireless:
;; 5. approach-ble-range(nation-state-attacker, nano-x)
;; 6. eavesdrop-ble(nation-state-attacker, nano-x, mcu-nanox)
;; 7. ble-mitm-attack(nation-state-attacker, nano-x, ledger-live)
;;
;; Stage 4 - Physical Access:
;; 8. gain-physical-access(nation-state-attacker, nano-x)
;; 9. fault-injection-attack(nation-state-attacker, nano-x, se-nanox)
;; 10. side-channel-attack(nation-state-attacker, nano-x, se-nanox)
;; 11. timing-attack-pin(nation-state-attacker, nano-x)
;;
;; Stage 5 - Final Compromise:
;; 12. extract-seed(nation-state-attacker, nano-x, se-nanox)
;;
;; This demonstrates how a sophisticated attacker might use multiple attack vectors
;; in sequence to overcome the defense-in-depth strategy of hardware wallets. 